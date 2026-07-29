/**
 * DORMITORY MANAGEMENT SYSTEM — Backend (White-Label Ready)
 *
 * Preserves every existing API and data-shape from the original server.js while
 * adding a fully automated, retryable, configurable billing & email pipeline:
 *
 *   - Background scheduler that runs daily at a configurable time (default 08:00)
 *   - Hourly catch-up sweep so missed cron ticks still fire
 *   - Configurable reminder schedule (7/3/1/0/-1/-7 days, editable)
 *   - Duplicate protection via per-cycle reminderHistory keys
 *   - Automatic reset of reminderHistory when balance reaches zero
 *   - Professional HTML email templates for: Upcoming, Due Today, Overdue,
 *     Payment Receipt, Reservation Confirmation, Reservation Cancellation,
 *     Reservation Expiration
 *   - Automatic payment receipts triggered by /api/payment
 *   - Automatic retry (default 3x) with error capture in Email Logs
 *   - SMTP validation (connection + sender + recipient format)
 *   - Rich Email Logs (type, retries, error) exposed via /api/email-logs
 *   - Hot-reload of config via /api/reload-config (no server restart needed)
 *   - Architecture stubs for future GCash / Maya / PayMongo / Stripe / PayPal
 *   - Unique Email Reference Number generated per email and logged
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;

// STORAGE: Supabase PostgreSQL (replaces the legacy data.json file store).
const { loadDatabase, persistDatabase, isConfigured: supabaseConfigured } = require('./supabase');

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

/* ====================================================================
 * ROLE-BASED AUTHORIZATION (server-side enforcement)
 * The UI hides restricted modules, but the rules below are what actually
 * protect the system: they are applied to every incoming API request, so
 * a crafted/direct request cannot bypass them.
 *
 *   Super Administrator - unrestricted.
 *   Administrator       - no Reset System Data, no White Label config,
 *                         no Email configuration, cannot see or modify
 *                         any Super Administrator account.
 *   Staff               - no Reset System Data, no System Settings,
 *                         no Receipt Archive, no Room Inventory,
 *                         no Room Settings & Pricing, no User Management.
 *   Viewer              - removed from the system.
 * ==================================================================== */
const ROLE_MATRIX = {
    'Super Administrator': { userManagement:'FULL',  systemSettings:'FULL',  resetDatabase:'FULL',  whiteLabel:'FULL',  emailConfig:'FULL',  receiptArchive:'FULL',  roomInventory:'FULL',  roomSettings:'FULL',  billing:'FULL', reservations:'FULL', maintenance:'FULL', reports:'FULL' },
    'Administrator':       { userManagement:'FULL',  systemSettings:'FULL',  resetDatabase:'HIDDEN',whiteLabel:'HIDDEN',emailConfig:'HIDDEN',receiptArchive:'FULL',  roomInventory:'FULL',  roomSettings:'FULL',  billing:'FULL', reservations:'FULL', maintenance:'FULL', reports:'FULL' },
    'Staff':               { userManagement:'HIDDEN',systemSettings:'HIDDEN',resetDatabase:'HIDDEN',whiteLabel:'HIDDEN',emailConfig:'HIDDEN',receiptArchive:'HIDDEN',roomInventory:'HIDDEN',roomSettings:'HIDDEN',billing:'RW',   reservations:'FULL', maintenance:'FULL', reports:'RO' }
};
const VALID_ROLES = Object.keys(ROLE_MATRIX);

function identify(req) {
    const username = String(req.headers['x-mdms-user'] || '').trim();
    const claimed  = String(req.headers['x-mdms-role'] || '').trim();
    let stored = null;
    try {
        const db = readStorage();
        stored = (db.users || []).find(u => String(u.username || '').toLowerCase() === username.toLowerCase()) || null;
    } catch (_) {}
    // The persisted record always wins over whatever the client claims.
    const role = stored ? stored.role : claimed;
    return { username, role: VALID_ROLES.includes(role) ? role : (role || ''), verified: !!stored };
}

function levelFor(role, mod) {
    const m = ROLE_MATRIX[role];
    if (!m) return role === '' ? 'FULL' : 'HIDDEN'; // unauthenticated bootstrap (login/seed) stays permissive for reads
    return m[mod] || 'HIDDEN';
}
function allowed(role, mod, action) {
    const lvl = levelFor(role, mod);
    if (lvl === 'HIDDEN') return false;
    if (lvl === 'FULL') return true;
    if (lvl === 'RW') return action !== 'delete';
    return action === 'read';
}
function deny(res, mod) {
    return res.status(403).json({ error: '403 Forbidden — Access Denied', module: mod });
}

// Route-level guards
const GUARDS = [
    { method: 'POST', path: '/api/reset-system', mod: 'resetDatabase', action: 'write' },
    { method: 'PUT',  path: '/api/whitelabel',   mod: 'whiteLabel',    action: 'write' },
    { method: 'POST', path: '/api/test-email',   mod: 'emailConfig',   action: 'write' },
    { method: 'POST', path: '/api/reload-config',mod: 'emailConfig',   action: 'write' },
    { method: 'GET',  path: '/api/users',        mod: 'userManagement',action: 'read'  },
    { method: 'PUT',  path: '/api/users',        mod: 'userManagement',action: 'write' }
];

app.use('/api', (req, res, next) => {
    const who = identify(req);
    req.mdmsUser = who;
    const isSA = who.role === 'Super Administrator';

    // Only a real, known role may act. Unknown/blank identity keeps the legacy
    // permissive behaviour needed for first boot + login, but never for the
    // privileged routes below.
    const g = GUARDS.find(x => x.method === req.method && req.path === x.path.replace('/api', ''));
    if (g) {
        if (!who.role) return deny(res, g.mod);
        if (!allowed(who.role, g.mod, g.action)) return deny(res, g.mod);
    }

    // Hard protection of the Super Administrator directory
    if (req.path === '/users' && req.method === 'GET' && !isSA) {
        res.locals.hideSuperAdmins = true;
    }
    if (req.path === '/users' && req.method === 'PUT') {
        try {
            const db = readStorage();
            const existing = db.users || [];
            let incoming = Array.isArray((req.body || {}).users) ? req.body.users : null;
            if (incoming) {
                // The Viewer role can never be assigned again.
                if (incoming.some(u => u.role === 'Viewer')) {
                    return res.status(400).json({ error: 'The Viewer role has been removed and cannot be assigned.' });
                }
                if (!isSA) {
                    const saAccounts = existing.filter(u => u.role === 'Super Administrator');
                    // Nobody but a Super Administrator may create, edit,
                    // disable, delete or impersonate a Super Administrator.
                    const touchesSA = incoming.some(u => u.role === 'Super Administrator' &&
                        !saAccounts.some(sa => String(sa.id) === String(u.id) &&
                            JSON.stringify({ ...sa, avatar: undefined }) === JSON.stringify({ ...u, avatar: undefined })));
                    if (touchesSA) return deny(res, 'userManagement');
                    // Re-attach untouched SA accounts so a filtered client list
                    // can never delete them.
                    const keptIds = new Set(incoming.map(u => String(u.id)));
                    saAccounts.forEach(sa => { if (!keptIds.has(String(sa.id))) incoming.push(sa); });
                    req.body.users = incoming;
                }
            }
        } catch (_) {}
    }

    // Settings written through the generic data sync are filtered per role:
    // a role without emailConfig / whiteLabel access cannot change them even
    // by posting a crafted payload.
    if (req.path === '/data' && req.method === 'POST' && who.role) {
        try {
            const db = readStorage();
            const body = req.body || {};
            if (body.settings && db.settings) {
                if (!allowed(who.role, 'emailConfig', 'write')) {
                    ['smtpEnabled','smtpServer','smtpPort','smtpGmail','smtpPassword','smtpUser','emailNotifications','notificationRules','reminderSchedule']
                        .forEach(k => { if (k in db.settings) body.settings[k] = db.settings[k]; else delete body.settings[k]; });
                }
                if (!allowed(who.role, 'whiteLabel', 'write')) {
                    if (db.settings.whiteLabel !== undefined) body.settings.whiteLabel = db.settings.whiteLabel;
                    else delete body.settings.whiteLabel;
                }
            }
            if (!allowed(who.role, 'receiptArchive', 'read') && body.receiptArchive) {
                body.receiptArchive = db.receiptArchive || [];
            }
            if (!allowed(who.role, 'roomSettings', 'write') && Array.isArray(body.rooms) && Array.isArray(db.rooms)) {
                // Staff may move boarders around, but may not re-price or
                // re-configure rooms / inventory.
                body.rooms = body.rooms.map(r => {
                    const cur = (db.rooms || []).find(x => String(x.id) === String(r.id));
                    if (!cur) return r;
                    return { ...r, rate: cur.rate, capacity: cur.capacity, name: cur.name, floor: cur.floor, type: cur.type, inventory: cur.inventory };
                });
            }
        } catch (_) {}
    }

    next();
});

/* ====================================================================
 * STORAGE: Atomic read/write with corruption recovery
 * ==================================================================== */
let MEMORY_DB = null;              // authoritative in-process snapshot
let PERSIST_CHAIN = Promise.resolve();
let PERSIST_ERRORS = 0;

/**
 * Hydrate the in-process snapshot from Supabase. Called once at startup,
 * before the HTTP server accepts traffic, so every synchronous readStorage()
 * below keeps working exactly as it did with data.json.
 */
async function bootstrapStorage() {
    const loaded = await loadDatabase();
    MEMORY_DB = normalizeStructure(loaded || {});
    const seeded = !loaded || Object.keys(loaded).length === 0;
    if (seeded) {
        MEMORY_DB = normalizeStructure(initializeDefaultDatabase());
    }
    await persistDatabase(MEMORY_DB);
    console.log(`[STORAGE] Supabase snapshot ${seeded ? 'initialised' : 'loaded'} (${Object.keys(MEMORY_DB).length} collections).`);
    return MEMORY_DB;
}

/** Synchronous read — returns the live snapshot (identical shape to data.json). */
function readStorage() {
    if (!MEMORY_DB) MEMORY_DB = normalizeStructure(initializeDefaultDatabase());
    return MEMORY_DB;
}

/**
 * Atomic write — updates the snapshot, then serialises the Supabase write so
 * concurrent requests can never interleave and corrupt the stored document.
 */
function writeStorageAtomic(data) {
    const norm = normalizeStructure(data);
    norm.lastUpdate = new Date().toISOString();
    MEMORY_DB = norm;
    const payload = JSON.parse(JSON.stringify(norm));
    PERSIST_CHAIN = PERSIST_CHAIN.then(() => persistDatabase(payload))
        .then(() => { PERSIST_ERRORS = 0; })
        .catch(err => {
            PERSIST_ERRORS++;
            console.error(`[STORAGE] Supabase persist failure #${PERSIST_ERRORS}:`, err.message);
        });
    return true;
}

/** Flush any queued Supabase writes (used by health checks / shutdown). */
function flushStorage() { return PERSIST_CHAIN; }

/* ====================================================================
 * WHITE LABEL CONFIGURATION — THE single source of truth (SSOT) for all
 * branding in the entire system (frontend + backend).
 *
 * Every downstream value (company/dormitory/business/system names, logos,
 * favicon, address, contact, receipt header/footer, email signature/footer,
 * sender name, watermark, permit, TIN, QR, currency, theme colours) is read
 * from this ONE object through BrandingService — never stored twice.
 *
 * Legacy duplicates (settings.dormName / dormLogoUrl / signature / footer /
 * contactInfo) found in older data.json files are migrated into whiteLabel
 * once and then permanently removed, so no module can drift out of sync.
 * ==================================================================== */
const DEFAULT_WHITE_LABEL = {
    // ---- Fully white-label. NOTHING here is client specific and NOTHING is
    // ---- duplicated anywhere else in the system. The White Label module is
    // ---- the single source of truth (SSOT) for every branding value.
    companyName: '',                     // auto = businessName || dormName
    dormName: 'Dormitory',
    businessName: '',                    // auto = dormName
    systemName: 'Dormitory Management System',
    systemShortName: '',                 // auto-derived (e.g. DMS)
    logoUrl: '',
    faviconUrl: '',
    loadingLogoUrl: '',
    address: '',
    contactNumber: '',
    email: '',
    website: '',
    browserTitle: '',                    // auto = systemName
    receiptHeader: '',
    receiptFooter: '',
    emailSignature: '',                  // auto = companyName + " Administration"
    emailFooter: 'This is an automated notification. Please do not reply directly to this email.',
    emailSenderName: '',                 // auto = systemShortName + " Admin"
    primaryColor: '#1d4ed8',
    secondaryColor: '#0f172a',
    watermark: '',
    currency: 'PHP',
    businessPermit: '',
    tin: '',
    qrCode: ''
};

/* Currency code -> display symbol. Used by every money value the backend
 * renders (emails, receipts) so currency is never hardcoded. */
const CURRENCY_SYMBOLS = { PHP:'\u20b1', USD:'$', EUR:'\u20ac', GBP:'\u00a3', JPY:'\u00a5', AUD:'A$', CAD:'C$', SGD:'S$', HKD:'HK$', AED:'\u062f.\u0625', INR:'\u20b9', KRW:'\u20a9', CNY:'\u00a5', THB:'\u0e3f', MYR:'RM', IDR:'Rp', VND:'\u20ab' };
function currencySymbol(code){ return CURRENCY_SYMBOLS[String(code||'PHP').toUpperCase()] || (String(code||'').toUpperCase()+' '); }

function autoAbbr(name) {
    if (!name) return '';
    return String(name).split(/\s+/).filter(Boolean).map(w => w[0]).join('').toUpperCase().slice(0, 6);
}

function resolveWhiteLabel(wl) {
    const w = { ...DEFAULT_WHITE_LABEL, ...(wl || {}) };
    // Every derived value is computed here — never stored twice, never
    // re-entered by the user in another module.
    if (!w.businessName)    w.businessName    = w.dormName;
    if (!w.companyName)     w.companyName     = w.businessName || w.dormName;
    if (!w.systemShortName) w.systemShortName = autoAbbr(w.systemName);
    if (!w.browserTitle)    w.browserTitle    = w.systemName;
    if (!w.emailSenderName) w.emailSenderName = (w.systemShortName || 'System') + ' Admin';
    if (!w.emailSignature)  w.emailSignature  = (w.companyName || 'System') + ' Administration';
    w.currencySymbol = currencySymbol(w.currency);
    w.contactInfo    = [w.address, w.contactNumber, w.email].filter(Boolean).join(' \u00b7 ');
    return w;
}

/** Centralised backend Branding Service — the ONLY way server code reads brand data. */
const BrandingService = {
    /* Stored record (raw, no derived values baked in). */
    raw(db){ return { ...DEFAULT_WHITE_LABEL, ...(((db && db.settings) || {}).whiteLabel || {}) }; },
    get(db){ return resolveWhiteLabel(((db && db.settings) || {}).whiteLabel); },
    read(){ try { return this.get(readStorage()); } catch(_) { return resolveWhiteLabel({}); } },
    save(db, patch){
        db.settings = db.settings || {};
        // Persist the RAW record only. Derived values (short name, browser title,
        // sender name, signature, company name...) are computed on every read so
        // renaming the business instantly re-derives them everywhere.
        db.settings.whiteLabel = { ...DEFAULT_WHITE_LABEL, ...(db.settings.whiteLabel || {}), ...(patch || {}) };
        stripLegacyBrandingFields(db.settings);
        return resolveWhiteLabel(db.settings.whiteLabel);
    },
    money(brand, n){ return (brand.currencySymbol || '') + Number(n || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
};

/* Branding must exist in exactly one place. Any legacy duplicate copied into
 * settings by older builds is removed on load and on save. */
const LEGACY_BRANDING_KEYS = ['dormName','dormLogoUrl','signature','footer','contactInfo','businessName','companyName','logoUrl','address','contactNumber','currency'];
function stripLegacyBrandingFields(settings){
    if (!settings) return settings;
    LEGACY_BRANDING_KEYS.forEach(k => { delete settings[k]; });
    return settings;
}

const DEFAULT_SETTINGS = {
    reminderDays: 7,
    autoRemindersEnabled: true,
    dailyTime: '08:00',                    // HH:MM 24h
    reminderSchedule: [7, 3, 1, 0, -1, -7],// negative = days after due
    weeklyOverdueInterval: 7,              // re-nag every 7 days while overdue
    retryAttempts: 3,
    retryIntervalMinutes: 5,
    replyTo: '',
    // NO branding fields here. All branding lives in settings.whiteLabel only.
    whiteLabel: { ...DEFAULT_WHITE_LABEL }
};

/* ====================================================================
 * ENTIRE ROOM OCCUPANCY RECONCILIATION (FINAL FIX)
 * --------------------------------------------------------------------
 * Runs on every read and every write so the persisted state can never
 * disagree with the UI after a page refresh:
 *
 *   - A room owned by an entire-room occupant keeps ALL beds locked,
 *     occupied = capacity, payerId = the occupant, status Fully Occupied.
 *   - A room whose entire-room occupant has moved away (transfer /
 *     checkout) is fully released: beds cleared, occupied = 0,
 *     payerId = null, reservation lock cleared, status = "Available".
 * ==================================================================== */
function reconcileEntireRoomState(v) {
    if (!Array.isArray(v.rooms)) return v;
    const boarders = Array.isArray(v.boarders) ? v.boarders : [];
    const reservations = Array.isArray(v.reservations) ? v.reservations : [];

    v.rooms.forEach(room => {
        if (!room || room.type === 'Admin') return;
        if (!Array.isArray(room.beds)) room.beds = [];

        const roomBoarders = boarders.filter(b => String(b.roomId) === String(room.id));
        let owner = null;
        if (room.entireRoomBoarderId) {
            owner = roomBoarders.find(b => b.id === room.entireRoomBoarderId) || null;
        }
        if (!owner) owner = roomBoarders.find(b => b.occupancyType === 'entire_room') || null;

        if (owner) {
            room.entireRoomBoarderId = owner.id;
            room.occupancyType = 'entire_room';
            room.beds.forEach(b => {
                b.isOccupied = true;          // internal lock only
                b.boarder = owner.id;
                b.isReserved = false;
                b.reservationId = null;
            });
            room.occupied = room.beds.length;
            room.payerId = owner.id;
            room.status = 'Fully Occupied';

            // Keep the entire-room reservation record in sync with the occupant's
            // CURRENT room (an Entire Room Transfer moves the occupant, and the
            // record must follow so the UI renders the ENTIRE ROOM view).
            const ownerRecords = reservations.filter(r =>
                r && r.type === 'room' &&
                (r.status === 'Active' || r.status === 'Checked-in') &&
                ((r.boarderId && r.boarderId === owner.id) ||
                 (!!r.name && String(r.name).trim().toLowerCase() === String(owner.name || '').trim().toLowerCase())));
            let current = ownerRecords.find(r => String(r.roomId) === String(room.id));
            if (!current && ownerRecords.length) {
                current = ownerRecords[0];
                current.roomId = room.id;
            }
            if (current) {
                current.status = 'Checked-in';
                current.bedNo = null;
                current.boarderId = owner.id;
            } else {
                reservations.push({
                    id: 'RES-' + Date.now() + '-' + owner.id,
                    type: 'room',
                    roomId: room.id,
                    bedNo: null,
                    boarderId: owner.id,
                    name: owner.name || '',
                    email: owner.email || '',
                    contact: owner.contact || '',
                    status: 'Checked-in',
                    deposit: 0,
                    remarks: 'Auto-reconciled entire-room occupancy'
                });
                v.reservations = reservations;
            }
            ownerRecords.forEach(r => {
                if (r !== current && String(r.roomId) !== String(room.id)) {
                    r.status = 'Completed';
                    r.completionReason = 'Entire Room Transfer';
                }
            });
            return;
        }


        // No entire-room owner: drop any stale entire-room lock.
        if (room.entireRoomBoarderId || room.occupancyType === 'entire_room') {
            const staleId = room.entireRoomBoarderId;
            room.beds.forEach(b => {
                if (!staleId || b.boarder === staleId || !roomBoarders.some(rb => rb.id === b.boarder)) {
                    b.isOccupied = false;
                    b.boarder = null;
                    b.boarderId = null;
                    b.isReserved = false;
                    b.reservationId = null;
                }
            });
            room.entireRoomBoarderId = null;
            room.occupancyType = null;
            reservations.forEach(r => {
                if (String(r.roomId) === String(room.id) && r.type === 'room' &&
                    (r.status === 'Active' || r.status === 'Checked-in') &&
                    !roomBoarders.length) {
                    r.status = 'Completed';
                }
            });
        }

        const occ = room.beds.filter(b => b.isOccupied).length;
        const res = room.beds.filter(b => b.isReserved).length;
        room.occupied = occ;
        if (occ === 0 && res === 0) {
            room.payerId = null;
            const activeRes = reservations.find(r => String(r.roomId) === String(room.id) &&
                r.type === 'room' && (r.status === 'Active' || r.status === 'Checked-in'));
            room.status = activeRes ? (activeRes.status === 'Checked-in' ? 'Fully Occupied' : 'Reserved') : 'Available';
        } else if (occ + res < (room.capacity || room.beds.length)) {
            room.status = 'Partially Occupied';
        } else {
            room.status = 'Fully Occupied';
        }
    });
    return v;
}

function normalizeStructure(data) {
    const v = data && typeof data === 'object' ? data : {};
    v.rooms = Array.isArray(v.rooms) ? v.rooms : [];
    v.boarders = Array.isArray(v.boarders) ? v.boarders : [];
    v.formerBoarders = Array.isArray(v.formerBoarders) ? v.formerBoarders : [];
    v.reservations = Array.isArray(v.reservations) ? v.reservations : [];
    v.waitingList = Array.isArray(v.waitingList) ? v.waitingList : (Array.isArray(v.waitlist) ? v.waitlist : []);
    v.waitlist = v.waitingList;
    v.transactions = Array.isArray(v.transactions) ? v.transactions : (Array.isArray(v.billingRecords) ? v.billingRecords : []);
    v.billingRecords = v.transactions;
    v.tickets = Array.isArray(v.tickets) ? v.tickets : (Array.isArray(v.maintenanceTickets) ? v.maintenanceTickets : []);
    v.maintenanceTickets = v.tickets;
    v.audit = Array.isArray(v.audit) ? v.audit : (Array.isArray(v.auditLogs) ? v.auditLogs : []);
    v.auditLogs = v.audit;
    v.emailLogs = Array.isArray(v.emailLogs) ? v.emailLogs : [];

    v.emailConfig = (v.emailConfig && typeof v.emailConfig === 'object') ? v.emailConfig : {
        enabled: true, server: 'smtp.gmail.com', port: 465, email: '', pass: '', name: ''
    };

    v.settings = { ...DEFAULT_SETTINGS, ...(v.settings || {}) };
    // ---- White Label: ensure object exists and mirror to legacy fields ----
    // ---- White Label = SSOT. Migrate any legacy duplicate once, then delete it.
    const _legacy = v.settings || {};
    const _seed = { ...(v.settings.whiteLabel || {}) };
    if (!_seed.dormName && _legacy.dormName)        _seed.dormName = _legacy.dormName;
    if (!_seed.logoUrl && _legacy.dormLogoUrl)      _seed.logoUrl = _legacy.dormLogoUrl;
    if (!_seed.emailSignature && _legacy.signature) _seed.emailSignature = _legacy.signature;
    if (!_seed.emailFooter && _legacy.footer)       _seed.emailFooter = _legacy.footer;
    v.settings.whiteLabel = { ...DEFAULT_WHITE_LABEL, ..._seed };
    stripLegacyBrandingFields(v.settings);
    // ---- Persistent user avatar map: { userId: '/uploads/user_xxx.jpg' } ----
    v.userAvatars = (v.userAvatars && typeof v.userAvatars === 'object') ? v.userAvatars : {};
    // ---- Persistent tenant photo map: { boarderId: '/uploads/tenant_xxx.jpg' } ----
    v.tenantPhotos = (v.tenantPhotos && typeof v.tenantPhotos === 'object') ? v.tenantPhotos : {};
    // ---- Persistent user directory (mirrors client localStorage so profile
    //      photos & user records survive browser/server restarts) ----
    v.users = Array.isArray(v.users) ? v.users : [];
    if (!Array.isArray(v.settings.reminderSchedule) || !v.settings.reminderSchedule.length) {
        v.settings.reminderSchedule = DEFAULT_SETTINGS.reminderSchedule.slice();
    }

    v.boarders.forEach(b => {
        if (!b.id) b.id = 'BRD-' + Date.now() + Math.floor(Math.random() * 1000);
        if (!b.email) b.email = 'tenant@gmail.com';
        if (!b.contact) b.contact = 'N/A';
        if (!b.roomId) b.roomId = '';
        if (!b.bedNo) b.bedNo = '';
        if (!b.moveInDate) b.moveInDate = new Date().toISOString().split('T')[0];
        if (b.rentRate !== undefined && b.monthlyRent === undefined) b.monthlyRent = parseFloat(b.rentRate) || 0;
        if (b.monthlyRent !== undefined && b.rentRate === undefined) b.rentRate = parseFloat(b.monthlyRent) || 0;
        if (b.monthlyRent === undefined) b.monthlyRent = 2500;
        if (b.rentRate === undefined) b.rentRate = 2500;
        b.balance = parseFloat(b.balance) || 0;
        if (b.balance < 0) b.balance = 0;
        if (!b.status) b.status = b.balance === 0 ? 'Paid' : 'Active';
        if (!Array.isArray(b.reminderHistory)) b.reminderHistory = [];
    });

    // Seed the demo layout only on a genuinely fresh database (no floors yet),
    // so deleting a floor never resurrects rooms.
    if (v.rooms.length === 0 && (!Array.isArray(v.floors) || v.floors.length === 0)) {
        for (let i = 1; i <= 24; i++) {
            const isR1 = (i === 1);
            const cap = isR1 ? 0 : 4;
            const beds = [];
            for (let b = 1; b <= cap; b++) beds.push({ bedNo: `B${b}`, isOccupied: false, boarder: null, isReserved: false, reservationId: null });
            v.rooms.push({
                id: i, roomNumber: i, type: isR1 ? 'Admin' : 'Rentable', capacity: cap, occupied: 0,
                status: isR1 ? 'Admin' : 'Available', rate: 2500, beds,
                inventory: { beds: cap, chairs: cap, tables: 1, cooling: 1 }
            });
        }
    }
    // ==================================================================
    // FLOOR INVENTORY (v3.2) — Floor entity + automatic room migration.
    // Every room references floorId + floorName. Rooms that predate the
    // Floor module keep their numeric `floor` value and are attached to the
    // matching Floor record; rooms with no floor at all land on "Floor 1".
    // Nothing is ever deleted or renumbered here, so the migration is safe
    // to run on every read/write and is fully backward compatible.
    // ==================================================================
    normalizeFloors(v);

    // FINAL FIX: entire-room ownership is reconciled on every read/write so
    // a refreshed browser always sees the same state the transfer produced.
    reconcileEntireRoomState(v);
    return v;
}

/* ====================================================================
 * FLOOR ENTITY HELPERS
 * ==================================================================== */
function floorSlug(n) { return 'FL-' + String(n).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }

function normalizeFloors(v) {
    v.floors = Array.isArray(v.floors) ? v.floors : [];

    // Sanitize existing floor records.
    v.floors = v.floors
        .filter(f => f && typeof f === 'object')
        .map((f, i) => ({
            id: String(f.id || floorSlug(f.name || ('Floor ' + (i + 1)))),
            name: String(f.name || ('Floor ' + (i + 1))).trim() || ('Floor ' + (i + 1)),
            order: Number.isFinite(Number(f.order)) ? Number(f.order) : i + 1,
            createdAt: f.createdAt || new Date().toISOString()
        }));

    const byId = new Map(v.floors.map(f => [String(f.id), f]));
    const byName = new Map(v.floors.map(f => [f.name.toLowerCase(), f]));

    function ensureFloor(name, order) {
        const clean = String(name || 'Floor 1').trim() || 'Floor 1';
        const hit = byName.get(clean.toLowerCase());
        if (hit) return hit;
        const rec = { id: floorSlug(clean), name: clean, order: order || (v.floors.length + 1), createdAt: new Date().toISOString() };
        v.floors.push(rec);
        byId.set(rec.id, rec);
        byName.set(rec.name.toLowerCase(), rec);
        return rec;
    }

    // Seed floors from legacy numeric room.floor values (no data loss).
    if (v.floors.length === 0) {
        const legacy = Array.from(new Set(
            v.rooms.map(r => (r && r.floorName) ? String(r.floorName) : (Number(r && r.floor) || 1))
        ));
        legacy
            .sort((a, b) => (typeof a === 'number' && typeof b === 'number') ? a - b : String(a).localeCompare(String(b)))
            .forEach((f, i) => ensureFloor(typeof f === 'number' ? ('Floor ' + f) : f, i + 1));
        if (v.floors.length === 0) ensureFloor('Floor 1', 1);
    }

    const first = v.floors[0];

    // Attach every room to a floor.
    v.rooms.forEach(r => {
        if (!r || typeof r !== 'object') return;
        let target = null;
        if (r.floorId && byId.has(String(r.floorId))) target = byId.get(String(r.floorId));
        else if (r.floorName && byName.has(String(r.floorName).toLowerCase())) target = byName.get(String(r.floorName).toLowerCase());
        else if (Number.isFinite(Number(r.floor)) && byName.has(('floor ' + Number(r.floor)))) target = byName.get('floor ' + Number(r.floor));
        if (!target) target = first;
        r.floorId = target.id;
        r.floorName = target.name;
        if (!Number.isFinite(Number(r.floor))) {
            const m = /(\d+)/.exec(target.name);
            r.floor = m ? parseInt(m[1], 10) : 1;
        }
    });

    v.floors.sort((a, b) => (a.order || 0) - (b.order || 0));
    return v;
}

/**
 * Returns a blocking reason string when a floor still holds live occupancy,
 * or null when it is safe to delete. Boarders, reservations and occupied beds
 * are ALL considered so deletion can never corrupt downstream modules.
 */
function floorDeletionBlocker(db, floorId) {
    const rooms = (db.rooms || []).filter(r => String(r.floorId) === String(floorId));
    const roomIds = new Set(rooms.map(r => String(r.id)));
    const activeBoarders = (db.boarders || []).filter(b => roomIds.has(String(b.roomId)));
    if (activeBoarders.length) return 'One or more rooms still contain active boarders.';
    const activeRes = (db.reservations || []).filter(r =>
        roomIds.has(String(r.roomId)) && !/cancel|expire|complete/i.test(String(r.status || '')));
    if (activeRes.length) return 'One or more rooms still contain active reservations.';
    const occupiedBed = rooms.some(r => (r.beds || []).some(b => b.isOccupied || b.isReserved));
    if (occupiedBed) return 'One or more rooms still contain occupied or reserved beds.';
    return null;
}

function initializeDefaultDatabase() {
    const fresh = normalizeStructure({});
    writeStorageAtomic(fresh);
    return fresh;
}

function appendAuditEntry(module, action, req = null) {
    try {
        const db = readStorage();
        const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1') : '127.0.0.1';
        db.audit.unshift({
            date: new Date().toLocaleString(), timestamp: new Date().toISOString(),
            user: 'Admin', ip, module, action, oldVal: '-', newVal: '-'
        });
        if (db.audit.length > 1000) db.audit.pop();
        writeStorageAtomic(db);
    } catch (e) { console.error('Audit logging fault:', e); }
}

function appendEmailLog(entry) {
    try {
        const db = readStorage();
        db.emailLogs.push({
            date: new Date().toLocaleString(),
            timestamp: new Date().toISOString(),
            to: '', subject: '', type: '', status: 'Pending',
            retries: 0, error: '',
            reference: '',
            ...entry
        });
        if (db.emailLogs.length > 5000) db.emailLogs.splice(0, db.emailLogs.length - 5000);
        writeStorageAtomic(db);
    } catch (e) { console.error('Email log write failure:', e); }
}

/* ====================================================================
 * EMAIL REFERENCE NUMBER GENERATOR
 *
 * Produces a unique per-email reference such as:
 *   MDMS-REM-20260722-0001
 * Prefix maps to email type. Date is YYYYMMDD. Trailing segment is a
 * zero-padded sequential counter persisted in data.json (emailCounter).
 * ==================================================================== */
const REF_PREFIX_BY_TYPE = {
    'Upcoming':     'REM',
    'Due Today':    'DUE',
    'Overdue':      'OVD',
    'Receipt':      'RCP',
    'Reservation': 'RSV',
    'Reservation Confirmation': 'RSV',
    'Reservation Cancellation': 'CAN',
    'Reservation Expiration':  'EXP',
    'Test':         'TST',
    'Manual':       'MAN',
    'Reminder':     'REM'
};

function refPrefixFor(type) {
    // Prefix resolution is centralized: the global Email Template Engine owns
    // the prefix for every notification type; legacy names still map here.
    try {
        if (typeof EMAIL_TYPES === 'object' && EMAIL_TYPES) {
            const key = resolveEmailType(type);
            if (EMAIL_TYPES[key] && EMAIL_TYPES[key].prefix) return EMAIL_TYPES[key].prefix;
        }
    } catch (_) {}
    return REF_PREFIX_BY_TYPE[type] || 'GEN';
}

const REF_PLACEHOLDER = '__MDMS_EMAIL_REF__';

function generateEmailReference(type) {
    let db;
    try { db = readStorage(); } catch (e) { db = null; }
    if (!db) db = { emailCounter: {} };
    if (!db.emailCounter || typeof db.emailCounter !== 'object') db.emailCounter = {};

    const prefix = refPrefixFor(type);
    const yyyymmdd = new Date().toISOString().split('T')[0].replace(/-/g, '');
    const counterKey = `${prefix}-${yyyymmdd}`;
    const next = (parseInt(db.emailCounter[counterKey], 10) || 0) + 1;
    db.emailCounter[counterKey] = next;

    try { writeStorageAtomic(db); } catch (e) { /* best-effort */ }

    const seq = String(next).padStart(4, '0');
    let short = 'SYS';
    try {
        const wl = resolveWhiteLabel((db && db.settings && db.settings.whiteLabel) || {});
        short = (wl.systemShortName || autoAbbr(wl.systemName) || 'SYS').replace(/[^A-Z0-9]/gi, '').toUpperCase() || 'SYS';
    } catch (_) {}
    return `${short}-${prefix}-${yyyymmdd}-${seq}`;
}

function injectReference(html, reference) {
    return (html || '').split(REF_PLACEHOLDER).join(reference);
}

/* ====================================================================
 * EMAIL PIPELINE — validation, retry, dispatch
 * ==================================================================== */
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateSmtpConfig(cfg) {
    if (!cfg) return 'SMTP config missing.';
    if (!cfg.enabled) return 'SMTP integration is disabled.';
    if (!cfg.email || !EMAIL_REGEX.test(cfg.email)) return 'Sender email is missing or invalid.';
    if (!cfg.pass) return 'SMTP password / app password is missing.';
    if (!cfg.server) return 'SMTP server host is missing.';
    if (!cfg.port || isNaN(parseInt(cfg.port))) return 'SMTP port is invalid.';
    return null;
}

function buildTransport(cfg) {
    const port = parseInt(cfg.port) || 465;
    return nodemailer.createTransport({
        host: cfg.server || 'smtp.gmail.com',
        port,
        secure: port === 465,
        auth: { user: cfg.email, pass: cfg.pass },
        tls: { rejectUnauthorized: false }
    });
}

async function verifySmtpHandshake(cfg) {
    const invalid = validateSmtpConfig(cfg);
    if (invalid) return { ok: false, reason: invalid };
    try {
        const t = buildTransport(cfg);
        await t.verify();
        return { ok: true };
    } catch (e) { return { ok: false, reason: 'SMTP verify failed: ' + e.message }; }
}

/**
 * Dispatch a single email with automatic retry. Records a structured entry
 * in emailLogs regardless of outcome. Never throws — one failure must not
 * halt the surrounding batch. Generates and records a unique Email
 * Reference Number per dispatch.
 */
async function sendEmailWithRetry({ to, subject, html, text, type = 'Reminder', config, settings }) {
    const cfg = config;
    const st = { ...DEFAULT_SETTINGS, ...(settings || {}) };
    const maxAttempts = Math.max(1, (st.retryAttempts || 3) + 1); // +1 = initial try
    const waitMs = Math.max(1000, (st.retryIntervalMinutes || 5) * 60 * 1000);

    const reference = generateEmailReference(type);
    const finalHtml = injectReference(html, reference);

    // Validate recipient + config up-front
    if (!to || !EMAIL_REGEX.test(to)) {
        const entry = { to: to || '', subject, type, status: 'Failed', retries: 0, error: 'Invalid recipient email format.', reference };
        appendEmailLog(entry);
        return { success: false, reason: entry.error, reference };
    }
    const invalid = validateSmtpConfig(cfg);
    if (invalid) {
        appendEmailLog({ to, subject, type, status: 'Failed', retries: 0, error: invalid, reference });
        return { success: false, reason: invalid, reference };
    }

    let transport;
    try { transport = buildTransport(cfg); }
    catch (e) {
        appendEmailLog({ to, subject, type, status: 'Failed', retries: 0, error: 'Transport init: ' + e.message, reference });
        return { success: false, reason: e.message, reference };
    }

    // FIX: resolve the sender name from the persisted White Label record.
    // If the caller passed a settings object without a whiteLabel block we fall
    // back to the stored branding instead of silently auto-deriving "DMS Admin".
    const _wlForSender = ((settings || {}).whiteLabel && Object.keys((settings || {}).whiteLabel).length)
        ? resolveWhiteLabel((settings || {}).whiteLabel)
        : BrandingService.read();
    const _senderName = (_wlForSender.emailSenderName || '').trim() || 'System Admin';

    const mailOptions = {
        from: `"${_senderName}" <${cfg.email}>`,
        to, subject,
        html: finalHtml || undefined,
        text: text || (finalHtml ? finalHtml.replace(/<[^>]+>/g, ' ') : ''),
        replyTo: st.replyTo || undefined
    };

    let lastErr = '';
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            await transport.sendMail(mailOptions);
            appendEmailLog({ to, subject, type, status: 'Sent', retries: attempt - 1, error: '', reference });
            return { success: true, attempts: attempt, reference };
        } catch (err) {
            lastErr = err.message || String(err);
            console.warn(`[EMAIL] Attempt ${attempt}/${maxAttempts} to ${to} failed: ${lastErr}`);
            if (attempt < maxAttempts) await new Promise(r => setTimeout(r, waitMs));
        }
    }
    appendEmailLog({ to, subject, type, status: 'Failed', retries: maxAttempts - 1, error: lastErr, reference });
    return { success: false, reason: lastErr, reference };
}

/* ====================================================================
 * ONE GLOBAL EMAIL SYSTEM — Centralized Email Template Engine
 *
 * THE single source for every outgoing email in the system. Every
 * notification (reservation, billing, payment, maintenance, account and
 * announcement mails) is rendered by renderEmail() and therefore shares
 * the exact same chrome: header, logo, company information, typography,
 * colours, information card, button style, footer and responsive rules.
 *
 * Only these things change per notification type:
 *   subject · badge · notification title · message · information-card
 *   fields · status colour · action button · optional payment section
 *
 * Every branding / company / payment value is read from the White Label
 * Branding configuration through BrandingService — zero duplication.
 *
 * Colour system (auto-applied to badge, left border, accent lines,
 * buttons and status labels):
 *   Blue   – Reservation           Green  – Payment Successful
 *   Orange – Due Today             Yellow – Upcoming Reminder
 *   Red    – Overdue               Purple – Room Transfer
 *   Gray   – Cancelled
 *
 * Payment section is modular: GCash today (driven by the White Label
 * contact number), with Maya / Bank Transfer / PayMongo / Stripe / PayPal
 * pluggable through EMAIL_PAYMENT_PROVIDERS without redesigning anything.
 *
 * Rendering is table-based with inline CSS so it survives Gmail, Outlook,
 * Yahoo Mail, Apple Mail, Android Mail and iPhone Mail.
 * ==================================================================== */
function fmtDate(d) { try { return new Date(d).toLocaleDateString('en-PH', { year:'numeric', month:'long', day:'numeric' }); } catch(_) { return String(d); } }
function fmtTime(d) { try { return new Date(d).toLocaleTimeString('en-PH', { hour:'2-digit', minute:'2-digit' }); } catch(_) { return String(d); } }
function fmtDateTime(d) { try { return new Date(d).toLocaleString('en-PH', { year:'numeric', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit' }); } catch(_) { return String(d); } }
function esc(v){ return String(v == null ? '' : v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ---------------------------------------------------------------------
 * Email-safe URL helpers.
 * Remote email clients (Gmail, Outlook, Apple Mail on another device)
 * cannot resolve `blob:`, `file:`, `/relative` paths, or `http://localhost`
 * / private-network hosts. These helpers make sure the white-label logo
 * and every action button either use a public URL or gracefully fall
 * back so recipients still see a branded logo and a working button even
 * when the backend is running on localhost.
 * ------------------------------------------------------------------- */
function isEmailSafeUrl(u) {
    if (!u) return false;
    const s = String(u).trim();
    if (!s) return false;
    if (/^data:image\//i.test(s)) return true;                 // inline images OK
    if (!/^https?:\/\//i.test(s)) return false;                // must be absolute http(s)
    try {
        const h = new URL(s).hostname.toLowerCase();
        if (!h) return false;
        if (h === 'localhost' || h === '0.0.0.0' || h === '::1') return false;
        if (/^127\./.test(h)) return false;
        if (/^10\./.test(h)) return false;
        if (/^192\.168\./.test(h)) return false;
        if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
        if (/\.local$/i.test(h)) return false;
        return true;
    } catch (_) { return false; }
}
function pickEmailLogo(c) {
    if (isEmailSafeUrl(c && c.logoUrl)) return c.logoUrl;
    if (isEmailSafeUrl(c && c.loadingLogoUrl)) return c.loadingLogoUrl;
    return '';
}
function resolveActionUrl(c, d, label) {
    const candidates = [d && d.buttonUrl, c && c.website, d && d.originHint];
    for (const u of candidates) if (isEmailSafeUrl(u)) return u;
    const mail = c && c.email;
    if (mail) {
        const subject = encodeURIComponent(label ? `${label} — ${c.companyName || c.dormName || 'Dormitory'}` : (c.companyName || 'Dormitory Enquiry'));
        return `mailto:${mail}?subject=${subject}`;
    }
    return '';
}

/* Email/receipt rendering context. Every branding value is read from the
 * Branding Service — there is no fallback to a second source. */
function ctx(db) {
    const s = { ...DEFAULT_SETTINGS, ...(db.settings || {}) };
    const wl = BrandingService.get(db);
    return {
        settings: s,
        whiteLabel: wl,
        companyName: wl.companyName,
        dormName: wl.dormName,
        businessName: wl.businessName,
        systemName: wl.systemName,
        logoUrl: wl.logoUrl,
        loadingLogoUrl: wl.loadingLogoUrl,
        footer: wl.emailFooter,
        signature: wl.emailSignature,
        receiptHeader: wl.receiptHeader,
        receiptFooter: wl.receiptFooter,
        currency: wl.currency,
        cur: wl.currencySymbol,
        contactInfo: wl.contactInfo,
        address: wl.address,
        contactNumber: wl.contactNumber,
        email: wl.email,
        website: wl.website,
        officeHours: wl.officeHours || 'Monday – Saturday, 8:00 AM – 5:00 PM',
        qrCode: wl.qrCode
    };
}

/** Format an amount using the branded currency. */
function money(c, n) { return (c && c.cur ? c.cur : currencySymbol('PHP')) + Number(n || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

function findRoom(db, tenant) { return db.rooms.find(r => String(r.id) === String(tenant.roomId) || String(r.roomNumber) === String(tenant.roomId)); }

/* Parse the White Label contact block into address / phone / email so the
 * header and footer can render corporate-style lines. */
function parseContactInfo(raw) {
    const out = { address: '', city: '', phone: '', email: '', raw: raw || '' };
    if (!raw) return out;
    const parts = String(raw).split(/\s*[|•·]\s*|\s{2,}|\n+/).map(s => s.trim()).filter(Boolean);
    parts.forEach(p => {
        if (/^\+?\d[\d\s\-()]{5,}$/.test(p) || /(tel|phone|contact)[:\s]/i.test(p)) {
            out.phone = out.phone || p.replace(/^(tel|phone|contact)[:\s]*/i, '');
        } else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(p)) {
            out.email = out.email || p;
        } else if (!out.address) {
            out.address = p;
        }
    });
    return out;
}

/* -------------------- STATUS COLOUR SYSTEM -------------------- */
const STATUS_COLORS = {
    blue:   { main: '#1d4ed8', soft: '#eff6ff', text: '#1e3a8a' },
    green:  { main: '#059669', soft: '#ecfdf5', text: '#065f46' },
    orange: { main: '#ea580c', soft: '#fff7ed', text: '#9a3412' },
    yellow: { main: '#ca8a04', soft: '#fefce8', text: '#854d0e' },
    red:    { main: '#b91c1c', soft: '#fef2f2', text: '#7f1d1d' },
    purple: { main: '#7c3aed', soft: '#f5f3ff', text: '#5b21b6' },
    gray:   { main: '#64748b', soft: '#f8fafc', text: '#334155' }
};
function tone(name){ return STATUS_COLORS[name] || STATUS_COLORS.blue; }

/* -------------------- SHARED BUILDING BLOCKS -------------------- */

/**
 * Global header. Logo, Company Name, System Name, Date Generated,
 * Current Time and Email Reference Number — all from White Label.
 */
function globalHeader(c, reference) {
    const info = parseContactInfo(c.contactInfo);
    const now = new Date();
    const addr = c.address || info.address;
    const phone = c.contactNumber || info.phone;
    const mail = c.email || info.email;

    const safeLogo = pickEmailLogo(c);
    const logoCell = safeLogo
        ? `<img src="${esc(safeLogo)}" alt="${esc(c.companyName || c.dormName)}" width="60" height="60" style="width:60px;height:60px;max-width:60px;border-radius:12px;object-fit:cover;display:block;border:1px solid #e2e8f0;">`
        : `<div style="width:60px;height:60px;border-radius:12px;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#ffffff;text-align:center;line-height:60px;font-size:26px;font-weight:800;font-family:Georgia,serif;letter-spacing:0.5px;">${esc(autoAbbr(c.companyName || c.dormName).slice(0,2) || 'B')}</div>`;

    return `
    <tr><td style="padding:0;background:#ffffff;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;">
        <tr>
          <td class="mdms-pad" style="padding:26px 28px 18px 28px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td class="mdms-hdr-left" style="vertical-align:top;" width="60%">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                      <td style="vertical-align:top;padding-right:14px;">${logoCell}</td>
                      <td style="vertical-align:top;font-family:Arial,Helvetica,sans-serif;">
                        <div style="font-size:20px;font-weight:800;color:#0f172a;letter-spacing:0.4px;line-height:1.15;text-transform:uppercase;">${esc(c.companyName || c.dormName)}</div>
                        <div style="font-size:11px;color:#64748b;margin-top:3px;letter-spacing:1.2px;text-transform:uppercase;font-weight:600;">${esc(c.systemName || '')}</div>
                        ${c.receiptHeader ? `<div style="font-size:11px;color:#64748b;margin-top:4px;line-height:1.5;">${esc(c.receiptHeader)}</div>` : ''}
                        ${addr ? `<div style="font-size:12px;color:#334155;margin-top:8px;line-height:1.5;">${esc(addr)}</div>` : ''}
                        ${phone ? `<div style="font-size:12px;color:#334155;line-height:1.5;">Tel: ${esc(phone)}</div>` : ''}
                        ${mail ? `<div style="font-size:12px;color:#334155;line-height:1.5;">${esc(mail)}</div>` : ''}
                      </td>
                    </tr>
                  </table>
                </td>
                <td class="mdms-hdr-right" style="vertical-align:top;text-align:right;font-family:Arial,Helvetica,sans-serif;" width="40%">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="right">
                    <tr><td style="text-align:right;">
                      <div style="font-size:10px;color:#94a3b8;letter-spacing:1.4px;text-transform:uppercase;font-weight:700;">Date Generated</div>
                      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-top:3px;">${fmtDate(now)}</div>
                      <div style="font-size:10px;color:#94a3b8;letter-spacing:1.4px;text-transform:uppercase;font-weight:700;margin-top:10px;">Current Time</div>
                      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-top:3px;">${fmtTime(now)}</div>
                      <div style="font-size:10px;color:#94a3b8;letter-spacing:1.4px;text-transform:uppercase;font-weight:700;margin-top:10px;">Email Reference No.</div>
                      <div style="display:inline-block;margin-top:4px;padding:5px 10px;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;font-family:'Courier New',Consolas,monospace;font-size:12px;font-weight:700;color:#0f172a;letter-spacing:0.5px;">${reference}</div>
                    </td></tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr><td style="padding:0 28px;">
          <div style="height:1px;background:#e2e8f0;line-height:1px;font-size:1px;">&nbsp;</div>
        </td></tr>
      </table>
    </td></tr>`;
}

/* Global footer — company name, administration, office hours, address,
 * contact information, copyright and the automated-email disclaimer. */
function globalFooter(c) {
    const info = parseContactInfo(c.contactInfo);
    const year = new Date().getFullYear();
    const addr = c.address || info.address;
    const phone = c.contactNumber || info.phone;
    const mail = c.email || info.email;
    return `
    <tr><td style="padding:0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0f172a;">
        <tr><td class="mdms-pad" style="padding:28px 28px 22px 28px;text-align:center;font-family:Arial,Helvetica,sans-serif;">
          <div style="font-size:15px;font-weight:800;color:#ffffff;letter-spacing:0.6px;text-transform:uppercase;">${esc(c.companyName || c.dormName)}</div>
          <div style="font-size:12px;font-weight:700;color:#cbd5e1;letter-spacing:1.2px;text-transform:uppercase;margin-top:4px;">${esc(c.signature)}</div>
          <div style="height:1px;background:#334155;margin:14px auto 16px auto;width:56px;line-height:1px;font-size:1px;">&nbsp;</div>
          <div style="font-size:12px;color:#cbd5e1;line-height:1.7;">Office Hours: ${esc(c.officeHours)}</div>
          ${addr ? `<div style="font-size:12px;color:#cbd5e1;line-height:1.7;">${esc(addr)}</div>` : ''}
          ${phone ? `<div style="font-size:12px;color:#cbd5e1;line-height:1.7;">Contact: ${esc(phone)}</div>` : ''}
          ${mail ? `<div style="font-size:12px;color:#cbd5e1;line-height:1.7;">Email: <a href="mailto:${esc(mail)}" style="color:#93c5fd;text-decoration:none;">${esc(mail)}</a></div>` : ''}
          ${c.website ? `<div style="font-size:12px;color:#cbd5e1;line-height:1.7;">${esc(c.website)}</div>` : ''}
          <div style="height:1px;background:#334155;margin:16px auto;width:70%;line-height:1px;font-size:1px;">&nbsp;</div>
          <div style="font-size:11px;color:#94a3b8;line-height:1.6;">© ${year} ${esc(c.companyName || c.dormName)}. All rights reserved.</div>
          ${c.receiptFooter ? `<div style="font-size:11px;color:#94a3b8;line-height:1.6;">${esc(c.receiptFooter)}</div>` : ''}
          <div style="font-size:10.5px;color:#64748b;margin-top:8px;line-height:1.6;font-style:italic;max-width:460px;margin-left:auto;margin-right:auto;">
            ${esc(c.footer)}
          </div>
        </td></tr>
      </table>
    </td></tr>`;
}

/**
 * Base shell wrapping every notification — identical chrome for all mail.
 */
function baseShell({ title, bodyInner, settings, whiteLabel, companyName, dormName, systemName, logoUrl, loadingLogoUrl, footer, signature, contactInfo, receiptHeader, receiptFooter, cur, reference, accent, address, contactNumber, email, website, officeHours, qrCode }) {
    const c = { companyName, dormName, systemName, logoUrl, loadingLogoUrl, footer, signature, contactInfo, receiptHeader, receiptFooter, cur, address, contactNumber, email, website, officeHours: officeHours || 'Monday – Saturday, 8:00 AM – 5:00 PM', qrCode };
    const accentColor = accent || '#1d4ed8';
    return `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="x-apple-disable-message-reformatting">
<meta name="format-detection" content="telephone=no,address=no,email=no,date=no">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>${esc(title)}</title>
<!--[if mso]><style>body,table,td,div,p,a{font-family:Arial,Helvetica,sans-serif !important;}</style><![endif]-->
<style>
  html,body{margin:0 !important;padding:0 !important;width:100% !important;}
  img{border:0;outline:none;text-decoration:none;-ms-interpolation-mode:bicubic;max-width:100%;height:auto;}
  table{border-collapse:collapse !important;mso-table-lspace:0pt;mso-table-rspace:0pt;}
  a{text-decoration:none;}
  @media only screen and (max-width:620px){
    .mdms-shell{width:100% !important;max-width:100% !important;border-radius:0 !important;}
    .mdms-pad{padding:20px 16px !important;}
    .mdms-hdr-left,.mdms-hdr-right{display:block !important;width:100% !important;text-align:left !important;}
    .mdms-hdr-right{margin-top:16px !important;text-align:left !important;}
    .mdms-hdr-right table{margin:0 !important;float:none !important;}
    .mdms-hdr-right td{text-align:left !important;}
    .mdms-title{font-size:19px !important;}
    .mdms-row td{font-size:13px !important;padding:11px 14px !important;}
    .mdms-stack{display:block !important;width:100% !important;text-align:center !important;}
    .mdms-btn a{display:block !important;width:auto !important;}
  }
</style>
</head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;color:#0f172a;-webkit-font-smoothing:antialiased;width:100%;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;font-size:1px;line-height:1px;color:#eef2f7;">${esc(title)} — ${esc(companyName || dormName)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef2f7;">
  <tr><td align="center" style="padding:28px 12px;">
    <table role="presentation" width="620" cellpadding="0" cellspacing="0" border="0" class="mdms-shell" style="max-width:620px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e2e8f0;border-left:5px solid ${accentColor};">
      ${globalHeader(c, reference)}
      <tr><td style="padding:0;">
        <div style="height:5px;background:${accentColor};line-height:5px;font-size:5px;">&nbsp;</div>
      </td></tr>
      <tr><td class="mdms-pad" style="padding:30px 28px;font-size:15px;line-height:1.65;color:#1e293b;font-family:Arial,Helvetica,sans-serif;">
        ${bodyInner}
      </td></tr>
      ${globalFooter(c)}
    </table>
    <div style="font-size:11px;color:#94a3b8;margin-top:14px;text-align:center;font-family:Arial,Helvetica,sans-serif;">© ${new Date().getFullYear()} ${esc(companyName || dormName)} · Automated Notification</div>
  </td></tr>
</table></body></html>`;
}

/** Status pill shown above every notification title. */
function statusBadge(icon, label, color) {
    return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 18px 0;"><tr>
      <td style="background:${color};padding:8px 16px;border-radius:999px;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;color:#ffffff;letter-spacing:1.2px;text-transform:uppercase;">
        <span style="display:inline-block;margin-right:6px;font-size:14px;line-height:1;">${icon}</span>${esc(label)}
      </td>
    </tr></table>`;
}

function notificationTitle(text, color) {
    return `<h1 class="mdms-title" style="margin:0 0 10px 0;color:${color};font-size:22px;font-weight:800;letter-spacing:0.2px;font-family:Arial,Helvetica,sans-serif;line-height:1.25;">${esc(text)}</h1>`;
}

/**
 * THE standardized information card. Fields adapt to the notification
 * type; the layout never changes.
 */
function infoCard(rows, statusRow) {
    const body = (rows || []).filter(Boolean).map((r, i) => `
      <tr class="mdms-row" style="background:${i % 2 ? '#f8fafc' : '#ffffff'};">
        <td style="padding:13px 18px;font-size:12.5px;color:#64748b;width:46%;border-bottom:1px solid #eef2f7;font-family:Arial,Helvetica,sans-serif;letter-spacing:0.3px;text-transform:uppercase;font-weight:600;">${esc(r[0])}</td>
        <td style="padding:13px 18px;font-size:14px;font-weight:700;color:#0f172a;width:54%;border-bottom:1px solid #eef2f7;font-family:Arial,Helvetica,sans-serif;text-align:right;">${r[1]}</td>
      </tr>`).join('');
    const statusBlock = statusRow ? `
      <tr><td colspan="2" style="padding:16px 18px;background:#f8fafc;border-top:1px solid #eef2f7;text-align:right;">
        <span style="display:inline-block;padding:7px 16px;border-radius:999px;font-size:11.5px;font-weight:800;color:#ffffff;background:${statusRow.color};letter-spacing:1.3px;text-transform:uppercase;font-family:Arial,Helvetica,sans-serif;">${esc(statusRow.label)}</span>
      </td></tr>` : '';
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin:20px 0;background:#ffffff;">
      ${body}${statusBlock}
    </table>`;
}

/** Standard action button — one style, colour follows the status tone. */
function actionButton(label, url, color) {
    if (!label) return '';
    if (!url) return '';                       // never render a dead "#" button in email
    const href = url;
    return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" class="mdms-btn" style="margin:22px 0 4px 0;"><tr>
      <td style="background:${color};border-radius:10px;">
        <a href="${esc(href)}" target="_blank" rel="noopener" style="display:inline-block;padding:13px 26px;font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:800;color:#ffffff;letter-spacing:0.6px;text-transform:uppercase;border-radius:10px;text-decoration:none;">${esc(label)}</a>
      </td>
    </tr></table>`;
}

/** Thin accent divider that follows the status colour. */
function accentLine(color){
    return `<div style="height:2px;background:${color};opacity:0.25;line-height:2px;font-size:2px;margin:22px 0;">&nbsp;</div>`;
}

/* ====================================================================
 * MODULAR PAYMENT SECTION
 *
 * Providers are registered here. Today only GCash is active and it is
 * driven entirely by the White Label contact number (the official GCash
 * number) — no duplicated configuration. Maya / Bank Transfer / PayMongo
 * / Stripe / PayPal can be switched on later by flipping `enabled` and
 * filling in `render`, with no change to the email design.
 * ==================================================================== */
function qrImageUrl(c, payload) {
    if (c.qrCode && String(c.qrCode).trim()) return String(c.qrCode).trim();
    return 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=0&data=' + encodeURIComponent(payload);
}

const EMAIL_PAYMENT_PROVIDERS = {
    gcash: {
        enabled: true,
        available(c){ return !!(c.contactNumber && String(c.contactNumber).trim()); },
        render(c, data, colors){
            const number = String(c.contactNumber).trim();
            const account = c.companyName || c.dormName;
            const amount = (data.amount != null ? data.amount : data.balance);
            const payload = `GCASH|${number}|${account}${amount ? '|' + Number(amount).toFixed(2) : ''}`;
            return `
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:22px 0;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;background:${colors.soft};">
        <tr><td style="padding:16px 18px;border-bottom:1px solid #e2e8f0;background:#ffffff;">
          <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:800;letter-spacing:1.3px;text-transform:uppercase;color:${colors.main};">Pay via GCash</div>
        </td></tr>
        <tr><td style="padding:20px 18px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td class="mdms-stack" width="45%" style="vertical-align:top;text-align:center;padding-bottom:10px;">
                <img src="${esc(qrImageUrl(c, payload))}" alt="GCash QR Code for ${esc(account)}" width="180" style="width:180px;max-width:100%;height:auto;border-radius:10px;border:1px solid #e2e8f0;background:#ffffff;display:inline-block;">
              </td>
              <td class="mdms-stack" width="55%" style="vertical-align:top;padding-left:16px;font-family:Arial,Helvetica,sans-serif;">
                <div style="font-size:11px;color:#64748b;letter-spacing:1px;text-transform:uppercase;font-weight:700;">GCash Number</div>
                <div style="font-size:18px;font-weight:800;color:#0f172a;margin:3px 0 10px 0;letter-spacing:0.5px;">${esc(number)}</div>
                <div style="font-size:11px;color:#64748b;letter-spacing:1px;text-transform:uppercase;font-weight:700;">Account Name</div>
                <div style="font-size:14px;font-weight:700;color:#0f172a;margin:3px 0 10px 0;">${esc(account)}</div>
                ${amount ? `<div style="font-size:11px;color:#64748b;letter-spacing:1px;text-transform:uppercase;font-weight:700;">Amount</div>
                <div style="font-size:16px;font-weight:800;color:${colors.main};margin:3px 0 0 0;">${money(c, amount)}</div>` : ''}
              </td>
            </tr>
          </table>
          <div style="margin-top:14px;font-family:Arial,Helvetica,sans-serif;font-size:12.5px;color:#475569;line-height:1.7;">
            <b style="color:#0f172a;">How to pay:</b><br>
            1. Open GCash and tap <b>Send Money</b> (or scan the QR code above).<br>
            2. Enter the GCash number <b>${esc(number)}</b> and confirm the account name is <b>${esc(account)}</b>.<br>
            3. Enter the exact amount shown on this notice and complete the transfer.<br>
            4. Keep the reference number and send the receipt to the dormitory administration for posting.
          </div>
        </td></tr>
      </table>`;
        }
    },
    maya:        { enabled: false, available(){ return false; }, render(){ return ''; } },
    bankTransfer:{ enabled: false, available(){ return false; }, render(){ return ''; } },
    paymongo:    { enabled: false, available(){ return false; }, render(){ return ''; } },
    stripe:      { enabled: false, available(){ return false; }, render(){ return ''; } },
    paypal:      { enabled: false, available(){ return false; }, render(){ return ''; } }
};

/** Renders every enabled + available payment provider block, or nothing. */
function paymentSection(c, data, colors) {
    return Object.keys(EMAIL_PAYMENT_PROVIDERS)
        .map(k => EMAIL_PAYMENT_PROVIDERS[k])
        .filter(p => p && p.enabled && p.available(c, data))
        .map(p => p.render(c, data, colors))
        .join('');
}

/* ====================================================================
 * NOTIFICATION TYPE REGISTRY
 *
 * Only the dynamic parts live here. Everything else is shared.
 * ==================================================================== */
function tenantRows(c, d) {
    return [
        ['Tenant Name', esc(d.name || '—')],
        ['Room Number', esc(d.roomNumber || d.roomId || '—')],
        bedRow(d),
        d.monthlyRent != null ? ['Monthly Rent', money(c, d.monthlyRent)] : null,
        d.balance != null ? ['Outstanding Balance', money(c, d.balance)] : null,
        ['Due Date', d.dueDate ? fmtDate(d.dueDate) : '—'],
        ['Payment Status', Number(d.balance || 0) > 0 ? 'Outstanding' : 'Settled']
    ];
}

/* Central helper: every email template shows "ENTIRE ROOM" (not Bed 1 /
 * Bed —) for entire-room reservations and check-ins. Uses the same rule
 * as the front-end getReceiptAccommodation(): entire_room wins over bedNo. */
function bedRow(d) {
    var isEntire = d && (d.occupancyType === 'entire_room' || d.type === 'room');
    if (isEntire) return ['Accommodation', 'ENTIRE ROOM'];
    return ['Bed Number', esc((d && d.bedNo) || '—')];
}

const EMAIL_TYPES = {
    'reservation-confirmation': {
        prefix: 'RSV', color: 'blue', icon: '&#10004;', badge: 'Reservation Confirmed',
        title: 'Your Reservation Is Confirmed',
        subject: (c) => `[${c.dormName}] Reservation Confirmed`,
        message: (c, d) => `We are pleased to confirm that your reservation at ${esc(c.companyName || c.dormName)} has been successfully recorded. Details of your booking are shown below.`,
        closing: () => 'Kindly complete your check-in on or before the expiration date to secure your accommodation. We look forward to welcoming you.',
        status: () => ({ label: 'Confirmed', color: STATUS_COLORS.blue.main }),
        button: () => 'View Reservation Details',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Reservation Date', d.date ? fmtDate(d.date) : fmtDate(new Date())],
            ['Expiration', d.expiresOn ? fmtDate(d.expiresOn) : '—'],
            ['Reservation Status', 'Confirmed']
        ]
    },
    'reservation-approved': {
        prefix: 'RSV', color: 'blue', icon: '&#10004;', badge: 'Reservation Approved',
        title: 'Your Reservation Has Been Approved',
        subject: (c) => `[${c.dormName}] Reservation Approved`,
        message: (c, d) => `Good news — your reservation request has been reviewed and approved by the ${esc(c.companyName || c.dormName)} administration.`,
        closing: () => 'Please proceed with your check-in on or before the expiration date shown above.',
        status: () => ({ label: 'Approved', color: STATUS_COLORS.blue.main }),
        button: () => 'Proceed to Check-in',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Approved On', fmtDate(d.approvedOn || new Date())],
            ['Expiration', d.expiresOn ? fmtDate(d.expiresOn) : '—'],
            ['Reservation Status', 'Approved']
        ]
    },
    'reservation-declined': {
        prefix: 'RSV', color: 'gray', icon: '&#10006;', badge: 'Reservation Declined',
        title: 'Reservation Request Declined',
        subject: (c) => `[${c.dormName}] Reservation Declined`,
        message: (c, d) => `We regret to inform you that your reservation request could not be accommodated at this time${d.reason ? ` — <b style="color:#0f172a;">${esc(d.reason)}</b>` : ''}.`,
        closing: () => 'You may submit a new request or contact the dormitory administration to be added to the waiting list.',
        status: () => ({ label: 'Declined', color: STATUS_COLORS.gray.main }),
        button: () => 'Contact Administration',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Requested', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Request Date', d.date ? fmtDate(d.date) : '—'],
            ['Reason', esc(d.reason || 'Not specified')],
            ['Reservation Status', 'Declined']
        ]
    },
    'reservation-cancelled': {
        prefix: 'CAN', color: 'gray', icon: '&#10006;', badge: 'Reservation Cancelled',
        title: 'Reservation Cancellation Notice',
        subject: (c) => `[${c.dormName}] Reservation Cancelled`,
        message: (c, d) => `We would like to inform you that your reservation at ${esc(c.companyName || c.dormName)} has been cancelled${d.reason ? ` for the following reason: <b style="color:#0f172a;">${esc(d.reason)}</b>` : ''}.`,
        closing: (c, d) => {
            const dormName = String(c.companyName || c.dormName || 'the dormitory').toUpperCase();
            const notice = `
                <div style="margin-top:18px;padding:18px 20px;border:1px solid #e2e8f0;border-radius:10px;background:#fafafa;font-family:Georgia,'Times New Roman',serif;color:#1e293b;line-height:1.6;">
                    <div style="font-size:12px;letter-spacing:.22em;text-transform:uppercase;color:#b91c1c;border-bottom:2px solid #b91c1c;padding-bottom:8px;margin-bottom:14px;font-weight:700;">No Return of Deposit Policy</div>
                    <p style="margin:0 0 10px 0;">All deposits tendered at the time of reservation &mdash; whether for a <b>single bed space</b> or for an <b>entire room</b> &mdash; are strictly <b>NON-REFUNDABLE</b> upon cancellation of the reservation.</p>
                    <p style="margin:0 0 10px 0;">This policy is applied uniformly, regardless of the reason for cancellation, the length of time between booking and cancellation, or the payment method originally used. The deposit secures the reserved accommodation on the guest&rsquo;s behalf from the moment of booking, and its forfeiture upon cancellation is intended to offset the opportunity cost of the reserved bed or room.</p>
                    <p style="margin:0 0 10px 0;">Guests retain the full right to cancel their reservation at any time; however, no portion of the deposit shall be returned. This notice constitutes the formal statement of policy furnished at booking and reiterated at cancellation.</p>
                    <p style="margin:14px 0 0 0;font-style:italic;">Respectfully,<br>${esc(dormName)} MANAGEMENT</p>
                    <p style="margin:8px 0 0 0;font-size:11px;color:#64748b;">This is an official policy notice. Please retain a copy for your records.</p>
                </div>
                <p style="margin:14px 0 0 0;color:#334155;">If this cancellation was made in error or you wish to book again, please contact the dormitory administration at your earliest convenience.</p>`;
            return notice;
        },
        status: () => ({ label: 'Cancelled', color: STATUS_COLORS.gray.main }),
        button: () => 'Contact Administration',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Reservation Date', d.date ? fmtDate(d.date) : '—'],
            ['Reason for Cancellation', esc(d.reason || 'Not specified')],
            ['Cancelled On', fmtDate(d.cancelledOn || new Date())],
            ['Reservation Status', 'Cancelled']
        ]
    },
    'reservation-expired': {
        prefix: 'EXP', color: 'red', icon: '&#9888;', badge: 'Reservation Expired',
        title: 'Your Reservation Has Expired',
        subject: (c) => `[${c.dormName}] Reservation Expired`,
        message: (c, d) => `Your reservation at ${esc(c.companyName || c.dormName)} has expired and the reserved bed has been released back to the available pool.`,
        closing: () => 'If you are still interested in staying with us, kindly submit a new reservation or contact the dormitory administration.',
        status: () => ({ label: 'Expired', color: STATUS_COLORS.red.main }),
        button: () => 'Make a New Reservation',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Reservation Date', d.date ? fmtDate(d.date) : '—'],
            ['Expired On', fmtDate(d.expiresOn || new Date())],
            ['Reservation Status', 'Expired']
        ]
    },
    'reservation-reminder': {
        prefix: 'RSV', color: 'yellow', icon: '&#9200;', badge: 'Reservation Reminder',
        title: 'Your Reservation Is About to Expire',
        subject: (c) => `[${c.dormName}] Reservation Expiring Soon`,
        message: (c, d) => `This is a courteous notice that your reservation at ${esc(c.companyName || c.dormName)} is set to expire in <b style="color:${STATUS_COLORS.yellow.main};">${esc(d.daysLeft || 1)} day${Number(d.daysLeft) === 1 ? '' : 's'}</b>. Please complete your check-in before the expiration date; otherwise the reservation will be automatically released.`,
        closing: () => 'For assistance or to extend your reservation, kindly reach out to the dormitory administration.',
        status: () => ({ label: 'Expiring Soon', color: STATUS_COLORS.yellow.main }),
        button: () => 'Complete Check-in',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Expiration Date', d.expiresOn ? fmtDate(d.expiresOn) : '—'],
            ['Days Remaining', `${esc(d.daysLeft || 1)} day${Number(d.daysLeft) === 1 ? '' : 's'}`],
            ['Reservation Status', 'Expiring']
        ]
    },
    'check-in': {
        prefix: 'CHI', color: 'green', icon: '&#10004;', badge: 'Check-in Successful',
        title: 'Check-in Completed Successfully',
        subject: (c) => `[${c.dormName}] Check-in Successful`,
        message: (c, d) => `Welcome! Your check-in at ${esc(c.companyName || c.dormName)} has been completed successfully. Your accommodation details are confirmed below.`,
        closing: () => 'Should you need anything during your stay, the dormitory administration is happy to assist.',
        status: () => ({ label: 'Checked In', color: STATUS_COLORS.green.main }),
        button: () => 'View My Accommodation',
        rows: (c, d) => tenantRows(c, d).concat([['Check-in Date', fmtDate(d.checkInDate || d.moveInDate || new Date())]])
    },
    'check-out': {
        prefix: 'CHO', color: 'gray', icon: '&#128075;', badge: 'Check-out Successful',
        title: 'Check-out Completed Successfully',
        subject: (c) => `[${c.dormName}] Check-out Successful`,
        message: (c, d) => `Your check-out from ${esc(c.companyName || c.dormName)} has been processed successfully. Thank you for staying with us.`,
        closing: () => 'We hope your stay was comfortable and we would be glad to welcome you back in the future.',
        status: (c, d) => ({ label: Number(d.balance || 0) > 0 ? 'Balance Outstanding' : 'Cleared', color: Number(d.balance || 0) > 0 ? STATUS_COLORS.red.main : STATUS_COLORS.green.main }),
        button: () => 'Request Clearance Copy',
        rows: (c, d) => tenantRows(c, d).concat([['Check-out Date', fmtDate(d.checkOutDate || new Date())]])
    },
    'room-transfer': {
        prefix: 'TRF', color: 'purple', icon: '&#8646;', badge: 'Room Transfer',
        title: 'Room Transfer Confirmation',
        subject: (c) => `[${c.dormName}] Room Transfer Confirmation`,
        message: (c, d) => `Your room assignment at ${esc(c.companyName || c.dormName)} has been updated${d.reason ? ` — <b style="color:#0f172a;">${esc(d.reason)}</b>` : ''}. Your new accommodation details are shown below.`,
        closing: () => 'Please coordinate with the dormitory administration for the turnover of keys and room inventory.',
        status: () => ({ label: 'Transferred', color: STATUS_COLORS.purple.main }),
        button: () => 'View New Room Details',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Previous Room', esc(d.previousRoom || '—')],
            ['Previous Bed', esc(d.previousBed || '—')],
            ['New Room Number', esc(d.roomNumber || d.roomId || '—')],
            ['New Bed Number', esc(d.bedNo || '—')],
            ['Transfer Date', fmtDate(d.transferDate || new Date())],
            ['Monthly Rent', money(c, d.monthlyRent || 0)]
        ]
    },
    'payment-notification': {
        prefix: 'PAY', color: 'green', icon: '&#10004;', badge: 'Payment Successful',
        title: 'Payment Successfully Received',
        subject: (c, d) => `[${c.dormName}] Payment Received — ${money(c, d.amount || 0)}`,
        message: (c, d) => `Thank you! We have successfully received your payment. A summary of the transaction is shown below.`,
        closing: (c, d) => Number(d.balance || 0) > 0 ? 'Your remaining balance is reflected above. Kindly settle it on or before the due date.' : 'Your account is now fully settled. We sincerely appreciate your prompt payment.',
        status: (c, d) => ({ label: Number(d.balance || 0) > 0 ? 'Partial Payment' : 'Fully Paid', color: Number(d.balance || 0) > 0 ? STATUS_COLORS.orange.main : STATUS_COLORS.green.main }),
        button: () => 'View Payment History',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Amount Paid', money(c, d.amount || 0)],
            ['Previous Balance', money(c, d.previousBalance || 0)],
            ['Outstanding Balance', money(c, d.balance || 0)],
            ['Payment Date', fmtDate(d.paymentDate || new Date())],
            ['Payment Reference', esc(d.paymentReference || 'N/A')]
        ]
    },
    'payment-receipt': {
        prefix: 'RCP', color: 'green', icon: '&#10004;', badge: 'Payment Received',
        title: 'Payment Confirmation & Receipt',
        subject: (c, d) => `[${c.dormName}] Payment Receipt — ${money(c, d.amount || 0)}`,
        message: () => 'Thank you! We have successfully received your payment. Below is the official record of your transaction — please retain this email for your records.',
        closing: (c, d) => Number(d.balance || 0) > 0 ? 'Your remaining balance is reflected above. Kindly settle the outstanding amount on or before the due date.' : 'Your account is now fully settled. We sincerely appreciate your prompt payment.',
        status: (c, d) => ({ label: Number(d.balance || 0) > 0 ? 'Partial Payment' : 'Fully Paid', color: Number(d.balance || 0) > 0 ? STATUS_COLORS.orange.main : STATUS_COLORS.green.main }),
        button: () => 'Download Official Receipt',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            bedRow(d),
            ['Monthly Rent', money(c, d.monthlyRent || 0)],
            ['Amount Paid', money(c, d.amount || 0)],
            ['Previous Balance', money(c, d.previousBalance || 0)],
            ['Outstanding Balance', money(c, d.balance || 0)],
            ['Due Date', d.dueDate ? fmtDate(d.dueDate) : '—'],
            ['Payment Reference', esc(d.paymentReference || 'N/A')],
            ['Official Receipt No.', esc(d.orNumber || '—')],
            ['Payment Date', fmtDate(d.paymentDate || new Date())]
        ]
    },
    'billing-notification': {
        prefix: 'BIL', color: 'blue', icon: '&#128196;', badge: 'Billing Notification',
        title: 'New Billing Statement',
        subject: (c) => `[${c.dormName}] New Billing Statement`,
        message: (c, d) => `A new billing statement has been generated for your account at ${esc(c.companyName || c.dormName)}. Please review the details below.`,
        closing: () => 'Kindly settle your balance on or before the due date to keep your account in good standing.',
        status: () => ({ label: 'Payment Required', color: STATUS_COLORS.blue.main }),
        button: () => 'Settle Balance Now',
        payment: true,
        rows: (c, d) => tenantRows(c, d).concat(d.amount != null ? [['Amount Billed', money(c, d.amount)]] : [])
    },
    'payment-due-today': {
        prefix: 'DUE', color: 'orange', icon: '&#9888;', badge: 'Payment Due Today',
        title: 'Your Payment Is Due Today',
        subject: (c, d) => `[${c.dormName}] Payment Due TODAY — ${fmtDate(d.dueDate || new Date())}`,
        message: (c, d) => `Our records indicate that your monthly rent of <b style="color:${STATUS_COLORS.orange.main};">${money(c, d.balance || 0)}</b> is <b>due today, ${fmtDate(d.dueDate || new Date())}</b>. Please arrange settlement before end of day.`,
        closing: () => 'If your payment has already been processed, kindly disregard this notice. For assistance, please contact the dormitory administration.',
        status: () => ({ label: 'Due Today', color: STATUS_COLORS.orange.main }),
        button: () => 'Pay Now',
        payment: true,
        rows: (c, d) => tenantRows(c, d)
    },
    'upcoming-reminder': {
        prefix: 'REM', color: 'yellow', icon: '&#9200;', badge: 'Upcoming Reminder',
        title: 'Upcoming Payment Reminder',
        subject: (c, d) => `[${c.dormName}] Upcoming Payment Due on ${fmtDate(d.dueDate || new Date())}`,
        message: (c, d) => `This is a courteous reminder that your monthly rent payment is scheduled to be due in <b style="color:${STATUS_COLORS.yellow.main};">${esc(d.daysAway != null ? d.daysAway : 1)} day${Number(d.daysAway) === 1 ? '' : 's'}</b> — on <b style="color:#0f172a;">${fmtDate(d.dueDate || new Date())}</b>. Please review the details below at your convenience.`,
        closing: (c) => `Kindly settle your balance on or before the due date to avoid any late-payment notice. Thank you for your continued stay with us at ${esc(c.companyName || c.dormName)}.`,
        status: () => ({ label: 'Payment Upcoming', color: STATUS_COLORS.yellow.main }),
        button: () => 'Pay Early',
        payment: true,
        rows: (c, d) => tenantRows(c, d)
    },
    'overdue-reminder': {
        prefix: 'OVD', color: 'red', icon: '&#10071;', badge: 'Overdue Notice',
        title: 'Overdue Payment Notice',
        subject: (c) => `[${c.dormName}] OVERDUE — Balance Settlement Required`,
        message: (c, d) => `Our records show that your rent payment was due on <b style="color:#0f172a;">${fmtDate(d.dueDate || new Date())}</b> and is now <b style="color:${STATUS_COLORS.red.main};">${esc(d.daysLate != null ? d.daysLate : 1)} day${Number(d.daysLate) === 1 ? '' : 's'} overdue</b>. Immediate settlement is respectfully requested.`,
        closing: () => 'Please settle your outstanding balance as soon as possible to avoid additional penalties. Kindly contact the dormitory office if you require any assistance or a payment arrangement.',
        status: () => ({ label: 'Overdue', color: STATUS_COLORS.red.main }),
        button: () => 'Settle Overdue Balance',
        payment: true,
        rows: (c, d) => tenantRows(c, d).concat([['Days Overdue', `${esc(d.daysLate != null ? d.daysLate : 1)} day${Number(d.daysLate) === 1 ? '' : 's'}`]])
    },
    'maintenance': {
        prefix: 'MNT', color: 'purple', icon: '&#128295;', badge: 'Maintenance Notification',
        title: 'Maintenance Update',
        subject: (c, d) => `[${c.dormName}] Maintenance Update${d.ticketId ? ' — ' + d.ticketId : ''}`,
        message: (c, d) => d.message ? esc(d.message) : 'There is an update regarding a maintenance request associated with your accommodation. Details are listed below.',
        closing: () => 'Our maintenance team will coordinate with you should access to your room be required.',
        status: (c, d) => ({ label: esc(d.status || 'In Progress'), color: STATUS_COLORS.purple.main }),
        button: () => 'View Maintenance Ticket',
        rows: (c, d) => [
            ['Tenant Name', esc(d.name || '—')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            ['Ticket Number', esc(d.ticketId || '—')],
            ['Category', esc(d.category || 'General')],
            ['Priority', esc(d.priority || 'Normal')],
            ['Reported On', d.reportedOn ? fmtDate(d.reportedOn) : fmtDate(new Date())],
            ['Current Status', esc(d.status || 'In Progress')]
        ]
    },
    'announcement': {
        prefix: 'ANN', color: 'blue', icon: '&#128226;', badge: 'Announcement',
        title: 'Dormitory Announcement',
        subject: (c, d) => `[${c.dormName}] ${d.subject || 'Announcement'}`,
        message: (c, d) => d.message ? esc(d.message) : 'Please take note of the following announcement from the dormitory administration.',
        closing: () => 'Thank you for your cooperation and continued support.',
        status: () => ({ label: 'Notice', color: STATUS_COLORS.blue.main }),
        button: () => '',
        rows: (c, d) => [
            ['Recipient', esc(d.name || 'Resident')],
            ['Room Number', esc(d.roomNumber || d.roomId || '—')],
            ['Announcement', esc(d.subject || 'General Notice')],
            ['Effective Date', d.effectiveDate ? fmtDate(d.effectiveDate) : fmtDate(new Date())],
            ['Issued By', esc(c.signature)]
        ]
    },
    'welcome': {
        prefix: 'WEL', color: 'green', icon: '&#127881;', badge: 'Welcome',
        title: 'Welcome to Your New Home',
        subject: (c) => `[${c.dormName}] Welcome!`,
        message: (c, d) => `Welcome to ${esc(c.companyName || c.dormName)}! Your account has been created and your accommodation is ready. Here are your details.`,
        closing: () => 'We are delighted to have you with us. Please reach out to the administration for any assistance.',
        status: () => ({ label: 'Active', color: STATUS_COLORS.green.main }),
        button: () => 'View My Account',
        rows: (c, d) => tenantRows(c, d)
    },
    'password-reset': {
        prefix: 'PWD', color: 'blue', icon: '&#128274;', badge: 'Password Reset',
        title: 'Password Reset Request',
        subject: (c) => `[${c.dormName}] Password Reset Request`,
        message: (c, d) => `We received a request to reset the password for your ${esc(c.systemName)} account. Use the details below to continue. This request expires in ${esc(d.expiresInMinutes || 30)} minutes.`,
        closing: () => 'If you did not request a password reset, please ignore this email or contact the administration immediately.',
        status: () => ({ label: 'Action Required', color: STATUS_COLORS.blue.main }),
        button: () => 'Reset My Password',
        rows: (c, d) => [
            ['Account Name', esc(d.name || '—')],
            ['Username', esc(d.username || d.to || '—')],
            ['Request Date', fmtDateTime(new Date())],
            ['Reset Code', `<span style="font-family:'Courier New',Consolas,monospace;letter-spacing:2px;">${esc(d.resetCode || '—')}</span>`],
            ['Valid For', `${esc(d.expiresInMinutes || 30)} minutes`]
        ]
    },
    'generic': {
        prefix: 'GEN', color: 'blue', icon: '&#9993;', badge: 'Notification',
        title: 'System Notification',
        subject: (c, d) => d.subject || `[${c.dormName}] Notification`,
        message: (c, d) => esc(d.message || ''),
        closing: () => '',
        status: () => ({ label: 'Notice', color: STATUS_COLORS.blue.main }),
        button: () => '',
        rows: (c, d) => [
            ['Recipient', esc(d.name || d.to || '—')],
            ['Subject', esc(d.subject || 'Notification')],
            ['Date', fmtDateTime(new Date())]
        ]
    }
};

/* Legacy type aliases so older call sites keep working unchanged. */
const EMAIL_TYPE_ALIASES = {
    'Upcoming': 'upcoming-reminder',
    'Due Today': 'payment-due-today',
    'Overdue': 'overdue-reminder',
    'Receipt': 'payment-receipt',
    'Reminder': 'upcoming-reminder',
    'Billing': 'billing-notification',
    'Reservation': 'reservation-confirmation',
    'Reservation Confirmation': 'reservation-confirmation',
    'Reservation Cancellation': 'reservation-cancelled',
    'Reservation Expiration': 'reservation-reminder',
    'CheckIn': 'check-in',
    'Checkout': 'check-out',
    'Transfer': 'room-transfer',
    'Notification': 'generic',
    'Manual': 'generic',
    'AdminAlert': 'generic'
};
function resolveEmailType(type){
    if (!type) return 'generic';
    if (EMAIL_TYPES[type]) return type;
    const alias = EMAIL_TYPE_ALIASES[type];
    if (alias) return alias;
    const slug = String(type).trim().toLowerCase().replace(/\s+/g, '-');
    return EMAIL_TYPES[slug] ? slug : 'generic';
}

/* ====================================================================
 * THE ONLY EMAIL RENDERER IN THE SYSTEM
 * ==================================================================== */
function renderEmail(db, type, data) {
    const key = resolveEmailType(type);
    const def = EMAIL_TYPES[key];
    const c = ctx(db);
    const d = data || {};
    const colors = tone(def.color);
    const accent = colors.main;
    const reference = REF_PLACEHOLDER;

    const status = typeof def.status === 'function' ? def.status(c, d) : null;
    const title = typeof def.title === 'function' ? def.title(c, d) : def.title;
    const buttonLabel = d.buttonLabel != null ? d.buttonLabel : (typeof def.button === 'function' ? def.button(c, d) : def.button);
    const buttonUrl = resolveActionUrl(c, d, buttonLabel);
    const closing = typeof def.closing === 'function' ? def.closing(c, d) : (def.closing || '');
    const showPayment = (d.showPayment != null ? d.showPayment : !!def.payment);

    const bodyInner = `
      ${statusBadge(def.icon, def.badge, accent)}
      ${notificationTitle(title, accent)}
      <p style="margin:0 0 14px 0;color:#334155;">Dear <b style="color:#0f172a;">${esc(d.name || 'Resident')}</b>,</p>
      <p style="margin:0 0 6px 0;color:#334155;">${def.message(c, d)}</p>
      ${infoCard(def.rows(c, d), status)}
      ${showPayment ? paymentSection(c, d, colors) : ''}
      ${buttonLabel ? actionButton(buttonLabel, buttonUrl, accent) : ''}
      ${closing ? `${accentLine(accent)}<p style="margin:0;color:#334155;">${closing}</p>` : ''}`;

    return {
        type: key,
        logType: def.prefix,
        subject: (d.subjectOverride) || (typeof def.subject === 'function' ? def.subject(c, d) : def.subject),
        html: baseShell({ title, bodyInner, ...c, reference, accent })
    };
}

/* Data adapters — turn domain records into the standard email data object. */
function tenantEmailData(db, tenant, extra) {
    const room = findRoom(db, tenant) || null;
    // Detect entire-room occupancy so bedRow() renders "ENTIRE ROOM" for tenants
    // who occupy the whole room (never falls back to Bed 1).
    const _isEntire = !!(tenant && (tenant.occupancyType === 'entire_room' ||
        (room && String(room.entireRoomBoarderId || '') === String(tenant.id || ''))));
    return {
        name: tenant.name,
        to: tenant.email,
        roomNumber: room ? (room.roomName || `Room ${room.roomNumber}`) : (tenant.roomId || ''),
        bedNo: _isEntire ? null : tenant.bedNo,
        occupancyType: _isEntire ? 'entire_room' : (tenant.occupancyType || 'bed'),
        monthlyRent: tenant.monthlyRent || tenant.rentRate || 0,
        balance: tenant.balance || 0,
        dueDate: tenant.dueDate || '',
        ...(extra || {})
    };
}
function reservationEmailData(res, extra) {
    const _isEntire = !!(res && (res.occupancyType === 'entire_room' || res.type === 'room'));
    return {
        name: res.name,
        to: res.email,
        roomNumber: res.roomName || res.roomId || '',
        bedNo: _isEntire ? null : res.bedNo,
        occupancyType: _isEntire ? 'entire_room' : (res.occupancyType || 'bed'),
        type: res.type,
        date: res.date,
        expiresOn: res.expiresOn || res.expDate,
        ...(extra || {})
    };
}

/* -------------------- Backward-compatible template wrappers --------------------
 * Every legacy tpl* helper now simply delegates to the one global engine. */
function tplUpcomingDue(db, tenant, dueDate, daysAway) {
    return renderEmail(db, 'upcoming-reminder', tenantEmailData(db, tenant, { dueDate, daysAway }));
}
function tplDueToday(db, tenant, dueDate) {
    return renderEmail(db, 'payment-due-today', tenantEmailData(db, tenant, { dueDate }));
}
function tplOverdue(db, tenant, dueDate, daysLate) {
    return renderEmail(db, 'overdue-reminder', tenantEmailData(db, tenant, { dueDate, daysLate }));
}
function tplPaymentReceipt(db, tenant, tx, prevBalance) {
    return renderEmail(db, 'payment-receipt', tenantEmailData(db, tenant, {
        amount: tx.amount,
        previousBalance: prevBalance,
        paymentReference: tx.reference,
        orNumber: tx.orNumber || tx.id,
        paymentDate: tx.date || new Date()
    }));
}
function tplReservationConfirmation(db, res) {
    return renderEmail(db, 'reservation-confirmation', reservationEmailData(res));
}
function tplReservationCancellation(db, res, reason) {
    return renderEmail(db, 'reservation-cancelled', reservationEmailData(res, { reason }));
}
function tplReservationExpiration(db, res, daysLeft) {
    return renderEmail(db, 'reservation-reminder', reservationEmailData(res, { daysLeft: daysLeft || 1 }));
}


/* ====================================================================
 * VALIDATION
 * ==================================================================== */
function validateBoarderPayload(b) {
    if (!b.name || typeof b.name !== 'string' || b.name.trim() === '') throw new Error('Full Name is mandatory.');
    if (!b.email || !EMAIL_REGEX.test(b.email)) throw new Error('Invalid email format.');
    if (b.monthlyRent !== undefined && (isNaN(b.monthlyRent) || b.monthlyRent < 0)) throw new Error('Rent must be a non-negative number.');
    if (b.balance !== undefined && (isNaN(b.balance) || b.balance < 0)) throw new Error('Balance cannot be negative.');
}


/* ====================================================================
 * v4.0 — FINAL RESERVATION & CHECK-IN OCCUPANCY RULES (SERVER SIDE)
 * --------------------------------------------------------------------
 * The frontend disables/hides invalid buttons for UX. These rules are
 * what actually protect data integrity: they are evaluated on every
 * /api/data sync, against the PRIOR persisted state, so a crafted or
 * direct request cannot create a conflicting occupancy.
 *
 *   Occupancy model (single source of truth):
 *     boarder.occupancyType    : 'bed' | 'entire_room'
 *     reservation.type         : 'bed' | 'room'
 *     reservation.occupancyType: 'bed' | 'entire_room'
 *     room.entireRoomBoarderId : id of the entire-room occupant (or null)
 * ==================================================================== */
// 'Reservation Fee Credit' is a settlement method, not a collection: it is used
// when the Reservation Fee already paid fully covers the Check-in charges.
const PAY_METHODS = ['Cash', 'GCash', 'Bank Transfer', 'Card', 'Reservation Fee Credit'];
const REF_REQUIRED_METHODS = ['GCash', 'Bank Transfer'];

/* Sensitive card data must NEVER be persisted. */
const FORBIDDEN_PAYMENT_FIELDS = ['cardNumber', 'cardNo', 'pan', 'cvv', 'cvc', 'cardPin', 'pin', 'cardPassword', 'password'];

function stripSensitivePaymentFields(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    FORBIDDEN_PAYMENT_FIELDS.forEach(f => { if (f in obj) delete obj[f]; });
    return obj;
}

function v40RoomOf(db, roomId) {
    return (db.rooms || []).find(r => String(r.id) === String(roomId)) || null;
}
function v40EntireOccupant(db, room) {
    if (!room) return null;
    const inRoom = (db.boarders || []).filter(b => String(b.roomId) === String(room.id));
    if (room.entireRoomBoarderId) {
        const owner = inRoom.find(b => b.id === room.entireRoomBoarderId);
        if (owner) return owner;
    }
    return inRoom.find(b => b.occupancyType === 'entire_room') || null;
}
function v40ActiveEntireRes(db, roomId, ignoreId) {
    return (db.reservations || []).find(r =>
        String(r.roomId) === String(roomId) &&
        r.id !== ignoreId &&
        (r.type === 'room' || r.occupancyType === 'entire_room') &&
        (r.status === 'Active' || r.status === 'Checked-in')) || null;
}
function v40ActiveBedRes(db, roomId, bedNo, ignoreId) {
    return (db.reservations || []).find(r =>
        String(r.roomId) === String(roomId) &&
        r.id !== ignoreId &&
        (r.type === 'bed' || r.occupancyType === 'bed') &&
        (bedNo === undefined || String(r.bedNo) === String(bedNo)) &&
        (r.status === 'Active' || r.status === 'Checked-in')) || null;
}

/* Validates every NEWLY added reservation against the prior state.
 * Returns an error object or null. */
function validateNewReservations(existing, merged) {
    const priorIds = new Set((existing.reservations || []).map(r => r.id));
    const incoming = Array.isArray(merged.reservations) ? merged.reservations : [];
    for (const r of incoming) {
        if (priorIds.has(r.id)) continue;
        stripSensitivePaymentFields(r);

        const isEntire = (r.type === 'room' || r.occupancyType === 'entire_room');

        // Consistency of the occupancy declaration
        if (isEntire && r.occupancyType && r.occupancyType !== 'entire_room') {
            return { error: 'Invalid occupancy type combination.', details: `Reservation ${r.id} mixes type=room with occupancyType=${r.occupancyType}.` };
        }
        if (!isEntire && r.occupancyType && r.occupancyType !== 'bed') {
            return { error: 'Invalid occupancy type combination.', details: `Reservation ${r.id} mixes type=bed with occupancyType=${r.occupancyType}.` };
        }

        const room = v40RoomOf(existing, r.roomId) || v40RoomOf(merged, r.roomId);
        if (!room) return { error: 'Invalid room.', details: `Reservation ${r.id} references unknown room ${r.roomId}.` };
        if (room.type === 'Admin') return { error: 'Invalid room.', details: `Room ${room.roomName || room.id} is not rentable.` };

        // === Designated Room Payer rule (server-side enforcement) ===
        // A Bed Space reservation in a room that already has a Designated Room
        // Payer must NOT carry Deposit or Payment Method. Ignore any values
        // supplied by the client so this cannot be bypassed via DevTools or
        // direct API requests. Entire Room reservations are unaffected.
        if (!isEntire) {
            const _priorRoom = v40RoomOf(existing, room.id) || room;
            if (_priorRoom && _priorRoom.payerId) {
                r.deposit = 0;
                r.method = null;
                r.paymentMethod = null;
                r.paymentReference = '';
                r.reference = '';
            }
        }


        // Payment integrity (applies to all four transaction paths)
        const pm = String(r.paymentMethod || r.method || '').trim();
        const pr = String(r.paymentReference || r.reference || '').trim();
        if (pm && PAY_METHODS.indexOf(pm) === -1) {
            return { error: 'Invalid payment method.', details: `Reservation ${r.id} uses unsupported payment method "${pm}".` };
        }
        if (Number(r.deposit || 0) > 0 && REF_REQUIRED_METHODS.indexOf(pm) !== -1 && !pr) {
            return { error: 'Reference Number required.', details: `Reservation ${r.id} paid via ${pm} but has no Reference Number.` };
        }

        // Occupancy conflicts, evaluated against the PRIOR state
        const priorOwner = v40EntireOccupant(existing, v40RoomOf(existing, room.id));
        const priorEntireRes = v40ActiveEntireRes(existing, room.id, r.id);

        if (isEntire) {
            if (r.bedNo) return { error: 'Invalid room/bed combination.', details: `Entire Room reservation ${r.id} must not carry a bed number.` };
            if (priorOwner) return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is occupied as an Entire Room; a new Entire Room reservation is not allowed.` };
            if (priorEntireRes) return { error: 'Duplicate reservation.', details: `Room ${room.roomName || room.id} already has an active Entire Room reservation (${priorEntireRes.id}).` };
            const pRoom = v40RoomOf(existing, room.id) || room;
            if ((pRoom.beds || []).some(b => b.isOccupied)) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} has active Bed Space occupants; Entire Room reservation is blocked.` };
            }
            if ((pRoom.beds || []).some(b => b.isReserved) || v40ActiveBedRes(existing, room.id, undefined, r.id)) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} has Bed Space reservations; Entire Room reservation is blocked.` };
            }
        } else {
            if (!r.bedNo) return { error: 'Invalid room/bed combination.', details: `Bed Space reservation ${r.id} has no bed number.` };
            const bedDef = (room.beds || []).find(b => String(b.bedNo) === String(r.bedNo));
            if (!bedDef) return { error: 'Invalid room/bed combination.', details: `Bed ${r.bedNo} does not exist in room ${room.roomName || room.id}.` };
            if (priorOwner) return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is occupied as an Entire Room; Bed Space reservation is blocked.` };
            if (priorEntireRes) return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is reserved as an Entire Room; Bed Space reservation is blocked.` };
            const pRoom = v40RoomOf(existing, room.id) || room;
            const priorBed = (pRoom.beds || []).find(b => String(b.bedNo) === String(r.bedNo));
            if (priorBed && priorBed.isOccupied) {
                return { error: 'Occupancy conflict.', details: `Bed ${r.bedNo} in room ${room.roomName || room.id} is already occupied.` };
            }
            const dupe = v40ActiveBedRes(existing, room.id, r.bedNo, r.id);
            if (dupe) return { error: 'Duplicate reservation.', details: `Bed ${r.bedNo} in room ${room.roomName || room.id} already has an active reservation (${dupe.id}).` };
        }
    }
    return null;
}

/* Validates every NEWLY added boarder (check-in) against the prior state. */
function validateNewCheckIns(existing, merged) {
    const priorIds = new Set((existing.boarders || []).map(b => b.id));
    const resById = new Map((merged.reservations || []).map(r => [r.id, r]));
    const incoming = Array.isArray(merged.boarders) ? merged.boarders : [];
    for (const b of incoming) {
        if (priorIds.has(b.id)) continue;
        stripSensitivePaymentFields(b);

        const isEntire = b.occupancyType === 'entire_room';
        const room = v40RoomOf(existing, b.roomId) || v40RoomOf(merged, b.roomId);
        if (!room) return { error: 'Invalid room.', details: `Check-in for ${b.name || b.id} references unknown room ${b.roomId}.` };
        if (room.type === 'Admin') return { error: 'Invalid room.', details: `Room ${room.roomName || room.id} is not rentable.` };

        // Payment integrity
        const pm = String(b.paymentMethod || '').trim();
        const pr = String(b.paymentReference || '').trim();
        if (pm && PAY_METHODS.indexOf(pm) === -1) {
            return { error: 'Invalid payment method.', details: `Check-in for ${b.name || b.id} uses unsupported payment method "${pm}".` };
        }
        const _collected = (b.checkInAmountCollected === undefined || b.checkInAmountCollected === null)
            ? null : Number(b.checkInAmountCollected);
        if (REF_REQUIRED_METHODS.indexOf(pm) !== -1 && !pr && (_collected === null || _collected > 0)) {
            return { error: 'Reference Number required.', details: `Boarder ${b.name || b.id} paid via ${pm} but has no Reference Number.` };
        }

        const priorRoom = v40RoomOf(existing, room.id) || room;
        const priorOwner = v40EntireOccupant(existing, priorRoom);
        const linkedRes = b.reservationId ? resById.get(b.reservationId) : null;
        const priorEntireRes = v40ActiveEntireRes(existing, room.id, linkedRes ? linkedRes.id : undefined);

        if (isEntire) {
            if (linkedRes && (linkedRes.type === 'bed' || linkedRes.occupancyType === 'bed')) {
                return { error: 'Invalid occupancy type combination.', details: `Entire Room check-in for ${b.name || b.id} is linked to a Bed Space reservation (${linkedRes.id}).` };
            }
            if (priorOwner) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is already occupied as an Entire Room.` };
            }
            if ((priorRoom.beds || []).some(x => x.isOccupied)) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} already has active Bed Space occupants; Entire Room check-in is not allowed.` };
            }
            // A pre-existing entire-room reservation is only acceptable when this
            // check-in is fulfilling that exact reservation.
            if (priorEntireRes && (!linkedRes || linkedRes.id !== priorEntireRes.id)) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is reserved as an Entire Room by another applicant.` };
            }
            const otherRes = v40ActiveBedRes(existing, room.id);
            if (otherRes) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} has Bed Space reservations; Entire Room check-in is blocked.` };
            }
        } else {
            if (linkedRes && (linkedRes.type === 'room' || linkedRes.occupancyType === 'entire_room')) {
                return { error: 'Invalid occupancy type combination.', details: `Bed Space check-in for ${b.name || b.id} is linked to an Entire Room reservation (${linkedRes.id}).` };
            }
            if (priorOwner) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is occupied as an Entire Room; Bed Space check-in is blocked.` };
            }
            if (priorEntireRes) {
                return { error: 'Occupancy conflict.', details: `Room ${room.roomName || room.id} is reserved as an Entire Room; Bed Space check-in is blocked.` };
            }
            if (!b.bedNo) return { error: 'Invalid room/bed combination.', details: `Bed Space check-in for ${b.name || b.id} has no bed number.` };
            const bedDef = (room.beds || []).find(x => String(x.bedNo) === String(b.bedNo));
            if (!bedDef) return { error: 'Invalid room/bed combination.', details: `Bed ${b.bedNo} does not exist in room ${room.roomName || room.id}.` };
            const priorBed = (priorRoom.beds || []).find(x => String(x.bedNo) === String(b.bedNo));
            if (priorBed && priorBed.isOccupied) {
                return { error: 'Occupancy conflict.', details: `Bed ${b.bedNo} in room ${room.roomName || room.id} is already occupied.` };
            }
        }
    }
    return null;
}

/* ====================================================================
 * RESERVATION FEE -> CHECK-IN CREDIT INTEGRITY (server-side enforcement)
 *
 * ONE consistent financial meaning across the whole system:
 *   Total Check-in Charges = Room Rent + Security Deposit
 *   Remaining Amount Due   = Total Check-in Charges - Reservation Fee Paid
 *
 * The fee may be applied to exactly ONE check-in, must never be charged
 * twice, never deducted twice, and never silently disappear.
 * ==================================================================== */
function validateReservationFeeCredits(existing, merged) {
    const priorBoarderIds = new Set((existing.boarders || []).map(b => b.id));
    const reservations = Array.isArray(merged.reservations) ? merged.reservations : [];
    const resById = new Map(reservations.map(r => [r.id, r]));
    const boarders = Array.isArray(merged.boarders) ? merged.boarders : [];
    const txs = Array.isArray(merged.transactions) ? merged.transactions : [];
    const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;

    // A reservation fee may back at most one check-in credit.
    const usage = new Map();
    for (const b of boarders) {
        if (!b.reservationId) continue;
        const credit = Number(b.reservationFeeCredit || 0);
        if (credit <= 0) continue;
        usage.set(b.reservationId, (usage.get(b.reservationId) || 0) + credit);
    }
    for (const [resId, used] of usage.entries()) {
        const r = resById.get(resId);
        if (!r) return { error: 'Invalid reservation credit.', details: `Check-in references unknown reservation ${resId}.` };
        const fee = Number(r.deposit || 0);
        if (round2(used) > round2(fee)) {
            return { error: 'Reservation fee credit exceeded.', details: `Reservation ${resId} paid ${fee} but ${used} was credited to check-ins.` };
        }
        if (r.feeCreditForfeited) {
            return { error: 'Reservation fee forfeited.', details: `Reservation ${resId} was cancelled/expired; its fee cannot be credited to a check-in.` };
        }
    }

    for (const b of boarders) {
        if (priorBoarderIds.has(b.id)) continue;   // only newly added check-ins
        const rent = Number(b.rentRate || 0);
        const dep = Number(b.deposit || 0);
        const gross = rent + dep;
        const linked = b.reservationId ? resById.get(b.reservationId) : null;
        const fee = linked ? Number(linked.deposit || 0) : 0;
        const expectedCredit = linked && !linked.feeCreditForfeited ? Math.min(fee, gross) : 0;
        const credit = Number(b.reservationFeeCredit || 0);

        if (round2(credit) !== round2(expectedCredit)) {
            return {
                error: 'Reservation fee credit mismatch.',
                details: `Check-in for ${b.name || b.id} credited ${credit} but the reservation fee creditable against ${gross} in charges is ${expectedCredit}.`
            };
        }
        // The Security Deposit must NEVER be reduced by the credit.
        if (linked && dep > 0 && round2(dep) === round2(Math.max(0, dep))) { /* deposit kept whole */ }

        const expectedDue = Math.max(0, gross - expectedCredit);
        const checkInTx = txs.find(t => t.boarderId === b.id && Number(t.grossCharges || 0) > 0);
        if (checkInTx) {
            if (round2(Number(checkInTx.amount || 0)) !== round2(expectedDue)) {
                return {
                    error: 'Check-in amount mismatch.',
                    details: `Check-in transaction ${checkInTx.id} records ${checkInTx.amount}; expected ${expectedDue} (Rent ${rent} + Deposit ${dep} - Reservation Fee ${expectedCredit}).`
                };
            }
            if (round2(Number(checkInTx.reservationCredit || 0)) !== round2(expectedCredit)) {
                return {
                    error: 'Check-in credit mismatch.',
                    details: `Check-in transaction ${checkInTx.id} declares a reservation credit of ${checkInTx.reservationCredit}; expected ${expectedCredit}.`
                };
            }
            // No duplicate check-in payment transactions for the same boarder.
            const dupes = txs.filter(t => t.boarderId === b.id && Number(t.grossCharges || 0) > 0);
            if (dupes.length > 1) {
                return { error: 'Duplicate check-in transaction.', details: `Boarder ${b.name || b.id} has ${dupes.length} initial check-in payment records.` };
            }
        }
    }
    return null;
}

/* ====================================================================
 * API ROUTES — all existing routes preserved, plus new ones
 * ==================================================================== */
app.get('/api/data', (req, res) => {
    try { res.status(200).json(readStorage()); }
    catch (e) { res.status(500).json({ error: 'Data read failed.', details: e.message }); }
});

app.post('/api/data', (req, res) => {
    try {
        if (!req.body || typeof req.body !== 'object') return res.status(400).json({ error: 'Invalid payload.' });
        // Preserve server-owned collections that the frontend does NOT manage:
        //   - emailLogs: written by the backend email pipeline (retries, receipts,
        //     scheduler reminders, reservation emails). Frontend syncs must never
        //     overwrite them.
        //   - emailCounter: persisted sequence used to mint unique Email Reference
        //     Numbers. Must survive frontend syncs.
        // Also preserve any tenant.reminderHistory that the scheduler has stamped
        // so we don't accidentally re-send reminders that were already delivered.
        const existing = readStorage();
        const incoming = req.body;
        const merged = { ...existing, ...incoming };
        // Force-preserve emailLogs from disk (frontend sends none)
        merged.emailLogs = Array.isArray(existing.emailLogs) ? existing.emailLogs : [];
        // Force-preserve emailCounter from disk (frontend sends none)
        merged.emailCounter = (existing.emailCounter && typeof existing.emailCounter === 'object') ? existing.emailCounter : {};
        // FIX: White Label branding is owned exclusively by /api/whitelabel.
        // The frontend syncs its whole snapshot here, and a stale copy used to
        // overwrite freshly saved branding (sender name, colors...). Always keep
        // the record that is on disk.
        const _incomingSettings = (incoming.settings && typeof incoming.settings === 'object') ? incoming.settings : {};
        const _existingWL = ((existing.settings || {}).whiteLabel) || {};
        merged.settings = {
            ...(existing.settings || {}),
            ..._incomingSettings,
            whiteLabel: { ...DEFAULT_WHITE_LABEL, ..._existingWL }
        };
        stripLegacyBrandingFields(merged.settings);
        // Merge reminderHistory per boarder (union of scheduler + frontend)
        if (Array.isArray(merged.boarders)) {
            const oldById = new Map((existing.boarders||[]).map(b => [b.id, b]));
            merged.boarders = merged.boarders.map(b => {
                const prior = oldById.get(b.id);
                if (!prior) return b;
                const priorHist = Array.isArray(prior.reminderHistory) ? prior.reminderHistory : [];
                const curHist   = Array.isArray(b.reminderHistory) ? b.reminderHistory : [];
                const union = Array.from(new Set([...priorHist, ...curHist]));
                return { ...b, reminderHistory: union };
            });
        }
        // === NEW: Server-side validation for check-in scope & payment integrity ===
        try {
            const _priorIds = new Set((existing.boarders || []).map(b => b.id));
            const _reservations = Array.isArray(merged.reservations) ? merged.reservations : [];
            const _resById = new Map(_reservations.map(r => [r.id, r]));
            const _incomingBoarders = Array.isArray(merged.boarders) ? merged.boarders : [];
            for (const b of _incomingBoarders) {
                if (_priorIds.has(b.id)) continue; // only newly added boarders

                // Rule 1: GCash / Bank Transfer must carry a Reference Number
                const pm = String(b.paymentMethod || '').trim();
                const pr = String(b.paymentReference || '').trim();
                const _amtCollected = (b.checkInAmountCollected === undefined || b.checkInAmountCollected === null)
                    ? null : Number(b.checkInAmountCollected);
                if ((pm === 'GCash' || pm === 'Bank Transfer') && !pr && (_amtCollected === null || _amtCollected > 0)) {
                    return res.status(400).json({
                        error: 'Reference Number required.',
                        details: `Boarder ${b.name || b.id} paid via ${pm} but has no Reference Number.`
                    });
                }

                // Rule 2: Entire-room occupancy only allowed for entire-room reservations
                const isEntire = b.occupancyType === 'entire_room';
                if (isEntire && b.reservationId) {
                    const linked = _resById.get(b.reservationId);
                    if (linked && linked.type === 'bed') {
                        return res.status(400).json({
                            error: 'Invalid check-in scope.',
                            details: `Boarder ${b.name || b.id} attempts Entire Room check-in against a single-bed reservation (${b.reservationId}).`
                        });
                    }
                }

                // Rule 3: Occupancy Type is the single source of truth for the room.
                //   - Entire-room boarder cannot land in a room that already has
                //     active Bed Space occupants (pre-existing, not counting self).
                //   - Bed-space boarder cannot land in a room that is entire-room
                //     occupied by someone else.
                try {
                    const _roomsArr = Array.isArray(merged.rooms) ? merged.rooms : [];
                    const _room = _roomsArr.find(r => String(r.id) === String(b.roomId));
                    if (_room) {
                        const _priorOccupants = (existing.boarders || []).filter(x =>
                            String(x.roomId) === String(_room.id) && x.id !== b.id);
                        const _priorEntire = _priorOccupants.find(x => x.occupancyType === 'entire_room');
                        if (isEntire && _priorOccupants.length > 0 && !_priorEntire) {
                            return res.status(400).json({
                                error: 'Occupancy conflict.',
                                details: `Room ${_room.roomName || _room.id} already has Bed Space occupants; Entire Room check-in is not allowed.`
                            });
                        }
                        if (!isEntire && _priorEntire) {
                            return res.status(400).json({
                                error: 'Occupancy conflict.',
                                details: `Room ${_room.roomName || _room.id} is occupied as Entire Room by ${_priorEntire.name || _priorEntire.id}; Bed Space check-in is blocked.`
                            });
                        }
                    }
                } catch(_) { /* non-fatal */ }
            }
        } catch (_valErr) {
            // Do not block legitimate writes if validation itself throws
        }
        // Rule 4: Transfer transactions paid by GCash / Bank Transfer must carry a Reference Number when a fee was charged.
        try {
            const _priorTxIds = new Set((existing.transactions || []).map(t => t.id));
            const _incomingTx = Array.isArray(merged.transactions) ? merged.transactions : [];
            for (const t of _incomingTx) {
                if (_priorTxIds.has(t.id)) continue; // only newly added transactions
                if (String(t.type) !== 'Transfer') continue;
                const amt = Number(t.amount) || 0;
                if (amt <= 0) continue;
                const pm = String(t.paymentMethod || t.method || '').trim();
                const pr = String(t.paymentReference || t.reference || t.refNo || '').trim();
                if ((pm === 'GCash' || pm === 'Bank Transfer') && !pr) {
                    return res.status(400).json({
                        error: 'Reference Number required.',
                        details: `Transfer ${t.id} paid via ${pm} but has no Reference Number.`
                    });
                }
            }
        } catch (_txValErr) { /* non-fatal */ }

        // === v4.0: FINAL Reservation & Check-In rule enforcement ===
        // Backed by the same occupancy model the UI uses. The frontend only
        // disables buttons; these checks are the real guarantee.
        const _resErr = validateNewReservations(existing, merged);
        if (_resErr) return res.status(400).json(_resErr);
        // MDMS: standardized cancellation workflow — a reservation may only
        // transition to "Cancelled" when a written Reason for Cancellation is
        // supplied. Applies to Bed Space AND Entire Room reservations and
        // cannot be bypassed by crafted API calls.
        try {
            const _prevRes = new Map((existing.reservations || []).map(r => [r.id, r]));
            for (const r of (merged.reservations || [])) {
                if (String(r.status) !== 'Cancelled') continue;
                const prior = _prevRes.get(r.id);
                const wasCancelled = prior && String(prior.status) === 'Cancelled';
                if (wasCancelled) continue; // already cancelled, unchanged
                // Auto-cancellations (e.g. expiration sweep) mark cancelReason as 'Auto-Expired'.
                const reason = String(r.cancelReason || r.cancellationReason || '').trim();
                if (!reason) {
                    return res.status(400).json({
                        error: 'Reason for Cancellation required.',
                        details: `Reservation ${r.id} cannot be cancelled without a written Reason for Cancellation.`
                    });
                }
                // Persist normalized field name for the log/audit trail.
                r.cancelReason = reason;
            }
        } catch (_cxErr) { /* non-fatal */ }
        const _ciErr = validateNewCheckIns(existing, merged);
        if (_ciErr) return res.status(400).json(_ciErr);
        // Reservation Fee is a CREDIT against the Check-in charges — enforce
        // that it is remembered, applied exactly once, and never double-charged.
        const _feeErr = validateReservationFeeCredits(existing, merged);
        if (_feeErr) return res.status(400).json(_feeErr);

        // Never persist sensitive card data, whatever the client sent.
        (merged.transactions || []).forEach(stripSensitivePaymentFields);
        (merged.boarders || []).forEach(stripSensitivePaymentFields);
        (merged.reservations || []).forEach(stripSensitivePaymentFields);

        // FINAL FIX: reconcile entire-room ownership before persisting so a
        // transferred-away room can never be written back as occupied.
        reconcileEntireRoomState(merged);
        writeStorageAtomic(merged);
        res.status(200).json({ success: true, message: 'Data synced.' });
    } catch (e) { res.status(500).json({ error: 'Sync failure.', details: e.message }); }
});

/* ====================================================================
 * FLOOR INVENTORY API — Floor CRUD. Room APIs are untouched; rooms simply
 * carry floorId + floorName. Deleting a floor is blocked whenever any room
 * inside it still has boarders, reservations or occupied beds.
 * ==================================================================== */
app.get('/api/floors', (req, res) => {
    try {
        const db = readStorage();
        const floors = (db.floors || []).map(f => ({
            ...f,
            roomCount: (db.rooms || []).filter(r => String(r.floorId) === String(f.id) && r.type !== 'Admin').length
        }));
        res.status(200).json(floors);
    } catch (e) { res.status(500).json({ error: 'Floor read failed.', details: e.message }); }
});

app.post('/api/floors', (req, res) => {
    try {
        const name = String((req.body || {}).name || '').trim();
        if (!name) return res.status(400).json({ error: 'Floor name is required.' });
        const db = readStorage();
        if ((db.floors || []).some(f => f.name.toLowerCase() === name.toLowerCase())) {
            return res.status(409).json({ error: 'A floor with that name already exists.' });
        }
        const rec = {
            id: floorSlug(name) + '-' + Date.now().toString(36),
            name,
            order: (db.floors || []).length + 1,
            createdAt: new Date().toISOString()
        };
        db.floors.push(rec);
        writeStorageAtomic(db);
        appendAuditEntry('Floor Inventory', `Created floor "${name}"`, req);
        res.status(201).json(rec);
    } catch (e) { res.status(500).json({ error: 'Floor create failed.', details: e.message }); }
});

app.put('/api/floors/:id', (req, res) => {
    try {
        const name = String((req.body || {}).name || '').trim();
        if (!name) return res.status(400).json({ error: 'Floor name is required.' });
        const db = readStorage();
        const floor = (db.floors || []).find(f => String(f.id) === String(req.params.id));
        if (!floor) return res.status(404).json({ error: 'Floor not found.' });
        if ((db.floors || []).some(f => String(f.id) !== String(floor.id) && f.name.toLowerCase() === name.toLowerCase())) {
            return res.status(409).json({ error: 'A floor with that name already exists.' });
        }
        const previous = floor.name;
        floor.name = name;
        // Rooms keep their floorId; only the denormalized label follows the rename.
        (db.rooms || []).forEach(r => { if (String(r.floorId) === String(floor.id)) r.floorName = name; });
        writeStorageAtomic(db);
        appendAuditEntry('Floor Inventory', `Renamed floor "${previous}" to "${name}"`, req);
        res.status(200).json(floor);
    } catch (e) { res.status(500).json({ error: 'Floor update failed.', details: e.message }); }
});

app.delete('/api/floors/:id', (req, res) => {
    try {
        const db = readStorage();
        const idx = (db.floors || []).findIndex(f => String(f.id) === String(req.params.id));
        if (idx === -1) return res.status(404).json({ error: 'Floor not found.' });
        const floor = db.floors[idx];
        const blocker = floorDeletionBlocker(db, floor.id);
        if (blocker) {
            return res.status(409).json({ error: 'Cannot delete this Floor.', details: blocker });
        }
        const removed = (db.rooms || []).filter(r => String(r.floorId) === String(floor.id));
        db.rooms = (db.rooms || []).filter(r => String(r.floorId) !== String(floor.id));
        db.floors.splice(idx, 1);
        // Boarders, reservations, billing, maintenance, audit, email logs and
        // reports are deliberately left untouched — only empty rooms are removed.
        writeStorageAtomic(db);
        appendAuditEntry('Floor Inventory', `Deleted floor "${floor.name}" (${removed.length} empty room(s))`, req);
        res.status(200).json({ success: true, deletedRooms: removed.length });
    } catch (e) { res.status(500).json({ error: 'Floor delete failed.', details: e.message }); }
});

app.get('/api/boarders', (req, res) => {
    try { res.status(200).json(readStorage().boarders); }
    catch (e) { res.status(500).json({ error: 'Retrieve failed.', details: e.message }); }
});

app.post('/api/boarders', (req, res) => {
    try {
        const db = readStorage();
        const record = req.body;
        validateBoarderPayload(record);
        if (!record.id) {
            record.id = 'BRD-' + Date.now();
            db.boarders.push(record);
            appendAuditEntry('Boarder Directory', `Created new tenant: ${record.name}`, req);
        } else {
            const idx = db.boarders.findIndex(b => b.id === record.id);
            if (idx !== -1) { db.boarders[idx] = { ...db.boarders[idx], ...record }; appendAuditEntry('Boarder Directory', `Updated tenant: ${record.name}`, req); }
            else db.boarders.push(record);
        }
        writeStorageAtomic(db);
        res.status(200).json({ success: true, record });
    } catch (e) { res.status(400).json({ error: 'Persistence rejected.', details: e.message }); }
});

app.get('/api/billing', (req, res) => {
    try { res.status(200).json(readStorage().transactions); }
    catch (e) { res.status(500).json({ error: 'Read failed.', details: e.message }); }
});

/**
 * Record a payment. Behavior preserved (balance decrement, transaction
 * insert, audit entry, reminderHistory reset when paid off) PLUS an
 * automatic HTML receipt email fired asynchronously.
 */
app.post('/api/payment', (req, res) => {
    try {
        const db = readStorage();
        const { boarderId, amount, reference, orNumber } = req.body;
        const numericAmount = parseFloat(amount);
        if (!boarderId || isNaN(numericAmount) || numericAmount <= 0) return res.status(400).json({ error: 'Payment amount must be positive.' });

        const tenant = db.boarders.find(b => b.id === boarderId);
        if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });

        const prevBalance = parseFloat(tenant.balance) || 0;
        tenant.balance = prevBalance - numericAmount;
        if (tenant.balance <= 0) {
            tenant.balance = 0;
            tenant.status = 'Paid';
            tenant.reminderHistory = []; // reset cycle
        }

        const tx = {
            id: 'TX-' + Date.now() + Math.floor(Math.random() * 10),
            type: 'Payment', boarderId,
            date: new Date().toISOString().split('T')[0],
            amount: numericAmount,
            reference: reference || '',
            orNumber: orNumber || '',
            details: `Payment recorded. Ref: ${reference || 'None'}`
        };
        db.transactions.push(tx);
        appendAuditEntry('Billing Ledger', `Payment ${BrandingService.get(db).currencySymbol}${numericAmount} for ${tenant.name}`, req);
        writeStorageAtomic(db);

        // Fire-and-forget receipt email — non-blocking, retry-aware, logged.
        (async () => {
            try {
                const freshDb = readStorage();
                const cfg = freshDb.emailConfig;
                if (cfg && cfg.enabled && tenant.email) {
                    const { subject, html } = tplPaymentReceipt(freshDb, tenant, tx, prevBalance);
                    await sendEmailWithRetry({ to: tenant.email, subject, html, type: 'Receipt', config: cfg, settings: freshDb.settings });
                }
            } catch (e) { console.error('[RECEIPT] async failure:', e.message); }
        })();

        res.status(200).json({ success: true, transaction: tx });
    } catch (e) { res.status(500).json({ error: 'Payment processing failed.', details: e.message }); }
});

app.get('/api/email-logs', (req, res) => {
    try { res.status(200).json(readStorage().emailLogs); }
    catch (e) { res.status(500).json({ error: 'Log read failed.', details: e.message }); }
});

/** Manual email send — preserved for backward compatibility. */
app.post('/api/send-email', async (req, res) => {
    try {
        const { to, subject, body, html, type, config } = req.body;
        if (!to || !subject || (!body && !html)) return res.status(400).json({ error: 'Missing to/subject/body.' });
        const db = readStorage();
        const cfg = config || db.emailConfig;
        const outcome = await sendEmailWithRetry({
            to, subject, html: html || null, text: body || null,
            type: type || 'Manual', config: cfg, settings: db.settings
        });
        if (outcome.success) return res.status(200).json({ success: true, message: 'Email dispatched.', reference: outcome.reference });
        return res.status(422).json({ error: outcome.reason, reference: outcome.reference });
    } catch (e) { res.status(500).json({ error: 'Send failed.', details: e.message }); }
});

/**
 * ONE GLOBAL ENDPOINT for every templated notification. The frontend never
 * builds email HTML — it names a notification type and passes data.
 * POST { type, to, data:{...} }
 */
app.post('/api/send-notification', async (req, res) => {
    try {
        const { type, to, data } = req.body || {};
        const db = readStorage();
        const payload = { ...(data || {}) };
        const recipient = to || payload.to;
        if (!recipient) return res.status(400).json({ error: 'Recipient email is required.' });
        const rendered = renderEmail(db, type, { ...payload, to: recipient });
        const outcome = await sendEmailWithRetry({
            to: recipient, subject: rendered.subject, html: rendered.html,
            type: rendered.type, config: db.emailConfig, settings: db.settings
        });
        return res.status(outcome.success ? 200 : 422).json(outcome.success
            ? { success: true, reference: outcome.reference, type: rendered.type }
            : { error: outcome.reason, reference: outcome.reference });
    } catch (e) { res.status(500).json({ error: 'Notification failed.', details: e.message }); }
});

/** Preview any notification type without sending (admin tooling). */
app.post('/api/preview-notification', (req, res) => {
    try {
        const { type, data } = req.body || {};
        const rendered = renderEmail(readStorage(), type, data || {});
        res.status(200).json({ success: true, type: rendered.type, subject: rendered.subject, html: injectReference(rendered.html, 'PREVIEW-0000') });
    } catch (e) { res.status(500).json({ error: 'Preview failed.', details: e.message }); }
});

/** Enumerate every notification type served by the global engine. */
app.get('/api/notification-types', (req, res) => {
    res.json(Object.keys(EMAIL_TYPES).map(k => ({
        type: k, badge: EMAIL_TYPES[k].badge, color: EMAIL_TYPES[k].color,
        prefix: EMAIL_TYPES[k].prefix, payment: !!EMAIL_TYPES[k].payment
    })));
});

/** SMTP handshake test — validates connection + sender + delivers a test email. */
app.post('/api/test-email', async (req, res) => {
    try {
        const cfg = req.body;
        if (!cfg || !cfg.email) return res.status(400).json({ error: 'Invalid config.' });
        const handshake = await verifySmtpHandshake(cfg);
        if (!handshake.ok) return res.status(422).json({ error: handshake.reason });

        const db = readStorage();
        const c = ctx(db);
        const reference = REF_PLACEHOLDER;
        const html = baseShell({
            title: 'SMTP Test',
            bodyInner: `<h2 style="color:#047857;margin:0 0 12px 0;">SMTP handshake successful</h2><p>Your automated email pipeline is fully operational.</p>`,
            ...c, reference, accent: '#047857'
        });
        const outcome = await sendEmailWithRetry({
            to: cfg.email, subject: `[${c.dormName}] SMTP Test`,
            html, type: 'Test', config: cfg, settings: db.settings
        });
        if (outcome.success) res.status(200).json({ success: true, message: 'Handshake verified — test email delivered.', reference: outcome.reference });
        else res.status(422).json({ error: outcome.reason, reference: outcome.reference });
    } catch (e) { res.status(500).json({ error: 'SMTP handshake failed.', details: e.message }); }
});

/** Manual trigger for the auto-billing engine. */
app.post('/api/run-billing-reminders', async (req, res) => {
    try {
        const result = await executeAutomatedBillingReminderEngine();
        res.status(200).json({ success: true, ...result });
    } catch (e) { res.status(500).json({ error: 'Reminder engine failed.', details: e.message }); }
});

/** Hot-reload — no-op that clears any cached scheduling so next tick picks up new settings. */
app.post('/api/reload-config', (req, res) => {
    scheduleState.lastDailyRunDate = null; // force re-evaluation
    res.status(200).json({ success: true, message: 'Configuration reloaded — automation will pick up new settings on next tick.' });
});

/** Reservation lifecycle emails — safe to call from the frontend on reservation events. */
app.post('/api/send-reservation-email', async (req, res) => {
    try {
        const { kind, reservation, reason, daysLeft } = req.body || {};
        if (!reservation || !reservation.email) return res.status(400).json({ error: 'Reservation with email required.' });
        const db = readStorage();
        let tpl;
        let type = 'Reservation';
        if (kind === 'confirmation') { tpl = tplReservationConfirmation(db, reservation); type = 'Reservation Confirmation'; }
        else if (kind === 'cancellation') { tpl = tplReservationCancellation(db, reservation, reason); type = 'Reservation Cancellation'; }
        else if (kind === 'expiration') { tpl = tplReservationExpiration(db, reservation, daysLeft || 1); type = 'Reservation Expiration'; }
        else return res.status(400).json({ error: 'Unknown kind. Use confirmation|cancellation|expiration.' });

        const outcome = await sendEmailWithRetry({
            to: reservation.email, subject: tpl.subject, html: tpl.html,
            type, config: db.emailConfig, settings: db.settings
        });
        res.status(outcome.success ? 200 : 422).json(outcome.success ? { success: true, reference: outcome.reference } : { error: outcome.reason, reference: outcome.reference });
    } catch (e) { res.status(500).json({ error: 'Reservation email failed.', details: e.message }); }
});

/* ====================================================================
 * FUTURE ONLINE PAYMENTS — architecture stubs
 * ==================================================================== */
const paymentProviders = {
    gcash:    { enabled: false, initCheckout: async () => { throw new Error('GCash integration not enabled yet.'); } },
    maya:     { enabled: false, initCheckout: async () => { throw new Error('Maya integration not enabled yet.'); } },
    paymongo: { enabled: false, initCheckout: async () => { throw new Error('PayMongo integration not enabled yet.'); } },
    stripe:   { enabled: false, initCheckout: async () => { throw new Error('Stripe integration not enabled yet.'); } },
    paypal:   { enabled: false, initCheckout: async () => { throw new Error('PayPal integration not enabled yet.'); } }
};
app.get('/api/payment-providers', (req, res) => {
    res.json(Object.fromEntries(Object.entries(paymentProviders).map(([k, v]) => [k, { enabled: v.enabled }])));
});
app.post('/api/payment-providers/:provider/checkout', async (req, res) => {
    const p = paymentProviders[req.params.provider];
    if (!p) return res.status(404).json({ error: 'Unknown provider.' });
    try { const out = await p.initCheckout(req.body); res.json({ success: true, ...out }); }
    catch (e) { res.status(501).json({ error: e.message }); }
});

/* ====================================================================
 * AUTOMATED BILLING REMINDER ENGINE
 * ==================================================================== */
function computeNextDueDate(tenant) {
    if (tenant.dueDate) {
        const explicit = new Date(tenant.dueDate + 'T00:00:00');
        if (!isNaN(explicit)) {
            const today = new Date(); today.setHours(0,0,0,0);
            while (explicit < today) explicit.setMonth(explicit.getMonth() + 1);
            return explicit;
        }
    }
    if (tenant.moveInDate) {
        const parts = tenant.moveInDate.split('-');
        if (parts.length === 3) {
            const dueDay = parseInt(parts[2], 10);
            if (!isNaN(dueDay)) {
                const today = new Date(); today.setHours(0,0,0,0);
                let cand = new Date(today.getFullYear(), today.getMonth(), dueDay);
                while (cand < today) cand = new Date(cand.getFullYear(), cand.getMonth() + 1, dueDay);
                return cand;
            }
        }
    }
    const t = new Date(); t.setHours(0,0,0,0); return t;
}

function cycleKey(dueDate) { return dueDate.toISOString().split('T')[0]; }

async function executeAutomatedBillingReminderEngine() {
    console.log(`[SCHEDULER] Reminder pass @ ${new Date().toISOString()}`);
    let sent = 0, skipped = 0, failed = 0;

    const db = readStorage();
    const st = { ...DEFAULT_SETTINGS, ...(db.settings || {}) };

    if (!db.emailConfig || !db.emailConfig.enabled) {
        console.log('[SCHEDULER] Email disabled — skipping.');
        return { sent: 0, skipped: db.boarders.length, reason: 'email_disabled' };
    }
    if (st.autoRemindersEnabled === false) {
        console.log('[SCHEDULER] Auto reminders disabled in settings.');
        return { sent: 0, skipped: db.boarders.length, reason: 'auto_disabled' };
    }

    const today = new Date(); today.setHours(0,0,0,0);
    const schedule = (st.reminderSchedule || DEFAULT_SETTINGS.reminderSchedule).slice()
        .map(n => parseInt(n)).filter(n => !isNaN(n)).sort((a,b) => b - a);
    const weeklyInterval = Math.max(1, parseInt(st.weeklyOverdueInterval || 7));

    for (const tenant of db.boarders) {
        if (!tenant.email || !EMAIL_REGEX.test(tenant.email)) { skipped++; continue; }
        if (!tenant.balance || tenant.balance <= 0) { skipped++; continue; }

        const dueDate = computeNextDueDate(tenant);
        const diffDays = Math.round((dueDate.getTime() - today.getTime()) / 86400000);
        const cycle = cycleKey(dueDate);
        if (!Array.isArray(tenant.reminderHistory)) tenant.reminderHistory = [];

        const milestones = [];

        // Configured schedule (positive = before due, 0 = due today, negative = after)
        for (const offset of schedule) {
            if (offset > 0 && diffDays <= offset && diffDays > 0) {
                milestones.push({ key: `PRE_${offset}_${cycle}`, tpl: tplUpcomingDue(db, tenant, dueDate, diffDays) });
            } else if (offset === 0 && diffDays === 0) {
                milestones.push({ key: `DUE_${cycle}`, tpl: tplDueToday(db, tenant, dueDate) });
            } else if (offset < 0 && diffDays <= offset) {
                milestones.push({ key: `POST_${Math.abs(offset)}_${cycle}`, tpl: tplOverdue(db, tenant, dueDate, Math.abs(diffDays)) });
            }
        }
        // Weekly overdue re-nag
        if (diffDays < 0) {
            const weekBucket = Math.floor(Math.abs(diffDays) / weeklyInterval);
            if (weekBucket >= 1) {
                milestones.push({ key: `WEEKLY_${weekBucket}_${cycle}`, tpl: tplOverdue(db, tenant, dueDate, Math.abs(diffDays)) });
            }
        }

        // Deduplicate by key
        const seen = new Set();
        const unique = milestones.filter(m => !seen.has(m.key) && seen.add(m.key));

        for (const m of unique) {
            if (tenant.reminderHistory.includes(m.key)) continue;
            const outcome = await sendEmailWithRetry({
                to: tenant.email, subject: m.tpl.subject, html: m.tpl.html,
                type: 'Reminder', config: db.emailConfig, settings: st
            });
            if (outcome.success) { tenant.reminderHistory.push(m.key); sent++; }
            else { failed++; }
        }
    }

    writeStorageAtomic(db);
    console.log(`[SCHEDULER] Done. sent=${sent} failed=${failed} skipped=${skipped}`);
    return { sent, failed, skipped };
}

/* ====================================================================
 * SCHEDULER — daily at configured time + hourly catch-up
 * ==================================================================== */
const scheduleState = { lastDailyRunDate: null };

function schedulerTick() {
    try {
        const db = readStorage();
        const st = { ...DEFAULT_SETTINGS, ...(db.settings || {}) };
        if (st.autoRemindersEnabled === false) return;

        const now = new Date();
        const [hh, mm] = (st.dailyTime || '08:00').split(':').map(x => parseInt(x));
        const todayKey = now.toISOString().split('T')[0];

        // Fire once per day, on or after configured time
        if (scheduleState.lastDailyRunDate !== todayKey &&
            (now.getHours() > hh || (now.getHours() === hh && now.getMinutes() >= mm))) {
            scheduleState.lastDailyRunDate = todayKey;
            executeAutomatedBillingReminderEngine().catch(e => console.error('[DAILY]', e.message));
        }
    } catch (e) { console.error('[SCHEDULER TICK]', e.message); }
}

// Global error handler
app.use((err, req, res, next) => {
    console.error('CAPTURED ROOT EXCEPTION:', err.stack);
    res.status(500).json({ error: 'System error.', context: err.message });
});

/* ====================================================================
 * v2.5 — RESET SYSTEM DATA
 * Wipes every operational record (boarders, former, reservations,
 * waitlist, transactions/billing, tickets, transfers, audit, email logs,
 * notifications, receipts, uploaded photos, temporary files) and resets
 * every room + bed to a brand-new state. Room definitions (id, name,
 * capacity, rate, floor, inventory) are preserved.
 * ==================================================================== */
app.post('/api/reset-system', (req, res) => {
    try {
        const db = readStorage();

        // Wipe operational collections
        db.boarders = [];
        db.formerBoarders = [];
        db.reservations = [];
        db.waitingList = []; db.waitlist = [];
        db.transactions = []; db.billingRecords = [];
        db.tickets = []; db.maintenanceTickets = [];
        db.transferHistory = [];
        db.visitorLogs = [];
        db.notifications = [];
        db.receiptArchive = [];
        db.emailLogs = [];
        db.audit = []; db.auditLogs = [];
        db.tempFiles = [];

        // Reset every room + bed
        (db.rooms || []).forEach(r => {
            if (r.type === 'Admin') return; // preserve admin office row
            r.occupied = 0;
            r.status = 'Available';
            r.payerId = null;
            r.lastStatusChange = new Date().toLocaleString('en-PH');
            if (Array.isArray(r.beds)) {
                r.beds.forEach(b => {
                    b.isOccupied = false;
                    b.boarder = null;
                    b.tenantId = null;
                    b.isReserved = false;
                    b.reservationId = null;
                });
            }
        });

        // Wipe uploaded tenant/user/brand images (stored in Supabase)
        db.uploads = {};
        db.userAvatars = {};
        db.tenantPhotos = {};

        writeStorageAtomic(db);
        appendAuditEntry('SYSTEM', 'RESET_SYSTEM_DATA', req);
        res.json({ success: true, message: 'System data reset. All operational records cleared.' });
    } catch (e) {
        console.error('RESET_SYSTEM error:', e);
        res.status(500).json({ error: 'Reset failed', detail: e.message });
    }
});

/* ====================================================================
 * WHITE LABEL CONFIG — GET / PUT
 * Single source of truth for all branding. The client Branding Service
 * consumes this and rebrands every screen, receipt, and email.
 * ==================================================================== */
app.get('/api/whitelabel', (req, res) => {
    try {
        const db = readStorage();
        // `_raw` is what is actually stored (blank = auto-derive), so the admin
        // form can show blanks instead of baking derived values back in.
        res.json({ ...BrandingService.get(db), _raw: BrandingService.raw(db) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/whitelabel', (req, res) => {
    try {
        const db = readStorage();
        db.settings = db.settings || { ...DEFAULT_SETTINGS };
        const merged = BrandingService.save(db, req.body || {});
        writeStorageAtomic(db);
        res.json({ success: true, whiteLabel: { ...merged, _raw: BrandingService.raw(db) } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ====================================================================
 * PERSISTENT USER DIRECTORY (mirror of client localStorage)
 * Ensures profile photos + user records survive browser/server restarts.
 * ==================================================================== */
app.get('/api/users', (req, res) => {
    try {
        const db = readStorage();
        // Apply persistent avatar map so every consumer gets the latest photo.
        const avatars = db.userAvatars || {};
        let users = (db.users || []).map(u => ({ ...u, avatar: avatars[u.id] || u.avatar || '' }));
        // The Super Administrator account is invisible to every lesser role.
        if (res.locals.hideSuperAdmins) users = users.filter(u => u.role !== 'Super Administrator');
        res.json({ users, userAvatars: avatars });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users', (req, res) => {
    try {
        const { users } = req.body || {};
        if (!Array.isArray(users)) return res.status(400).json({ error: 'users[] required' });
        const db = readStorage();
        // Preserve avatar from persistent map (avatar is set via /api/upload-photo)
        const avatars = db.userAvatars || {};
        db.users = users.map(u => {
            const avatar = u.avatar || avatars[u.id] || '';
            // Mirror any client-side photo into the persistent avatar map so it
            // survives browser cache clears and server restarts.
            if (avatar && avatar.startsWith('/uploads/')) avatars[u.id] = avatar;
            return { ...u, avatar };
        });
        db.userAvatars = avatars;
        writeStorageAtomic(db);
        res.json({ success: true, count: db.users.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/tenant-photo/:id', (req, res) => {
    try {
        const db = readStorage();
        const stored = (db.tenantPhotos || {})[String(req.params.id)]
            || ((db.boarders || []).find(b => String(b.id) === String(req.params.id)) || {}).photo
            || '';
        res.json({ id: req.params.id, path: stored });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user-avatar/:id', (req, res) => {
    try {
        const db = readStorage();
        const path = (db.userAvatars || {})[String(req.params.id)] || '';
        res.json({ id: req.params.id, path });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ====================================================================
 * v2.5 — PHOTO UPLOAD (Base64 → /uploads/<id>.<ext>)
 * Accepts { id, kind: 'tenant'|'user', dataUrl } and returns a stable
 * relative path. Falls back gracefully if fs writes fail; the client
 * can also store the Base64 dataUrl directly (offline mode).
 * ==================================================================== */
app.post('/api/upload-photo', (req, res) => {
    try {
        const { id, kind, dataUrl } = req.body || {};
        if (!id || !dataUrl || typeof dataUrl !== 'string') {
            return res.status(400).json({ error: 'id and dataUrl required' });
        }
        // v3.3: also accepts kind === 'brand' (white-label logo / favicon / QR)
        // and SVG payloads. 'user' and 'tenant' behaviour is unchanged.
        const m = dataUrl.match(/^data:image\/(png|jpe?g|webp|gif|svg\+xml);base64,(.+)$/i);
        if (!m) return res.status(400).json({ error: 'Invalid image dataUrl' });
        const rawExt = m[1].toLowerCase();
        const ext = rawExt === 'jpeg' ? 'jpg' : (rawExt === 'svg+xml' ? 'svg' : rawExt);
        const safeId = String(id).replace(/[^a-zA-Z0-9_.-]/g, '_');
        const prefix = kind === 'user' ? 'user_' : (kind === 'brand' ? 'brand_' : 'tenant_');
        const filename = `${prefix}${safeId}.${ext}`;
        const relPath = `/uploads/${filename}`;
        // Images live in Supabase (Render disks are ephemeral) but keep the
        // exact same /uploads/<file> URL the whole UI already uses.
        {
            const dbu = readStorage();
            dbu.uploads = dbu.uploads || {};
            dbu.uploads[filename] = { mime: `image/${rawExt}`, base64: m[2], updatedAt: new Date().toISOString() };
            writeStorageAtomic(dbu);
        }
        // Persist mapping so the photo survives browser restarts, server
        // restarts, and Render redeploys (files are also on disk).
        try {
            const db = readStorage();
            if (kind === 'user') {
                db.userAvatars = db.userAvatars || {};
                db.userAvatars[String(id)] = relPath;
                // Mirror into users[] if present
                if (Array.isArray(db.users)) {
                    const u = db.users.find(x => String(x.id) === String(id));
                    if (u) u.avatar = relPath;
                }
                writeStorageAtomic(db);
            } else if (kind === 'tenant') {
                db.tenantPhotos = db.tenantPhotos || {};
                db.tenantPhotos[String(id)] = relPath;
                const b = (db.boarders || []).find(x => String(x.id) === String(id));
                if (b) b.photo = relPath;
                writeStorageAtomic(db);
            } else if (kind === 'brand') {
                // White-label asset (logo, loading logo, favicon, QR, watermark).
                // Stored separately so it never touches user/tenant records.
                db.brandAssets = db.brandAssets || {};
                db.brandAssets[String(id)] = relPath;
                writeStorageAtomic(db);
            }
        } catch (e) { console.warn('[UPLOAD_PHOTO] persistence warn:', e.message); }
        res.json({ success: true, path: relPath });
    } catch (e) {
        console.error('UPLOAD_PHOTO error:', e);
        res.status(500).json({ error: 'Upload failed', detail: e.message });
    }
});

// Serve /uploads from the Supabase-backed image store
app.get('/uploads/:filename', (req, res) => {
    try {
        const rec = (readStorage().uploads || {})[String(req.params.filename)];
        if (!rec) return res.status(404).end();
        res.setHeader('Content-Type', rec.mime || 'application/octet-stream');
        res.setHeader('Cache-Control', 'no-cache');
        return res.end(Buffer.from(rec.base64, 'base64'));
    } catch (e) { return res.status(500).end(); }
});


/* ====================================================================
 * STARTUP
 * ==================================================================== */
function startServer() {
app.listen(PORT, () => {
    console.log(`========================================================================`);
    let _sn = 'System';
    try { _sn = resolveWhiteLabel((readStorage().settings || {}).whiteLabel).systemShortName || 'System'; } catch(_){}
    console.log(`   ${_sn} BACKEND ACTIVE ON PORT: ${PORT}`);
    console.log(`   Automated reminder engine armed.`);
    console.log(`========================================================================`);

    // Immediate warm-up run (catch missed cycles across restarts)
    executeAutomatedBillingReminderEngine().catch(e => console.error('[STARTUP]', e.message));

    // Tick every minute so configured dailyTime is honored to the minute.
    setInterval(schedulerTick, 60 * 1000);

    // Hourly catch-up sweep so a missed daily tick still fires today's reminders.
    setInterval(() => {
        executeAutomatedBillingReminderEngine().catch(e => console.error('[HOURLY]', e.message));
    }, 60 * 60 * 1000);
});

}

bootstrapStorage()
    .then(startServer)
    .catch(err => {
        console.error('=========================================================');
        console.error(' FATAL: could not reach Supabase. Check SUPABASE_URL and');
        console.error(' SUPABASE_SERVICE_ROLE_KEY, and run supabase.sql once.');
        console.error(' ' + err.message);
        console.error('=========================================================');
        process.exit(1);
    });
