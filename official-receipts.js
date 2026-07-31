/**
 * OFFICIAL RECEIPT ENGINE — single source of truth for every financial
 * transaction processed by the Dormitory Management System.
 *
 * Responsibilities (all automatic, no manual encoding anywhere):
 *   1. Unique, never-reused Official Receipt (OR) numbering.
 *   2. Official Receipt record generation with full White-Label branding.
 *   3. Permanent persistence in the Receipt Archive (db.officialReceipts).
 *   4. Automatic logging into the correct financial report bucket
 *      (Reservation & Deposit / Billing / Deposit / Transfer / Other).
 *   5. Printable HTML + automatic emailing of the receipt to the customer.
 *   6. Idempotency: one completed transaction => exactly one OR, unless the
 *      OR is explicitly voided and reissued.
 *
 * This module never talks to storage directly; the host (server.js) passes the
 * db object in and persists it. Branding, email delivery and audit logging are
 * injected so there is exactly ONE branding service and ONE email pipeline.
 */

let deps = {
    BrandingService: null,
    sendEmailWithRetry: null,
    appendAuditEntry: null
};

function init(injected) { deps = Object.assign(deps, injected || {}); }

/* --------------------------------------------------------------- helpers */

function esc(v) {
    return String(v == null ? '' : v)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function ensure(db) {
    db.officialReceipts = Array.isArray(db.officialReceipts) ? db.officialReceipts : [];
    db.financialReports = Array.isArray(db.financialReports) ? db.financialReports : [];
    db.counters = db.counters && typeof db.counters === 'object' ? db.counters : {};
    if (typeof db.counters.orSequence !== 'number') {
        // Recover the sequence from existing records so numbers are never reused
        // even if the counter is lost (restore from backup / migrated database).
        let max = 0;
        db.officialReceipts.forEach(r => {
            const m = String(r.orNumber || '').match(/(\d+)\s*$/);
            if (m) max = Math.max(max, parseInt(m[1], 10));
        });
        db.counters.orSequence = max;
    }
    return db;
}

/** Report bucket for each transaction category. */
const REPORT_BUCKET = {
    'Reservation Fee': 'Reservation & Deposit Report',
    'Security Deposit': 'Deposit Report',
    'Check-in Payment': 'Billing & Payment Report',
    'Monthly Rental': 'Billing & Payment Report',
    'Utilities': 'Billing & Payment Report',

    'Transfer Fee': 'Transfer Report',
    'Penalty': 'Other Charges Report',
    'Miscellaneous Fee': 'Other Charges Report',
    'Additional Charge': 'Other Charges Report',
    'Manual Payment': 'Billing & Payment Report',
    'Walk-in Payment': 'Billing & Payment Report',
    'Office Payment': 'Billing & Payment Report',
    'Other': 'Other Charges Report'
};

function reportBucket(category) { return REPORT_BUCKET[category] || REPORT_BUCKET.Other; }

/** Unique, monotonic, never-reused Official Receipt number. */
function nextOrNumber(db) {
    ensure(db);
    const used = new Set(db.officialReceipts.map(r => String(r.orNumber)));
    const year = new Date().getFullYear();
    let n;
    do {
        db.counters.orSequence = Number(db.counters.orSequence || 0) + 1;
        n = 'OR-' + year + '-' + String(db.counters.orSequence).padStart(6, '0');
    } while (used.has(n));
    return n;
}

/**
 * Stable key identifying the underlying completed transaction. Two calls with
 * the same key can never produce two live Official Receipts.
 */
function transactionKey(p) {
    return [p.category || 'Other', p.reservationId || '', p.boarderId || '',
            p.transactionId || '', p.receiptId || ''].join('|');
}

function findLiveReceipt(db, key) {
    return ensure(db).officialReceipts.find(r => r.transactionKey === key && r.status !== 'Void') || null;
}

/* ------------------------------------------------------- record building */

/**
 * Generate (or return the existing) Official Receipt for a completed payment.
 * Automatically archives it and logs it into the matching financial report.
 *
 * payload: {
 *   category, amount, currency?, paymentMethod?, paymentReference?,
 *   reservationId?, boarderId?, transactionId?, receiptId?,
 *   payerName, payerEmail, payerContact?,
 *   roomNumber?, bedNumber?, reservationType?,
 *   ocrStatus?, datePaid?, approvedBy?, approvedAt?, notes?
 * }
 */
function issueOfficialReceipt(db, payload) {
    ensure(db);
    const key = transactionKey(payload);
    const existing = findLiveReceipt(db, key);
    if (existing) return { receipt: existing, created: false };

    const brand = deps.BrandingService.get(db);
    const now = new Date();
    const amount = Number(payload.amount || 0);

    const receipt = {
        id: 'OFR-' + now.getTime() + Math.floor(Math.random() * 100),
        orNumber: nextOrNumber(db),
        transactionKey: key,
        status: 'Issued',                       // Issued | Void
        issuedAt: now.toISOString(),
        dateTime: now.toISOString(),

        category: payload.category || 'Other',
        reportBucket: reportBucket(payload.category),

        /* Traceability links */
        reservationId: payload.reservationId || null,
        boarderId: payload.boarderId || null,
        transactionId: payload.transactionId || null,
        receiptId: payload.receiptId || null,    // uploaded GCash receipt (OCR)

        /* Customer */
        tenantName: payload.payerName || '—',
        tenantEmail: payload.payerEmail || '',
        tenantContact: payload.payerContact || '',

        /* Accommodation */
        roomNumber: payload.roomNumber || '—',
        bedNumber: payload.bedNumber || 'ENTIRE ROOM',
        reservationType: payload.reservationType || '',

        /* Money */
        amount: amount,
        currency: brand.currency || 'PHP',
        currencySymbol: brand.currencySymbol || '',
        paymentMethod: payload.paymentMethod || 'Cash',
        paymentReference: payload.paymentReference || '',
        gcashReference: (String(payload.paymentMethod || '').toUpperCase() === 'GCASH')
            ? (payload.paymentReference || '') : '',
        ocrStatus: payload.ocrStatus || 'Not Applicable',
        paymentStatus: 'PAID',
        datePaid: payload.datePaid || now.toISOString(),

        /* Approval */
        approvedBy: payload.approvedBy || 'System',
        approvedAt: payload.approvedAt || now.toISOString(),
        notes: payload.notes || '',

        /* Branding snapshot (receipts must stay printable exactly as issued) */
        branding: {
            companyName: brand.companyName || brand.dormName,
            dormName: brand.dormName,
            logoUrl: brand.logoUrl || '',
            header: brand.receiptHeader || '',
            footer: brand.receiptFooter || '',
            address: brand.address || '',
            contactInfo: brand.contactInfo || '',
            email: brand.email || '',
            website: brand.website || '',
            signature: brand.signatureUrl || brand.signature || '',
            qrCode: brand.qrCode || '',
            tin: brand.tin || '',
            businessPermit: brand.businessPermit || '',
            primaryColor: brand.primaryColor || '#1d4ed8'
        }
    };

    db.officialReceipts.push(receipt);

    /* Permanent financial report entry (no manual encoding, ever). */
    db.financialReports.push({
        id: 'FRP-' + now.getTime() + Math.floor(Math.random() * 100),
        report: receipt.reportBucket,
        category: receipt.category,
        orNumber: receipt.orNumber,
        officialReceiptId: receipt.id,
        reservationId: receipt.reservationId,
        boarderId: receipt.boarderId,
        transactionId: receipt.transactionId,
        tenantName: receipt.tenantName,
        tenantEmail: receipt.tenantEmail,
        roomNumber: receipt.roomNumber,
        bedNumber: receipt.bedNumber,
        amount: receipt.amount,
        paymentMethod: receipt.paymentMethod,
        paymentReference: receipt.paymentReference,
        ocrStatus: receipt.ocrStatus,
        datePaid: receipt.datePaid,
        dateApproved: receipt.approvedAt,
        approvedBy: receipt.approvedBy,
        status: 'PAID',
        // Income & Payment Report SSOT: an issued Official Receipt is always
        // collected income until the OR itself is voided.
        isIncome: true,
        createdAt: now.toISOString()
    });

    /* Mirror into the Receipt Archive view so archived uploads and issued ORs
     * stay side by side (the archive keeps its original shape). */
    if (Array.isArray(db.receiptArchive) && receipt.receiptId) {
        const src = db.receiptArchive.find(r => String(r.id) === String(receipt.receiptId));
        if (src) { src.orNumber = receipt.orNumber; src.officialReceiptId = receipt.id; }
    }

    if (deps.appendAuditEntry) {
        deps.appendAuditEntry('Official Receipt',
            'Official Receipt ' + receipt.orNumber + ' issued for ' + receipt.category +
            ' (' + receipt.currencySymbol + receipt.amount + ') — ' + receipt.tenantName);
    }

    return { receipt, created: true };
}

/** Void an Official Receipt so a corrected one may be reissued. */
function voidOfficialReceipt(db, orId, reason, who) {
    ensure(db);
    const r = db.officialReceipts.find(x => String(x.id) === String(orId) || String(x.orNumber) === String(orId));
    if (!r) return null;
    if (r.status === 'Void') return r;
    r.status = 'Void';
    r.voidReason = reason || '';
    r.voidedBy = who || 'Administrator';
    r.voidedAt = new Date().toISOString();
    db.financialReports.forEach(f => {
        if (f.officialReceiptId === r.id) { f.status = 'VOID'; f.isIncome = false; }
    });
    /* A voided OR must disappear from every financial module at once. */
    ['transactions', 'paymentHistory', 'ledger', 'reservationPaymentHistory', 'checkinPaymentHistory']
        .forEach(k => {
            if (!Array.isArray(db[k])) return;
            db[k].forEach(row => {
                if (row && String(row.officialReceiptId) === String(r.id)) {
                    row.status = 'Void'; row.void = true; row.isIncome = false;
                }
            });
        });
    /* Recompute the reservation credit: the void removes the paid amount. */
    if (r.reservationId && Array.isArray(db.reservations)) {
        const res = db.reservations.find(x => String(x.id) === String(r.reservationId));
        if (res) {
            const live = db.officialReceipts.filter(o => o.status !== 'Void' &&
                String(o.reservationId || '') === String(r.reservationId));
            res.reservationCredit = live.reduce((sum, o) => sum + (Number(o.amount) || 0), 0);
            res.reservationCreditOrNumbers = live.map(o => o.orNumber);
        }
    }
    if (deps.appendAuditEntry) {
        deps.appendAuditEntry('Official Receipt', 'Official Receipt ' + r.orNumber + ' voided by ' + r.voidedBy);
    }
    return r;
}

/* ------------------------------------------------------------ rendering */

function money(r, n) {
    return (r.currencySymbol || '') + Number(n || 0)
        .toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function row(label, value) {
    return '<tr>' +
        '<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:12px;width:45%;">' + esc(label) + '</td>' +
        '<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;color:#0f172a;font-size:12px;font-weight:700;">' + esc(value) + '</td>' +
        '</tr>';
}

/** Printable / emailable Official Receipt (inline styles only, email safe). */
function renderOfficialReceiptHtml(r) {
    const b = r.branding || {};
    const dt = new Date(r.dateTime);
    const rows =
        row('Official Receipt No.', r.orNumber) +
        row('Date & Time', dt.toLocaleString()) +
        (r.reservationId ? row('Reservation Reference', r.reservationId) : '') +
        row('Tenant Name', r.tenantName) +
        row('Email Address', r.tenantEmail || '—') +
        row('Contact Number', r.tenantContact || '—') +
        row('Room Number', r.roomNumber) +
        row(String(r.bedNumber).toUpperCase() === 'ENTIRE ROOM' ? 'Accommodation' : 'Bed Number', r.bedNumber) +
        (r.reservationType ? row('Reservation Type', r.reservationType) : '') +
        row('Transaction Type', r.category) +
        row('Amount Paid', money(r, r.amount)) +
        row('Currency', r.currency) +
        row('Payment Method', r.paymentMethod) +
        (r.gcashReference ? row('GCash Reference No.', r.gcashReference)
                          : (r.paymentReference ? row('Payment Reference', r.paymentReference) : '')) +
        row('OCR Verification Status', r.ocrStatus) +
        row('Payment Status', r.paymentStatus) +
        row('Approved By', r.approvedBy) +
        row('Approval Date & Time', new Date(r.approvedAt).toLocaleString()) +
        (r.status === 'Void' ? row('Receipt Status', 'VOID — ' + (r.voidReason || '')) : row('Receipt Status', 'VALID'));

    return '' +
    '<div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;font-family:Segoe UI,Helvetica,Arial,sans-serif;">' +
      '<div style="background:' + esc(b.primaryColor || '#1d4ed8') + ';padding:22px 24px;color:#ffffff;">' +
        (b.logoUrl ? '<img src="' + esc(b.logoUrl) + '" alt="' + esc(b.companyName) + '" style="max-height:52px;display:block;margin-bottom:10px;">' : '') +
        '<div style="font-size:19px;font-weight:800;">' + esc(b.companyName || b.dormName || 'Dormitory') + '</div>' +
        (b.header ? '<div style="font-size:12px;opacity:.9;margin-top:4px;">' + esc(b.header) + '</div>' : '') +
        (b.address ? '<div style="font-size:11px;opacity:.85;margin-top:6px;">' + esc(b.address) + '</div>' : '') +
        (b.contactInfo ? '<div style="font-size:11px;opacity:.85;">' + esc(b.contactInfo) + '</div>' : '') +
      '</div>' +
      '<div style="padding:20px 24px;">' +
        '<div style="display:block;text-align:center;font-size:15px;font-weight:800;letter-spacing:.14em;color:#0f172a;">OFFICIAL RECEIPT</div>' +
        '<div style="text-align:center;font-size:12px;color:#16a34a;font-weight:800;margin-top:4px;">' +
          (r.status === 'Void' ? 'VOID' : 'PAID — ' + money(r, r.amount)) + '</div>' +
        '<table style="width:100%;border-collapse:collapse;margin-top:16px;">' + rows + '</table>' +
        (b.tin || b.businessPermit
            ? '<div style="font-size:10px;color:#64748b;margin-top:12px;">' +
              (b.tin ? 'TIN: ' + esc(b.tin) + '&nbsp;&nbsp;' : '') +
              (b.businessPermit ? 'Business Permit: ' + esc(b.businessPermit) : '') + '</div>' : '') +
        '<div style="margin-top:18px;display:block;">' +
          (b.signature ? '<img src="' + esc(b.signature) + '" alt="Authorized Signature" style="max-height:56px;display:block;">' : '') +
          '<div style="font-size:11px;color:#0f172a;font-weight:700;border-top:1px solid #cbd5e1;display:inline-block;padding-top:4px;margin-top:4px;">' +
            esc(r.approvedBy) + ' — Authorized Signatory</div>' +
        '</div>' +
        (b.qrCode ? '<div style="margin-top:14px;"><img src="' + esc(b.qrCode) + '" alt="Verification QR Code" style="max-height:96px;"></div>' : '') +
      '</div>' +
      '<div style="background:#f8fafc;padding:14px 24px;border-top:1px solid #e2e8f0;font-size:11px;color:#64748b;">' +
        (b.footer ? esc(b.footer) + '<br>' : '') +
        'This is a system-generated Official Receipt. Please retain it for your records.' +
      '</div>' +
    '</div>';
}

/** Standalone printable document (used by the print/PDF endpoint). */
function renderPrintableDocument(r) {
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
        '<title>Official Receipt ' + esc(r.orNumber) + '</title>' +
        '<style>body{margin:0;padding:24px;background:#f1f5f9;}@media print{body{background:#fff;padding:0;}.no-print{display:none;}}</style>' +
        '</head><body>' +
        '<div class="no-print" style="max-width:640px;margin:0 auto 14px;text-align:right;font-family:Segoe UI,Arial,sans-serif;">' +
        '<button onclick="window.print()" style="padding:9px 16px;border:0;border-radius:8px;background:#1d4ed8;color:#fff;font-weight:700;cursor:pointer;">Print / Save as PDF</button></div>' +
        renderOfficialReceiptHtml(r) +
        '</body></html>';
}

/* --------------------------------------------------------------- emailing */

/** Email the Official Receipt to the customer through the existing pipeline. */
async function emailOfficialReceipt(db, receipt, extraIntro) {
    const cfg = db.emailConfig;
    if (!cfg || !cfg.enabled || !receipt.tenantEmail) return { sent: false, reason: 'Email disabled or no recipient.' };
    const brand = deps.BrandingService.get(db);
    const intro = extraIntro ||
        'Your payment has been received and verified. Your Official Receipt is shown below.';
    const html =
        '<div style="background:#f1f5f9;padding:22px 0;font-family:Segoe UI,Helvetica,Arial,sans-serif;">' +
          '<div style="max-width:640px;margin:0 auto 14px;color:#0f172a;font-size:14px;">' +
            '<p style="margin:0 0 10px;">Hello ' + esc(receipt.tenantName) + ',</p>' +
            '<p style="margin:0 0 6px;">' + intro + '</p>' +
            '<p style="margin:0;"><b>Official Receipt No.: ' + esc(receipt.orNumber) + '</b></p>' +
          '</div>' +
          renderOfficialReceiptHtml(receipt) +
          '<div style="max-width:640px;margin:14px auto 0;color:#64748b;font-size:12px;">' +
            esc(brand.emailSignature || '') + '<br>' + esc(brand.emailFooter || '') +
          '</div>' +
        '</div>';
    await deps.sendEmailWithRetry({
        to: receipt.tenantEmail,
        subject: '[' + (brand.systemShortName || brand.dormName) + '] Official Receipt ' + receipt.orNumber +
                 ' — ' + receipt.category,
        html,
        type: 'Official Receipt',
        config: cfg,
        settings: db.settings
    });
    return { sent: true };
}

module.exports = {
    init, ensure, nextOrNumber, transactionKey, findLiveReceipt,
    issueOfficialReceipt, voidOfficialReceipt,
    renderOfficialReceiptHtml, renderPrintableDocument, emailOfficialReceipt,
    reportBucket, REPORT_BUCKET
};
