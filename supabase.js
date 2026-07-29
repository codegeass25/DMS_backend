/**
 * DORMITORY MANAGEMENT SYSTEM — Supabase storage adapter
 *
 * This is the ONLY database file. It replaces the legacy data.json file store
 * with Supabase PostgreSQL while keeping the exact same document shape the
 * whole system already uses, so server.js needs no logic changes anywhere.
 *
 * Table (see supabase.sql):
 *   app_data(collection text primary key, payload jsonb, updated_at timestamptz)
 *
 * Every top-level key of the old data.json (rooms, boarders, reservations,
 * transactions, settings, emailLogs, receiptArchive, users, uploads, ...) is
 * stored as its own row, so each collection can be inspected and queried
 * directly in the Supabase table editor.
 *
 * Uses ONLY @supabase/supabase-js. No ORM.
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    '';

const TABLE = process.env.SUPABASE_TABLE || 'app_data';

const isConfigured = !!(SUPABASE_URL && SUPABASE_KEY);

if (!isConfigured) {
    console.warn('[SUPABASE] SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set. See .env.example.');
}

const supabase = isConfigured
    ? createClient(SUPABASE_URL, SUPABASE_KEY, {
          auth: { persistSession: false, autoRefreshToken: false }
      })
    : null;

/** Read the whole database document back out of Supabase. */
async function loadDatabase() {
    if (!supabase) throw new Error('Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing).');
    const { data, error } = await supabase.from(TABLE).select('collection, payload');
    if (error) throw new Error(`Supabase read failed: ${error.message}`);
    const db = {};
    (data || []).forEach(row => {
        db[row.collection] = row.payload && typeof row.payload === 'object' && 'v' in row.payload
            ? row.payload.v
            : row.payload;
    });
    return db;
}

/**
 * Persist the whole database document. Each top-level key becomes one row.
 * Scalars are wrapped as { v: value } so jsonb always holds a JSON object.
 */
async function persistDatabase(db) {
    if (!supabase) throw new Error('Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing).');
    const now = new Date().toISOString();
    const rows = Object.keys(db || {}).map(collection => {
        const value = db[collection];
        const payload = value !== null && typeof value === 'object' ? value : { v: value };
        return { collection, payload, updated_at: now };
    });
    if (!rows.length) return true;

    // Chunked upsert keeps very large payloads (images, archives) within limits.
    const CHUNK = 8;
    for (let i = 0; i < rows.length; i += CHUNK) {
        const { error } = await supabase.from(TABLE).upsert(rows.slice(i, i + CHUNK), { onConflict: 'collection' });
        if (error) throw new Error(`Supabase write failed: ${error.message}`);
    }
    return true;
}

/** Convenience helper for health checks. */
async function pingDatabase() {
    if (!supabase) return false;
    const { error } = await supabase.from(TABLE).select('collection').limit(1);
    return !error;
}

module.exports = { supabase, loadDatabase, persistDatabase, pingDatabase, isConfigured, TABLE };
