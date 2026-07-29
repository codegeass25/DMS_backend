# Dormitory Management System

Monolithic, build-free application. Pure HTML + Express, storage on Supabase PostgreSQL.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | The entire frontend (HTML + CSS + JS in one file) |
| `server.js` | The entire backend: APIs, auth/roles, billing, reservations, scheduler, email, white-label, rooms, reports |
| `supabase.js` | Supabase client + load/persist of the database document |
| `supabase.sql` | Schema + seed migrated from the old `data.json` |
| `package.json` / `package-lock.json` | Dependencies (`express`, `cors`, `nodemailer`, `@supabase/supabase-js`) |
| `render.yaml` | Render deployment blueprint |
| `.env.example` | Required environment variables |

No build step. No bundler. No framework. No ORM.

## 1. Supabase setup

1. Create a Supabase project.
2. Open **SQL Editor** and run the whole of `supabase.sql` once. This creates
   `public.app_data` and seeds it with your existing data.
3. Copy **Project URL** and the **service_role** key from Project Settings → API.

Every top-level collection of the old `data.json` (rooms, boarders,
reservations, transactions, settings, emailLogs, receiptArchive, users,
uploads, …) is one row in `app_data`, so you can inspect each one directly in
the Supabase table editor.

## 2. Run locally

```bash
npm install
cp .env.example .env   # then fill in SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
npm start
```

Open http://localhost:8080

## 3. Deploy to Render

1. Push this repository to GitHub.
2. Render → New → Web Service → pick the repo (or use `render.yaml`).
3. Build command: `npm install` — Start command: `npm start`.
4. Add environment variables `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.

No code changes are required to deploy.

## What changed in this upgrade

* `data.json`, its `.bak`/`.tmp` files and the atomic file writer were removed.
* Storage now hydrates from Supabase at boot into an in-process snapshot and
  every write is persisted back to Supabase through a serialised queue, so all
  existing synchronous code paths and APIs behave exactly as before.
* Uploaded photos (tenant, user, brand assets) are stored in Supabase instead
  of the ephemeral Render disk, while keeping the same `/uploads/<file>` URLs.

Everything else — every API, modal, report, receipt, email template, scheduler
rule, role permission and white-label feature — is unchanged.
