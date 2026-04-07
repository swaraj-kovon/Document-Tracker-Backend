-- ============================================================
-- Kovon Document Registry — Supabase Schema
-- ============================================================
-- Run the ENTIRE script in:
--   Supabase Dashboard → SQL Editor → New Query → Run
--
-- Safe to run multiple times — drops everything first so you
-- always get a clean, consistent state.
-- ============================================================


-- ════════════════════════════════════════════════════════════
-- STEP 0 — CLEAN SLATE
-- Drop in reverse FK order so constraints don't block drops
-- ════════════════════════════════════════════════════════════

DROP TABLE IF EXISTS audit_logs                 CASCADE;
DROP TABLE IF EXISTS approvals                  CASCADE;
DROP TABLE IF EXISTS approval_tokens            CASCADE;
DROP TABLE IF EXISTS password_reset_tokens      CASCADE;
DROP TABLE IF EXISTS email_verification_tokens  CASCADE;
DROP TABLE IF EXISTS serial_counters            CASCADE;
DROP TABLE IF EXISTS documents                  CASCADE;
DROP TABLE IF EXISTS users                      CASCADE;

DROP FUNCTION IF EXISTS increment_serial_counter(TEXT, INTEGER);


-- ════════════════════════════════════════════════════════════
-- STEP 1 — TABLES
-- ════════════════════════════════════════════════════════════

-- ── 1. USERS ─────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT        UNIQUE NOT NULL,
    name          TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'user'
                                  CHECK (role IN ('admin', 'user')),
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    is_blocked    BOOLEAN     NOT NULL DEFAULT FALSE
);


-- ── 2. DOCUMENTS ─────────────────────────────────────────────────────────────

CREATE TABLE documents (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number        TEXT        UNIQUE NOT NULL,
    category             TEXT        NOT NULL,
    category_code        TEXT        NOT NULL
                                         CHECK (category_code IN ('HR','LG','FN','BR','SH','OP','OT')),
    document_type        TEXT        NOT NULL,
    title                TEXT        NOT NULL,
    to_field             TEXT        NOT NULL,
    generated_by         TEXT        NOT NULL,
    generated_by_user_id UUID        NOT NULL
                                         REFERENCES users(id) ON DELETE CASCADE,
    description          TEXT        NOT NULL DEFAULT '',
    file_url             TEXT,
    file_name            TEXT,
    file_path            TEXT,
    status               TEXT        NOT NULL DEFAULT 'draft'
                                         CHECK (status IN ('draft','pending','approved','rejected')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    year                 INTEGER     NOT NULL,
    serial_counter       INTEGER     NOT NULL
);


-- ── 3. EMAIL VERIFICATION TOKENS ─────────────────────────────────────────────

CREATE TABLE email_verification_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token      TEXT        UNIQUE NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE
);


-- ── 4. PASSWORD RESET TOKENS ─────────────────────────────────────────────────

CREATE TABLE password_reset_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token      TEXT        UNIQUE NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE
);


-- ── 5. APPROVAL TOKENS ───────────────────────────────────────────────────────

CREATE TABLE approval_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token       TEXT        UNIQUE NOT NULL,
    document_id UUID        NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN     NOT NULL DEFAULT FALSE
);


-- ── 6. APPROVALS ─────────────────────────────────────────────────────────────

CREATE TABLE approvals (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID        NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    status      TEXT        NOT NULL CHECK (status IN ('approved','rejected')),
    action_by   TEXT        NOT NULL,
    action_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    remarks     TEXT        NOT NULL DEFAULT ''
);


-- ── 7. AUDIT LOGS ────────────────────────────────────────────────────────────

CREATE TABLE audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID        NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    action      TEXT        NOT NULL,
    action_by   TEXT        NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    details     TEXT        NOT NULL DEFAULT ''
);


-- ── 8. SERIAL COUNTERS ───────────────────────────────────────────────────────

CREATE TABLE serial_counters (
    id            UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    category_code TEXT    NOT NULL
                              CHECK (category_code IN ('HR','LG','FN','BR','SH','OP','OT')),
    year          INTEGER NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (category_code, year)
);


-- ════════════════════════════════════════════════════════════
-- STEP 2 — INDEXES
-- ════════════════════════════════════════════════════════════

CREATE INDEX idx_doc_owner_date  ON documents (generated_by_user_id, created_at DESC);
CREATE INDEX idx_doc_status      ON documents (status);
CREATE INDEX idx_doc_category    ON documents (category_code);
CREATE INDEX idx_doc_submitter   ON documents (generated_by);
CREATE INDEX idx_doc_created_at  ON documents (created_at DESC);

CREATE INDEX idx_evtoken_user    ON email_verification_tokens (user_id, used);
CREATE INDEX idx_prtoken_user    ON password_reset_tokens (user_id, used);
CREATE INDEX idx_aptoken_doc     ON approval_tokens (document_id);
CREATE INDEX idx_approvals_doc   ON approvals (document_id);
CREATE INDEX idx_audit_doc_time  ON audit_logs (document_id, timestamp ASC);
CREATE INDEX idx_audit_time_desc ON audit_logs (timestamp DESC);


-- ════════════════════════════════════════════════════════════
-- STEP 3 — ATOMIC SERIAL COUNTER FUNCTION
-- Called by the backend via supabase.rpc("increment_serial_counter", ...)
-- Returns the new counter value as INTEGER.
-- ════════════════════════════════════════════════════════════

CREATE FUNCTION increment_serial_counter(
    p_category_code TEXT,
    p_year          INTEGER
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_counter INTEGER;
BEGIN
    INSERT INTO serial_counters (category_code, year, counter)
         VALUES (p_category_code, p_year, 1)
    ON CONFLICT (category_code, year)
    DO UPDATE SET counter = serial_counters.counter + 1
    RETURNING counter INTO v_counter;

    RETURN v_counter;
END;
$$;


-- ════════════════════════════════════════════════════════════
-- STEP 4 — ROW LEVEL SECURITY
-- Backend uses the service-role key which bypasses RLS.
-- Disabling keeps things explicit and avoids policy conflicts.
-- ════════════════════════════════════════════════════════════

ALTER TABLE users                     DISABLE ROW LEVEL SECURITY;
ALTER TABLE documents                 DISABLE ROW LEVEL SECURITY;
ALTER TABLE email_verification_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens     DISABLE ROW LEVEL SECURITY;
ALTER TABLE approval_tokens           DISABLE ROW LEVEL SECURITY;
ALTER TABLE approvals                 DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs                DISABLE ROW LEVEL SECURITY;
ALTER TABLE serial_counters           DISABLE ROW LEVEL SECURITY;


-- ════════════════════════════════════════════════════════════
-- STEP 5 — STORAGE BUCKET
-- Public bucket for PDF/DOCX uploads (max 50 MB per file).
-- The backend stores the public URL in documents.file_url.
-- ════════════════════════════════════════════════════════════

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'documents',
    'documents',
    true,
    52428800,
    ARRAY[
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]
)
ON CONFLICT (id) DO UPDATE SET
    public            = true,
    file_size_limit   = 52428800,
    allowed_mime_types = ARRAY[
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

-- Allow anyone to read files from the documents bucket
-- (files are accessed by direct public URL from the frontend)
DROP POLICY IF EXISTS "Public read access" ON storage.objects;
CREATE POLICY "Public read access"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'documents');
