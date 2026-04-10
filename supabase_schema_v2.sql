DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS approvals CASCADE;
DROP TABLE IF EXISTS approval_tokens CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS email_verification_tokens CASCADE;
DROP TABLE IF EXISTS serial_counters CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS users CASCADE;  -- OLD CUSTOM USERS

DROP FUNCTION IF EXISTS increment_serial_counter(TEXT, INTEGER);

-- STEP 1: PROFILES TABLE (linked to auth.users)
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
  is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- STEP 2: DOCUMENTS (FK to profiles.id)
CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  serial_number TEXT UNIQUE NOT NULL,
  category TEXT NOT NULL,
  category_code TEXT NOT NULL CHECK (category_code IN ('HR','LG','FN','BR','SH','OP','OT')),
  document_type TEXT NOT NULL,
  title TEXT NOT NULL,
  to_field TEXT NOT NULL,
  generated_by TEXT NOT NULL,
  generated_by_user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  description TEXT NOT NULL DEFAULT '',
  file_url TEXT,
  file_name TEXT,
  file_path TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','approved','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  year INTEGER NOT NULL,
  serial_counter INTEGER NOT NULL
);

-- REMAINING TABLES (unchanged)
CREATE TABLE approval_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token TEXT UNIQUE NOT NULL,
  document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('approved','rejected')),
  action_by TEXT NOT NULL,
  action_date TIMESTAMPTZ NOT NULL DEFAULT now(),
  remarks TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  action_by TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
  details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE serial_counters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category_code TEXT NOT NULL CHECK (category_code IN ('HR','LG','FN','BR','SH','OP','OT')),
  year INTEGER NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  UNIQUE (category_code, year)
);

-- INDEXES
CREATE INDEX idx_doc_owner_date ON documents (generated_by_user_id, created_at DESC);
CREATE INDEX idx_doc_status ON documents (status);
CREATE INDEX idx_doc_category ON documents (category_code);
CREATE INDEX idx_doc_submitter ON documents (generated_by);
CREATE INDEX idx_doc_created_at ON documents (created_at DESC);

CREATE INDEX idx_aptoken_doc ON approval_tokens (document_id);
CREATE INDEX idx_approvals_doc ON approvals (document_id);
CREATE INDEX idx_audit_doc_time ON audit_logs (document_id, timestamp ASC);

-- SERIAL COUNTER FUNCTION
CREATE OR REPLACE FUNCTION increment_serial_counter(p_category_code TEXT, p_year INTEGER)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE v_counter INTEGER;
BEGIN
  INSERT INTO serial_counters (category_code, year, counter)
  VALUES (p_category_code, p_year, 1)
  ON CONFLICT (category_code, year) DO UPDATE SET counter = serial_counters.counter + 1
  RETURNING counter INTO v_counter;
  RETURN v_counter;
END;
$$;

-- RLS: Secure profiles
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own profile" ON profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users update own name" ON profiles FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Service role full access" ON profiles FOR ALL TO service_role USING (true);

ALTER TABLE documents DISABLE ROW LEVEL SECURITY;  -- Service key bypass
ALTER TABLE approval_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE approvals DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE serial_counters DISABLE ROW LEVEL SECURITY;

-- STORAGE BUCKET
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('documents', 'documents', true, 52428800, ARRAY['application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document'])
ON CONFLICT (id) DO UPDATE SET public=true, file_size_limit=52428800, allowed_mime_types=ARRAY['application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

DROP POLICY IF EXISTS "Public read access" ON storage.objects;
CREATE POLICY "Public read documents" ON storage.objects FOR SELECT USING (bucket_id = 'documents');

-- ADMIN SETUP TRIGGER (auto-create profile on auth.users insert)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, role)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'role', 'user')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

