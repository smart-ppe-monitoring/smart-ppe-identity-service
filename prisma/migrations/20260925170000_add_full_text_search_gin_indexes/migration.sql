-- Migration: 20260925170000_add_full_text_search_gin_indexes
-- Description: Thêm các chỉ mục GIN (Generalized Inverted Index) phục vụ tối ưu hóa PostgreSQL Full-Text Search

-- 1. Create GIN index for Full-Text Search on users table (full_name, email, phone_number)
CREATE INDEX IF NOT EXISTS "idx_users_fts" ON "users" USING gin (
    to_tsvector('simple', coalesce("full_name", '') || ' ' || coalesce("email", '') || ' ' || coalesce("phone_number", ''))
);

-- 2. Create GIN index for Full-Text Search on file_records table (original_name, file_name, folder)
CREATE INDEX IF NOT EXISTS "idx_file_records_fts" ON "file_records" USING gin (
    to_tsvector('simple', coalesce("original_name", '') || ' ' || coalesce("file_name", '') || ' ' || coalesce("folder", ''))
);

-- 3. Create GIN index for Full-Text Search on audit_logs table (action, target_type, ip_address, user_agent)
CREATE INDEX IF NOT EXISTS "idx_audit_logs_fts" ON "audit_logs" USING gin (
    to_tsvector('simple', coalesce("action", '') || ' ' || coalesce("target_type", '') || ' ' || coalesce("ip_address", '') || ' ' || coalesce("user_agent", ''))
);
