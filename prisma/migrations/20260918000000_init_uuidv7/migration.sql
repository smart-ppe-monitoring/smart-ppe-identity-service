-- Enable pgcrypto for gen_random_bytes
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create uuid_generate_v7() function: time-ordered UUID v7
-- Encodes Unix epoch in milliseconds into the top 48 bits,
-- version bits (0111) into bits 48–51, and fills remaining bits
-- with cryptographically random data.
CREATE OR REPLACE FUNCTION uuid_generate_v7()
RETURNS uuid
AS $$
DECLARE
  unix_ts_ms bytea;
  uuid_bytes bytea;
BEGIN
  unix_ts_ms = substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3);
  uuid_bytes = unix_ts_ms ||
               substring(gen_random_bytes(10) FROM 1 FOR 2) ||
               gen_random_bytes(8);
  -- Set version to 7 (bits 48–51 = 0111)
  uuid_bytes = set_byte(uuid_bytes, 6, (b'0111' || get_byte(uuid_bytes, 6)::bit(4))::bit(8)::int);
  -- Set variant bits to 10 (bits 64–65)
  uuid_bytes = set_byte(uuid_bytes, 8, (b'10' || get_byte(uuid_bytes, 8)::bit(6))::bit(8)::int);
  RETURN encode(uuid_bytes, 'hex')::uuid;
END
$$
LANGUAGE plpgsql
VOLATILE;

-- AlterTable defaults to uuid_generate_v7()
ALTER TABLE "users" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "roles" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "permissions" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "role_permissions" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "audit_logs" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "refresh_tokens" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "user_socials" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "verification_tokens" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "password_reset_tokens" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "user_devices" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "notifications" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "email_notifications" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "notification_templates" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "maintenance_configs" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "api_keys" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "webhook_endpoints" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "webhook_deliveries" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();
ALTER TABLE "system_configs" ALTER COLUMN "id" SET DEFAULT uuid_generate_v7();

-- Drop redundant single indexes on foreign keys already covered by composite indexes
DROP INDEX IF EXISTS "users_role_id_idx";
DROP INDEX IF EXISTS "role_permissions_role_id_idx";
