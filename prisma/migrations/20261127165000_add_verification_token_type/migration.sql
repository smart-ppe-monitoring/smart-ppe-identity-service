-- AlterTable
ALTER TABLE "verification_tokens" ADD COLUMN IF NOT EXISTS "type" TEXT NOT NULL DEFAULT 'EMAIL_VERIFICATION';

-- CreateIndex
CREATE INDEX IF NOT EXISTS "verification_tokens_user_id_type_idx" ON "verification_tokens"("user_id", "type");
