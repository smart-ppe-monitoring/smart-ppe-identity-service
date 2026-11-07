-- AlterTable
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "site_ids" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- CreateIndex
CREATE INDEX IF NOT EXISTS "idx_users_site_ids" ON "users" USING gin ("site_ids");
