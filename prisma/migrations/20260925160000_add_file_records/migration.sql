-- CreateTable
CREATE TABLE "file_records" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "user_id" UUID,
    "original_name" TEXT NOT NULL,
    "file_name" TEXT NOT NULL,
    "mime_type" TEXT NOT NULL,
    "size" INTEGER NOT NULL DEFAULT 0,
    "bucket_key" TEXT NOT NULL,
    "folder" TEXT NOT NULL DEFAULT 'general',
    "is_public" BOOLEAN NOT NULL DEFAULT false,
    "is_confirmed" BOOLEAN NOT NULL DEFAULT false,
    "metadata" JSONB,
    "deleted_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "file_records_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "file_records_bucket_key_key" ON "file_records"("bucket_key");

-- CreateIndex
CREATE INDEX "file_records_user_id_is_public_idx" ON "file_records"("user_id", "is_public");

-- CreateIndex
CREATE INDEX "file_records_folder_is_public_idx" ON "file_records"("folder", "is_public");

-- CreateIndex
CREATE INDEX "file_records_is_confirmed_created_at_idx" ON "file_records"("is_confirmed", "created_at");

-- CreateIndex
CREATE INDEX "file_records_deleted_at_idx" ON "file_records"("deleted_at");

-- AddForeignKey
ALTER TABLE "file_records" ADD CONSTRAINT "file_records_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
