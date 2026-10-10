import { prisma, DEFAULT_TRANSACTION_OPTIONS } from "./prisma.client";

/**
 * Cấu hình timeout mặc định cho interactive transactions của Identity Service
 */
export const DEFAULT_IDENTITY_TRANSACTION_OPTIONS = DEFAULT_TRANSACTION_OPTIONS;

/**
 * Singleton Prisma Client cho Identity Service (ppe_identity_db)
 */
export const identityPrisma = prisma;
