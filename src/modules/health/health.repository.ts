import { prisma } from "../../database/prisma.client";

export class HealthRepository {
  async pingDatabase(): Promise<{ latencyMs: number }> {
    const start = Date.now();
    await prisma.$queryRaw`SELECT 1`;
    return { latencyMs: Date.now() - start };
  }
}

export const healthRepository = new HealthRepository();
