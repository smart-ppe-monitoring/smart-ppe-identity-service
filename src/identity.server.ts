import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing (e.g. Render, Railway, Docker)
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

import app from "./identity.app";
import { envConfig } from "./config/env.config";
import { webhookQueue } from "./common/queues/webhook.queue";
import { cronQueue } from "./common/queues/cron.queue";
import { maintenanceCacheService } from "./common/services/maintenance-cache.service";
import { systemConfigService } from "./modules/system-config/system-config.service";
import { sseManagerService } from "./common/services/sse-manager.service";
import { permissionCacheService } from "./common/services/permission-cache.service";
import { prisma } from "./database/prisma.client";

const PORT = envConfig.port;

/**
 * API Server Process (Microservices Phase 1: Process Decoupling)
 *
 * Chịu trách nhiệm độc quyền phục vụ các HTTP Request từ client/frontend.
 * KHÔNG khởi chạy BullMQ background workers (email, webhook, cron)
 * nhằm bảo toàn 100% CPU/RAM cho việc xử lý API và I/O.
 */
export const server = app.listen(PORT, async () => {
  console.log(
    `[API Server] Running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
  );

  // Ensure default system configs and feature flags are seeded
  await systemConfigService.ensureDefaultConfigs().catch((err) => {
    console.warn("[SystemConfig] Failed to seed default configs:", err.message);
  });
});

let isShuttingDown = false;

export async function handleApiShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(
    `\n[API Server] Received ${signal}. Starting graceful shutdown...`,
  );

  const forceExitTimer = setTimeout(() => {
    console.error(
      "[API Server] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Close idle HTTP connections
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests and wait for active requests
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) {
          console.warn(
            "[API Server] Warning while closing HTTP server:",
            err.message,
          );
        } else {
          console.log("[API Server] HTTP server closed.");
        }
        resolve();
      });
    });

    // 3. Close SSE streams, producer queues & Redis connections
    await sseManagerService.close();
    await webhookQueue.close();
    await cronQueue.close();
    await maintenanceCacheService.close();
    await systemConfigService.close();
    await permissionCacheService.close();
    console.log("[API Server] SSE, Redis & Queue connections closed.");

    // 4. Disconnect Prisma DB client
    await prisma.$disconnect();
    console.log("[API Server] Database client disconnected.");

    console.log("[API Server] Graceful shutdown completed cleanly.");
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(0);
    }
  } catch (err: any) {
    console.error("[API Server] Error during graceful shutdown:", err.message);
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(1);
    }
  }
}

if (process.env.NODE_ENV !== "test") {
  process.on("SIGTERM", () => handleApiShutdown("SIGTERM"));
  process.on("SIGINT", () => handleApiShutdown("SIGINT"));
}
