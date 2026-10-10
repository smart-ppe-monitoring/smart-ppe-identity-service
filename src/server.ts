import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing (e.g. Render, Railway, Docker)
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

import app from "./app";
import { envConfig } from "./config/env.config";
import { emailWorker } from "./common/workers/email-worker";
import { webhookWorker } from "./common/workers/webhook.worker";
import { cronWorker } from "./common/workers/cron.worker";
import { outboxWorker } from "./common/workers/outbox.worker";
import { eventBusWorker } from "./common/workers/event-bus.worker";
import { webhookQueue } from "./common/queues/webhook.queue";
import { cronQueue } from "./common/queues/cron.queue";
import { maintenanceCacheService } from "./common/services/maintenance-cache.service";
import { systemConfigService } from "./modules/system-config/system-config.service";
import { sseManagerService } from "./common/services/sse-manager.service";
import { permissionCacheService } from "./common/services/permission-cache.service";
import { registerAllSubscribers } from "./common/subscribers";
import { eventBus } from "./common/services/event-bus.service";
import { prisma } from "./database/prisma.client";

const PORT = envConfig.port;

const server = app.listen(PORT, async () => {
  console.log(
    `Server running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
  );

  // Register all EventBus microservices subscribers
  registerAllSubscribers();

  // Ensure default system configs and feature flags are seeded
  await systemConfigService.ensureDefaultConfigs().catch((err) => {
    console.warn("[SystemConfig] Failed to seed default configs:", err.message);
  });

  // Start background workers, outbox relay and register cron schedules
  emailWorker.start();
  webhookWorker.start();
  cronWorker.start();
  eventBusWorker.start();
  outboxWorker.start();
  await cronQueue.registerSchedules();
});

// Graceful Shutdown Handler
let isShuttingDown = false;

async function handleShutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`\n[Server] Received ${signal}. Starting graceful shutdown...`);

  // Force shutdown if taking longer than 10 seconds
  const forceExitTimer = setTimeout(() => {
    console.error(
      "[Server] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Close idle HTTP connections to avoid hanging server.close()
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests and wait for HTTP server to finish active requests
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) {
          console.warn(
            "[Server] Warning while closing HTTP server:",
            err.message,
          );
        } else {
          console.log("[Server] HTTP server closed.");
        }
        resolve();
      });
    });

    // 3. Stop background BullMQ workers, outbox worker and email workers safely
    await Promise.allSettled([
      emailWorker.stop(),
      webhookWorker.stop(),
      cronWorker.stop(),
      eventBusWorker.stop(),
      outboxWorker.stop(),
    ]);
    console.log("[Server] BullMQ & background workers stopped.");

    // 4. Close BullMQ queues, SSE streams, EventBus & Redis connections
    await sseManagerService.close();
    await webhookQueue.close();
    await cronQueue.close();
    await eventBus.close();
    await maintenanceCacheService.close();
    await systemConfigService.close();
    await permissionCacheService.close();
    console.log("[Server] SSE, Redis, EventBus & Queue connections closed.");

    // 5. Disconnect Prisma DB client
    await prisma.$disconnect();
    console.log("[Server] Database client disconnected.");

    console.log("[Server] Graceful shutdown completed cleanly.");
    clearTimeout(forceExitTimer);
    process.exit(0);
  } catch (err: any) {
    console.error("[Server] Error during graceful shutdown:", err.message);
    clearTimeout(forceExitTimer);
    process.exit(1);
  }
}

process.on("SIGTERM", () => handleShutdown("SIGTERM"));
process.on("SIGINT", () => handleShutdown("SIGINT"));
