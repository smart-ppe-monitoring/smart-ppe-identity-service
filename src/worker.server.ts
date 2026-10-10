import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

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
import { permissionCacheService } from "./common/services/permission-cache.service";
import { registerAllSubscribers } from "./common/subscribers";
import { notificationSubscriber } from "./common/subscribers/notification.subscriber";
import { authCleanupSubscriber } from "./common/subscribers/auth-cleanup.subscriber";
import { storageCleanupSubscriber } from "./common/subscribers/storage-cleanup.subscriber";
import { eventBus } from "./common/services/event-bus.service";
import { prisma } from "./database/prisma.client";

/**
 * Background Worker Process (Microservices Phase 1: Process Decoupling & Phase 3: Event-Driven Backbone)
 *
 * Chịu trách nhiệm độc quyền xử lý các tác vụ nền không đồng bộ:
 * - Email queue & SMTP/Resend dispatch
 * - Outgoing Webhook deliveries & HMAC signing
 * - Cron jobs định kỳ (cleanup audit logs, orphan files, expired tokens)
 * - Event-Driven Subscribers & Transactional Outbox Relay
 *
 * KHÔNG mở cổng HTTP, tối ưu hóa toàn bộ tài nguyên cho background processing.
 */
export async function startWorkerProcess(): Promise<void> {
  console.log(
    `[Worker Server] Starting Background Worker in ${envConfig.nodeEnv} mode...`,
  );

  // Register EventBus subscribers theo trạng thái standalone của các satellite microservices:
  if (!envConfig.notification.standalone) {
    notificationSubscriber.register();
  }
  if (!envConfig.media.standalone) {
    storageCleanupSubscriber.register();
  }
  authCleanupSubscriber.register();

  // Ensure default system configs are ready
  await systemConfigService.ensureDefaultConfigs().catch((err) => {
    console.warn(
      "[Worker Server] Failed to seed default configs:",
      err.message,
    );
  });

  // Start background workers, outbox relay and register repeatable cron jobs
  // Khi NOTIFICATION_SERVICE_STANDALONE=true, emailWorker được đảm nhiệm bởi notification-service riêng biệt
  if (!envConfig.notification.standalone) {
    emailWorker.start();
  }
  webhookWorker.start();
  cronWorker.start();
  eventBusWorker.start();
  outboxWorker.start();

  await cronQueue.registerSchedules().catch((err) => {
    console.warn(
      "[Worker Server] Failed to register cron schedules:",
      err.message,
    );
  });

  console.log(
    "[Worker Server] ✅ All BullMQ workers, Outbox worker and cron schedules are active and listening.",
  );
}

let isShuttingDown = false;

export async function handleWorkerShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(
    `\n[Worker Server] Received ${signal}. Starting graceful shutdown...`,
  );

  const forceExitTimer = setTimeout(() => {
    console.error(
      "[Worker Server] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Stop accepting new jobs and finish active workers safely
    await Promise.allSettled([
      emailWorker.stop(),
      webhookWorker.stop(),
      cronWorker.stop(),
      eventBusWorker.stop(),
      outboxWorker.stop(),
    ]);
    console.log("[Worker Server] BullMQ & background workers stopped.");

    // 2. Close BullMQ queues, EventBus & Redis connections
    await webhookQueue.close();
    await cronQueue.close();
    await eventBus.close();
    await maintenanceCacheService.close();
    await systemConfigService.close();
    await permissionCacheService.close();
    console.log("[Worker Server] Redis & Queue connections closed.");

    // 3. Disconnect Prisma DB client
    await prisma.$disconnect();
    console.log("[Worker Server] Database client disconnected.");

    console.log("[Worker Server] Graceful shutdown completed cleanly.");
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(0);
    }
  } catch (err: any) {
    console.error(
      "[Worker Server] Error during graceful shutdown:",
      err.message,
    );
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(1);
    }
  }
}

if (process.env.NODE_ENV !== "test") {
  startWorkerProcess().catch((err) => {
    console.error("[Worker Server] Fatal error starting worker process:", err);
    process.exit(1);
  });

  process.on("SIGTERM", () => handleWorkerShutdown("SIGTERM"));
  process.on("SIGINT", () => handleWorkerShutdown("SIGINT"));
}
