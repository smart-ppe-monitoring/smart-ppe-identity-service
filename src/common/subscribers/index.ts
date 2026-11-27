import { envConfig } from "../../config/env.config";
import { notificationSubscriber } from "./notification.subscriber";
import { authCleanupSubscriber } from "./auth-cleanup.subscriber";
import { storageCleanupSubscriber } from "./storage-cleanup.subscriber";
import { webhookSubscriber } from "./webhook.subscriber";

let isRegistered = false;

/**
 * Đăng ký toàn bộ event subscribers của hệ thống vào EventBus
 */
export function registerAllSubscribers(): void {
  if (isRegistered) return;
  if (!envConfig.notification.standalone) {
    notificationSubscriber.register();
  }
  authCleanupSubscriber.register();
  storageCleanupSubscriber.register();
  webhookSubscriber.register();
  isRegistered = true;
  console.log(
    "[EventBus] 🚀 All microservices event subscribers registered successfully",
  );
}
