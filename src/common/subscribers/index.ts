import { notificationSubscriber } from "./notification.subscriber";
import { authCleanupSubscriber } from "./auth-cleanup.subscriber";
import { storageCleanupSubscriber } from "./storage-cleanup.subscriber";

let isRegistered = false;

/**
 * Đăng ký toàn bộ event subscribers của hệ thống vào EventBus
 */
export function registerAllSubscribers(): void {
  if (isRegistered) return;
  notificationSubscriber.register();
  authCleanupSubscriber.register();
  storageCleanupSubscriber.register();
  isRegistered = true;
  console.log(
    "[EventBus] 🚀 All microservices event subscribers registered successfully",
  );
}
