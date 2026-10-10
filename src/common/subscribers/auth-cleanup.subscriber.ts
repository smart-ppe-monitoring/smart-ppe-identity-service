import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_NAMES } from "../constants/event.constant";
import {
  authRepository,
  AuthRepository,
} from "../../modules/auth/auth.repository";
import {
  permissionCacheService,
  PermissionCacheService,
} from "../services/permission-cache.service";
import { UserSoftDeletedPayload, EventEnvelope } from "../types/event.type";

export class AuthCleanupSubscriber {
  private readonly repository: AuthRepository;
  private readonly cacheService: PermissionCacheService;
  private readonly bus: EventBusService;

  constructor(
    repository?: AuthRepository,
    cacheService?: PermissionCacheService,
    bus?: EventBusService,
  ) {
    this.repository = repository || authRepository;
    this.cacheService = cacheService || permissionCacheService;
    this.bus = bus || eventBus;
  }

  public register(): void {
    // Consumer: user.soft_deleted
    this.bus.subscribe(
      EVENT_NAMES.USER_SOFT_DELETED,
      async (envelope: EventEnvelope<UserSoftDeletedPayload>) => {
        const { userId, deletedBy } = envelope.payload;
        try {
          // 1. Thu hồi toàn bộ Refresh Tokens của user bị soft delete
          await this.repository.revokeAllUserSessions(userId);

          // 2. Xóa sạch bộ nhớ đệm quyền (in-memory TTL cache)
          this.cacheService.invalidateUser(userId);

          console.log(
            `[AuthCleanupSubscriber] ✅ Revoked all sessions and cleared permission cache for soft-deleted user: ${userId} (by admin: ${deletedBy})`,
          );
        } catch (err: any) {
          console.error(
            `[AuthCleanupSubscriber] ❌ Failed to cleanup sessions for user ${userId}:`,
            err?.message || err,
          );
          throw err; // Nack to trigger retry/DLQ
        }
      },
    );
  }
}

export const authCleanupSubscriber = new AuthCleanupSubscriber();
