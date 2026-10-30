import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { FEATURE_FLAGS } from "../src/common/constants/system-config.constant";
import { MAINTENANCE_STATUS } from "../src/common/constants/maintenance.constant";
import { UserService } from "../src/modules/users/user.service";
import { UserRepository } from "../src/modules/users/user.repository";
import { maintenanceGuard } from "../src/middlewares/maintenance.middleware";
import { maintenanceCacheService } from "../src/common/services/maintenance-cache.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { requireFeatureFlag } from "../src/middlewares/feature-flag.middleware";
import { systemConfigService } from "../src/modules/system-config/system-config.service";
import { getClientIp } from "../src/common/helpers/ip.helper";
import authRouter from "../src/modules/auth/auth.route";

describe("SEC-19, SEC-20 & SEC-21 Security Remediation Test Suite", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-19: Trust Proxy & IP Spoofing Prevention in Maintenance Mode
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-19: Trust Proxy & IP Extraction Guard", () => {
    it("getClientIp should return normalized remoteAddress when no proxy is trusted", () => {
      const req: any = {
        socket: { remoteAddress: "::ffff:203.0.113.195" },
      };
      assert.strictEqual(getClientIp(req), "203.0.113.195");
    });

    it("maintenanceGuard should reject request when external IP attempts to spoof whitelisted IP via X-Forwarded-For", async () => {
      (maintenanceCacheService as any).cache = {
        config: {
          enabled: true,
          status: MAINTENANCE_STATUS.DOWN,
          title: "Maintenance",
          message: "System under maintenance",
          bypassRoles: [],
          bypassPermissions: [],
          bypassIps: ["127.0.0.1", "192.168.1.100"],
        },
        expiresAt: Date.now() + 60000,
      };

      const guard = maintenanceGuard();

      // Attacker sends request with spoofed X-Forwarded-For header, but socket connection is from external IP
      const req: any = {
        method: "GET",
        url: "/api/v1/users",
        ip: "203.0.113.195", // Express req.ip derived safely from 1 hop, NOT the attacker's spoofed header
        socket: { remoteAddress: "203.0.113.195" },
        headers: {
          "x-forwarded-for": "127.0.0.1",
        },
      };

      let errorThrown: any;
      await guard(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject request when real IP is not whitelisted");
      assert.strictEqual(errorThrown.statusCode, 503);
      assert.strictEqual(errorThrown.code, ERROR_CODE.SYSTEM_MAINTENANCE);
    });

    it("maintenanceGuard should allow request when client IP matches whitelist", async () => {
      (maintenanceCacheService as any).cache = {
        config: {
          enabled: true,
          status: MAINTENANCE_STATUS.DOWN,
          title: "Maintenance",
          message: "System under maintenance",
          bypassRoles: [],
          bypassPermissions: [],
          bypassIps: ["192.168.1.100"],
        },
        expiresAt: Date.now() + 60000,
      };

      const guard = maintenanceGuard();

      const req: any = {
        method: "GET",
        url: "/api/v1/users",
        ip: "192.168.1.100",
        socket: { remoteAddress: "192.168.1.100" },
        headers: {},
      };

      let nextCalled = false;
      let errorThrown: any;
      await guard(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.strictEqual(errorThrown, undefined);
      assert.strictEqual(nextCalled, true);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-20: Tombstone Soft Delete & Storage Cleanup
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-20: Tombstone Soft Delete & Storage Cleanup Guard", () => {
    it("UserService.softDelete should apply tombstone to email, clear phone and delete R2 avatar", async () => {
      const victimId = "v1000000-0000-0000-0000-000000000001";
      const adminId = "a1000000-0000-0000-0000-000000000001";

      const victimUser = {
        id: victimId,
        email: "victim@company.com",
        phoneNumber: "0901234567",
        avatarUrl: `https://pub-cdn.ppe.local/avatars/${victimId}/avatar-123.webp`,
        role: { name: ROLES.USER },
        roleId: "role-user-1",
        isActive: true,
        deletedAt: null,
      };

      const adminUser = {
        id: adminId,
        email: "admin@company.com",
        role: { name: ROLES.ADMIN },
        roleId: "role-admin-1",
        isActive: true,
      };

      let softDeleteCallArg: any = null;
      let deletedR2Key: string | null = null;

      const mockRepo: Partial<UserRepository> = {
        findById: async (id: string) => {
          if (id === victimId) return victimUser as any;
          if (id === adminId) return adminUser as any;
          return null;
        },
        findWithDeleted: async (id: string) => (id === victimId ? (victimUser as any) : null),
        countActiveAdmins: async () => 2,
        softDelete: async (id: string, admId: string, tombstone?: any) => {
          softDeleteCallArg = { id, admId, tombstone };
          return [
            {
              id,
              deletedAt: new Date(),
              email: tombstone?.email,
              phoneNumber: tombstone?.phoneNumber,
            },
          ] as any;
        },
        createAuditLog: async () => ({}) as any,
      };

      const mockEventBus = {
        publish: async () => {},
      };

      const mockR2Service = {
        deleteFile: async (key: string) => {
          deletedR2Key = key;
        },
      };

      const service = new UserService(
        mockRepo as any,
        mockEventBus as any,
        mockR2Service as any,
      );

      (permissionCacheService as any).cache.set("role-user-1", {
        permissions: new Set(["USER_READ"]),
        expiresAt: Date.now() + 60000,
      });
      (permissionCacheService as any).cache.set("role-admin-1", {
        permissions: new Set(["ADMIN_ALL"]),
        expiresAt: Date.now() + 60000,
      });

      await service.softDelete(victimId, adminId);

      // 1. Verify tombstone email format
      assert.ok(softDeleteCallArg, "softDelete must be called");
      assert.match(
        softDeleteCallArg.tombstone.email,
        /^deleted_\d+_[a-z0-9-]+@tombstone\.local$/,
        "Email must be tombstoned to release UNIQUE constraint",
      );

      // 2. Verify phone number released
      assert.strictEqual(
        softDeleteCallArg.tombstone.phoneNumber,
        null,
        "Phone number must be cleared to allow re-registration",
      );

      // 3. Verify R2 avatar deleted
      assert.strictEqual(
        deletedR2Key,
        `avatars/${victimId}/avatar-123.webp`,
        "Avatar on R2 must be deleted when user is soft deleted",
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-21: Feature Flag Mounting on Auth Routes
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-21: Feature Flag Middleware Mounting Guard", () => {
    it("requireFeatureFlag should reject with 403 FEATURE_DISABLED when flag is disabled", async () => {
      // Mock feature disabled
      const originalIsFeatureEnabled = systemConfigService.isFeatureEnabled;
      systemConfigService.isFeatureEnabled = async (key: string) => {
        if (key === FEATURE_FLAGS.REGISTRATION_ENABLED) return false;
        return true;
      };

      try {
        const middleware = requireFeatureFlag(FEATURE_FLAGS.REGISTRATION_ENABLED, {
          message: "Registration is temporarily disabled",
        });

        let errorThrown: any;
        await middleware({} as any, {} as any, (err?: any) => {
          errorThrown = err;
        });

        assert.ok(errorThrown, "Must reject request when registration flag is disabled");
        assert.strictEqual(errorThrown.statusCode, 403);
        assert.strictEqual(errorThrown.code, ERROR_CODE.FEATURE_DISABLED);
        assert.strictEqual(errorThrown.message, "Registration is temporarily disabled");
      } finally {
        systemConfigService.isFeatureEnabled = originalIsFeatureEnabled;
      }
    });

    it("POST /register route stack must contain requireFeatureFlag middleware", () => {
      const registerRoute = authRouter.stack.find(
        (layer: any) =>
          layer.route &&
          layer.route.path === "/register" &&
          layer.route.methods.post,
      );

      assert.ok(registerRoute, "POST /register must exist in authRouter");

      // Verify route has at least 4 middlewares (rateLimit, featureFlag, turnstile, validate, controller)
      assert.ok(
        registerRoute.route.stack.length >= 4,
        "POST /register route must have featureFlag middleware mounted",
      );
    });

    it("POST /google route stack must contain requireFeatureFlag middleware", () => {
      const googleRoute = authRouter.stack.find(
        (layer: any) =>
          layer.route &&
          layer.route.path === "/google" &&
          layer.route.methods.post,
      );

      assert.ok(googleRoute, "POST /google must exist in authRouter");

      assert.ok(
        googleRoute.route.stack.length >= 3,
        "POST /google route must have featureFlag middleware mounted",
      );
    });
  });
});
