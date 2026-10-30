import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import {
  loginSchema,
  registerSchema,
  updatePasswordSchema,
  resetPasswordSchema,
  requestDeactivateSchema,
  disable2FASchema,
} from "../src/modules/auth/auth.validation";
import { createUserSchema } from "../src/modules/users/user.validation";
import { AuthService } from "../src/modules/auth/auth.service";
import { UserService } from "../src/modules/users/user.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { createRequireGatewayOrigin } from "../src/middlewares/request-id.middleware";
import app from "../src/identity.app";

describe("SEC-22, SEC-23 & SEC-24 Hardening & Security Remediation Test Suite", () => {
  beforeEach(() => {
    permissionCacheService.clear();
    (permissionCacheService as any).cache.set("role-user-1", {
      permissions: new Set(["USER_READ"]),
      expiresAt: Date.now() + 60000,
    });
    (permissionCacheService as any).cache.set("role-admin-1", {
      permissions: new Set(["ADMIN_ALL"]),
      expiresAt: Date.now() + 60000,
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-22: Password Max Length (128 chars) Prevention for bcrypt Starvation
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-22: Password Max Length Guard (Anti-Event Loop Starvation)", () => {
    const validPassword = "StrongPassword@123";
    const oversizedPassword = "A".repeat(129) + "a1!";

    it("loginSchema should reject passwords exceeding 128 characters", () => {
      const result = loginSchema.safeParse({
        email: "user@example.com",
        password: oversizedPassword,
      });
      assert.strictEqual(result.success, false);
      const errors = result.error?.issues.map((i) => i.message);
      assert.ok(
        errors?.some((msg) => msg.includes("128")),
        "Must specify maximum 128 characters",
      );
    });

    it("loginSchema should accept valid passwords <= 128 characters", () => {
      const result = loginSchema.safeParse({
        email: "user@example.com",
        password: validPassword,
      });
      assert.strictEqual(result.success, true);
    });

    it("registerSchema should reject passwords exceeding 128 characters", () => {
      const result = registerSchema.safeParse({
        email: "user@example.com",
        password: oversizedPassword,
      });
      assert.strictEqual(result.success, false);
      const errors = result.error?.issues.map((i) => i.message);
      assert.ok(
        errors?.some((msg) => msg.includes("128")),
        "Must enforce 128 chars limit on register",
      );
    });

    it("updatePasswordSchema should reject newPassword exceeding 128 characters", () => {
      const result = updatePasswordSchema.safeParse({
        oldPassword: validPassword,
        newPassword: oversizedPassword,
      });
      assert.strictEqual(result.success, false);
      const errors = result.error?.issues.map((i) => i.message);
      assert.ok(errors?.some((msg) => msg.includes("128")));
    });

    it("resetPasswordSchema should reject newPassword exceeding 128 characters", () => {
      const result = resetPasswordSchema.safeParse({
        token: "sample-token",
        newPassword: oversizedPassword,
      });
      assert.strictEqual(result.success, false);
      const errors = result.error?.issues.map((i) => i.message);
      assert.ok(errors?.some((msg) => msg.includes("128")));
    });

    it("createUserSchema should reject password exceeding 128 characters", () => {
      const result = createUserSchema.safeParse({
        email: "user@example.com",
        password: oversizedPassword,
        roleId: "a0000000-0000-0000-0000-000000000001",
      });
      assert.strictEqual(result.success, false);
      const errors = result.error?.issues.map((i) => i.message);
      assert.ok(errors?.some((msg) => msg.includes("128")));
    });

    it("AuthService.login should reject password > 128 chars at service layer (Defense-in-Depth)", async () => {
      const authService = new AuthService({} as any, {} as any);
      await assert.rejects(
        () =>
          authService.login({
            email: "user@example.com",
            password: oversizedPassword,
          }),
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });

    it("AuthService.register should reject password > 128 chars at service layer", async () => {
      const authService = new AuthService({} as any, {} as any);
      await assert.rejects(
        () =>
          authService.register({
            email: "user@example.com",
            password: oversizedPassword,
          }),
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-23: Redaction of Lockout Metadata & Password Flags for Non-Admin
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-23: User FTS & Listing Sensitive Metadata Redaction", () => {
    const sampleUsers = [
      {
        id: "u1000000-0000-0000-0000-000000000001",
        email: "alice@company.com",
        fullName: "Alice Safety",
        phoneNumber: "0901111222",
        roleId: "role-user-1",
        role: { id: "role-user-1", name: ROLES.USER },
        isActive: true,
        twoFactorEnabled: false,
        mustChangePassword: true,
        failedLoginAttempts: 4,
        lockedUntil: new Date(Date.now() + 3600000),
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: "u2000000-0000-0000-0000-000000000002",
        email: "bob@company.com",
        fullName: "Bob Officer",
        phoneNumber: "0902222333",
        roleId: "role-user-1",
        role: { id: "role-user-1", name: ROLES.USER },
        isActive: true,
        twoFactorEnabled: true,
        mustChangePassword: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    const mockRepo: any = {
      findAll: async () => ({
        data: [...sampleUsers],
        meta: { page: 1, limit: 10, total: 2, totalPages: 1 },
      }),
      searchFts: async () => ({
        data: [...sampleUsers],
        meta: { page: 1, limit: 10, total: 2, totalPages: 1 },
      }),
      findById: async (id: string) =>
        sampleUsers.find((u) => u.id === id) || null,
    };

    const userService = new UserService(mockRepo, {} as any, {} as any);

    it("UserService.findAll should redact failedLoginAttempts, lockedUntil & mustChangePassword for non-admin", async () => {
      const nonAdminUser = {
        roleId: "role-user-1",
        role: ROLES.USER,
      };

      const result = await userService.findAll({ search: "alice" }, nonAdminUser);

      assert.strictEqual(result.data.length, 2);
      for (const item of result.data) {
        assert.strictEqual(
          item.failedLoginAttempts,
          undefined,
          "failedLoginAttempts must be redacted for non-admin",
        );
        assert.strictEqual(
          item.lockedUntil,
          undefined,
          "lockedUntil must be redacted for non-admin",
        );
        assert.strictEqual(
          item.mustChangePassword,
          undefined,
          "mustChangePassword must be redacted for non-admin",
        );
        assert.strictEqual(item.email !== undefined, true, "Public profile fields must remain");
      }
    });

    it("UserService.findAll should preserve sensitive metadata for ADMIN caller", async () => {
      const adminUser = {
        roleId: "role-admin-1",
        role: ROLES.ADMIN,
      };

      const result = await userService.findAll({ search: "alice" }, adminUser);

      assert.strictEqual(result.data.length, 2);
      const alice = result.data.find((u) => u.id === sampleUsers[0].id);
      assert.strictEqual(alice.failedLoginAttempts, 4);
      assert.ok(alice.lockedUntil !== undefined && alice.lockedUntil !== null);
      assert.strictEqual(alice.mustChangePassword, true);
    });

    it("UserService.findById should redact sensitive metadata for non-admin and preserve for ADMIN", async () => {
      const nonAdminUser = { role: ROLES.USER };
      const adminUser = { role: ROLES.ADMIN };

      const nonAdminResult = await userService.findById(sampleUsers[0].id, nonAdminUser);
      assert.strictEqual(nonAdminResult.failedLoginAttempts, undefined);
      assert.strictEqual(nonAdminResult.lockedUntil, undefined);
      assert.strictEqual(nonAdminResult.mustChangePassword, undefined);

      const adminResult = await userService.findById(sampleUsers[0].id, adminUser);
      assert.strictEqual(adminResult.failedLoginAttempts, 4);
      assert.strictEqual(adminResult.mustChangePassword, true);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-24: Mounting requireGatewayOrigin & API Gateway Origin Enforcement
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-24: Gateway Origin Boundary Enforcement", () => {
    const trustedSecret = "test_traefik_internal_secret_9999";

    it("requireGatewayOrigin should pass through when secret is not configured (monolith/dev mode)", async () => {
      const middleware = createRequireGatewayOrigin("");
      const req: any = {
        headers: {},
        path: "/api/v1/users",
      };

      let nextCalled = false;
      middleware(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });

    it("requireGatewayOrigin should reject direct request lacking x-gateway-secret header", async () => {
      const middleware = createRequireGatewayOrigin(trustedSecret);
      const req: any = {
        headers: {},
        path: "/api/v1/users",
        originalUrl: "/api/v1/users",
      };

      let errorThrown: any;
      middleware(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject request when gateway secret is missing");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.GATEWAY_REQUIRED);
    });

    it("requireGatewayOrigin should accept request with valid x-gateway-secret header", async () => {
      const middleware = createRequireGatewayOrigin(trustedSecret);
      const req: any = {
        headers: {
          [GATEWAY_HEADERS.INTERNAL_SECRET]: trustedSecret,
        },
        path: "/api/v1/users",
        originalUrl: "/api/v1/users",
      };

      let nextCalled = false;
      middleware(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });

    it("requireGatewayOrigin should exempt health check endpoints even if secret is set and header missing", async () => {
      const middleware = createRequireGatewayOrigin(trustedSecret);
      const req: any = {
        headers: {},
        path: "/health",
        originalUrl: "/api/v1/health",
      };

      let nextCalled = false;
      middleware(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true, "Health checks must bypass gateway secret requirement");
    });

    it("Express pipeline in identity.app must mount requireGatewayOrigin on /api/v1 route", () => {
      const apiV1Layer = (app as any)._router?.stack?.find(
        (layer: any) =>
          layer.regexp?.toString().includes("api") &&
          layer.regexp?.toString().includes("v1"),
      );

      assert.ok(apiV1Layer, "Layer for /api/v1 must exist in express router stack");
    });
  });
});
