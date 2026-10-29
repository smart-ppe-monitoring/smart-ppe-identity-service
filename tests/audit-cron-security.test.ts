import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { triggerCronJobSchema } from "../src/modules/cron/cron.validation";
import { CronService } from "../src/modules/cron/cron.service";
import { CronRepository } from "../src/modules/cron/cron.repository";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { createVerifyJwtLocally } from "../src/middlewares/verify-jwt-locally.middleware";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import auditRouter from "../src/modules/audit/audit.route";

describe("SEC-16, SEC-17 & SEC-18 Security Remediation Test Suite", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-17: Export Audit Logs Permission Requirement
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-17: Export Audit Logs Permission Guard", () => {
    it("should reject users with only AUDIT_LOG_READ from exporting audit logs with 403 FORBIDDEN", async () => {
      const exportRoute = auditRouter.stack.find(
        (layer: any) =>
          layer.route &&
          layer.route.path === "/export" &&
          layer.route.methods.get,
      );

      assert.ok(exportRoute, "Route GET /export must exist in auditRouter");

      // Giả lập user chỉ có quyền AUDIT_LOG_READ (không có AUDIT_LOG_EXPORT)
      const req: any = {
        user: {
          id: "u-read-only-1",
          email: "readonly@company.local",
          role: ROLES.OPERATOR,
          roleId: "r-read-only-1",
        },
      };

      // Mock active user state in cache
      (permissionCacheService as any).userCache.set("u-read-only-1", {
        user: {
          id: "u-read-only-1",
          isActive: true,
          deletedAt: null,
          roleId: "r-read-only-1",
          roleName: ROLES.OPERATOR,
        },
        expiresAt: Date.now() + 60000,
      });

      (permissionCacheService as any).cache.set("r-read-only-1", {
        permissions: new Set([PERMISSIONS.AUDIT_LOG_READ]),
        expiresAt: Date.now() + 60000,
      });

      // Lấy middleware permission từ route stack (middleware thứ 2 sau authMiddleware)
      const permMiddleware = exportRoute.route.stack[1].handle;

      let errorThrown: any;
      await permMiddleware(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject read-only user without AUDIT_LOG_EXPORT");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.FORBIDDEN);
    });

    it("should allow users with AUDIT_LOG_EXPORT permission", async () => {
      const exportRoute = auditRouter.stack.find(
        (layer: any) =>
          layer.route &&
          layer.route.path === "/export" &&
          layer.route.methods.get,
      );

      const req: any = {
        user: {
          id: "u-auditor-1",
          email: "auditor@company.local",
          role: "AUDITOR",
          roleId: "r-auditor-1",
        },
      };

      (permissionCacheService as any).userCache.set("u-auditor-1", {
        user: {
          id: "u-auditor-1",
          isActive: true,
          deletedAt: null,
          roleId: "r-auditor-1",
          roleName: "AUDITOR",
        },
        expiresAt: Date.now() + 60000,
      });

      (permissionCacheService as any).cache.set("r-auditor-1", {
        permissions: new Set([
          PERMISSIONS.AUDIT_LOG_READ,
          PERMISSIONS.AUDIT_LOG_EXPORT,
        ]),
        expiresAt: Date.now() + 60000,
      });

      const permMiddleware = exportRoute.route.stack[1].handle;

      let nextCalled = false;
      let errorThrown: any;
      await permMiddleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.strictEqual(errorThrown, undefined);
      assert.strictEqual(nextCalled, true);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-18: Cron Audit Log Retention Lower Bound & Evidentiary Protection
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-18: Cron Audit Log Retention Lower Bound Guard", () => {
    it("triggerCronJobSchema should reject retentionDays < 30", () => {
      // 0 days (purge today's logs)
      const res0 = triggerCronJobSchema.safeParse({
        params: { retentionDays: 0 },
      });
      assert.strictEqual(res0.success, false);

      // Negative days
      const resNeg = triggerCronJobSchema.safeParse({
        params: { retentionDays: -10 },
      });
      assert.strictEqual(resNeg.success, false);

      // 29 days
      const res29 = triggerCronJobSchema.safeParse({
        params: { retentionDays: 29 },
      });
      assert.strictEqual(res29.success, false);
    });

    it("triggerCronJobSchema should reject retentionDays > 3650 (10 years)", () => {
      const resExcess = triggerCronJobSchema.safeParse({
        params: { retentionDays: 3651 },
      });
      assert.strictEqual(resExcess.success, false);
    });

    it("triggerCronJobSchema should accept valid retentionDays >= 30", () => {
      const res30 = triggerCronJobSchema.safeParse({
        params: { retentionDays: 30 },
      });
      assert.strictEqual(res30.success, true);

      const res90 = triggerCronJobSchema.safeParse({
        params: { retentionDays: 90 },
      });
      assert.strictEqual(res90.success, true);
    });

    it("CronService.executeAuditLogCleanup should reject retentionDays < 30 with 400 VALIDATION_ERROR", async () => {
      const mockRepo: Partial<CronRepository> = {
        deleteAuditLogsOlderThan: async () => 0,
        createAuditLog: async () => ({}) as any,
      };
      const service = new CronService(mockRepo as any);

      await assert.rejects(
        async () => service.executeAuditLogCleanup(0),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );

      await assert.rejects(
        async () => service.executeAuditLogCleanup(15),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });

    it("CronRepository.deleteAuditLogsOlderThan should throw error if cutoffDate is within 30 days", async () => {
      const repo = new CronRepository();
      // Cutoff date is today/now (violating 30-day retention)
      const invalidCutoff = new Date();

      await assert.rejects(
        async () => repo.deleteAuditLogsOlderThan(invalidCutoff),
        /cutoffDate không được nằm trong phạm vi 30 ngày gần nhất/,
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-16: mustChangePassword Claim & Middleware Enforcement
  // ──────────────────────────────────────────────────────────────────────────
  describe("SEC-16: mustChangePassword Token Claim & Middleware Guard", () => {
    const userId = "u1000000-0000-0000-0000-000000000001";
    const roleId = "r1000000-0000-0000-0000-000000000001";

    it("authMiddleware should block access to other endpoints (e.g. /api/v1/users) when mustChangePassword is true", async () => {
      const token = jwtKeyService.signAccessToken({
        id: userId,
        email: "temp-pass@company.local",
        role: ROLES.USER,
        roleId,
        mustChangePassword: true,
        purpose: "ACCESS",
      });

      // Mock user state in cache as active but mustChangePassword = true
      (permissionCacheService as any).userCache.set(userId, {
        user: {
          id: userId,
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: ROLES.USER,
          mustChangePassword: true,
        },
        expiresAt: Date.now() + 60000,
      });

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
        baseUrl: "/api/v1",
        path: "/users",
        method: "GET",
        query: {},
      };

      let errorThrown: any;
      await authMiddleware(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject request when mustChangePassword is true");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.FORBIDDEN);
      assert.match(
        errorThrown.message,
        /Bạn bắt buộc phải đổi mật khẩu trước khi thực hiện các thao tác khác/,
      );
    });

    it("authMiddleware should allow access to PUT /api/v1/auth/password even when mustChangePassword is true", async () => {
      const token = jwtKeyService.signAccessToken({
        id: userId,
        email: "temp-pass@company.local",
        role: ROLES.USER,
        roleId,
        mustChangePassword: true,
        purpose: "ACCESS",
      });

      (permissionCacheService as any).userCache.set(userId, {
        user: {
          id: userId,
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: ROLES.USER,
          mustChangePassword: true,
        },
        expiresAt: Date.now() + 60000,
      });

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
        baseUrl: "/api/v1",
        path: "/auth/password",
        method: "PUT",
        query: {},
      };

      let nextCalled = false;
      let errorThrown: any;
      await authMiddleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.strictEqual(errorThrown, undefined);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(req.user.mustChangePassword, true);
    });

    it("verifyJwtLocally (satellite services) should reject tokens with mustChangePassword: true", async () => {
      const token = jwtKeyService.signAccessToken({
        id: userId,
        email: "temp-pass@company.local",
        role: ROLES.USER,
        roleId,
        mustChangePassword: true,
        purpose: "ACCESS",
      });

      const middleware = createVerifyJwtLocally({
        publicKey: jwtKeyService.getPublicKeyPem(),
      });

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
        baseUrl: "/api/v1",
        path: "/sites",
        method: "GET",
      };

      let errorThrown: any;
      await middleware(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Satellite service must reject mustChangePassword token");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.FORBIDDEN);
    });
  });
});
