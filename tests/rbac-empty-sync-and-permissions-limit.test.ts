import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import {
  PERMISSIONS,
  MAX_PERMISSION_LIST_LIMIT,
} from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../src/common/helpers/pagination.helper";
import {
  assignPermissionsSchema,
  permissionQuerySchema,
} from "../src/modules/rbac/rbac.validation";
import { RbacRepository } from "../src/modules/rbac/rbac.repository";
import { RbacService } from "../src/modules/rbac/rbac.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { swaggerSpec } from "../src/config/swagger.config";

describe("Issue #5: RBAC Empty Sync (min(0)) & Permissions Catalog Limit", () => {
  const permReadId = "018f0000-0000-7000-8000-000000000101";
  const permAssignId = "018f0000-0000-7000-8000-000000000102";
  const permConfigId = "018f0000-0000-7000-8000-000000000103";

  const adminRoleId = "018f0000-0000-7000-8000-000000000201";
  const operatorRoleId = "018f0000-0000-7000-8000-000000000202";
  const customRoleId = "018f0000-0000-7000-8000-000000000203";

  const adminUserId = "018f0000-0000-7000-8000-000000000301";
  const operatorUserId = "018f0000-0000-7000-8000-000000000302";

  describe("1. Zod Validation Schemas", () => {
    it("assignPermissionsSchema should accept empty array [] and valid UUID arrays", () => {
      const emptyParsed = assignPermissionsSchema.parse({ permissionIds: [] });
      assert.deepStrictEqual(emptyParsed.permissionIds, []);

      const validParsed = assignPermissionsSchema.parse({
        permissionIds: [permReadId, permConfigId],
      });
      assert.deepStrictEqual(validParsed.permissionIds, [
        permReadId,
        permConfigId,
      ]);
    });

    it("assignPermissionsSchema should reject non-UUID elements and non-array values", () => {
      assert.throws(() =>
        assignPermissionsSchema.parse({ permissionIds: ["not-a-uuid"] }),
      );
      assert.throws(() =>
        assignPermissionsSchema.parse({ permissionIds: permReadId }),
      );
      assert.throws(() => assignPermissionsSchema.parse({}));
    });

    it("permissionQuerySchema should accept empty query and limit up to MAX_PERMISSION_LIST_LIMIT", () => {
      const empty = permissionQuerySchema.parse({});
      assert.strictEqual(empty.page, undefined);
      assert.strictEqual(empty.limit, undefined);
      assert.strictEqual(empty.resource, undefined);

      const limit200 = permissionQuerySchema.parse({
        page: "1",
        limit: "200",
        resource: "ppe_site",
      });
      assert.strictEqual(limit200.page, 1);
      assert.strictEqual(limit200.limit, 200);
      assert.strictEqual(limit200.resource, "ppe_site");

      const limitMax = permissionQuerySchema.parse({
        limit: String(MAX_PERMISSION_LIST_LIMIT),
      });
      assert.strictEqual(limitMax.limit, MAX_PERMISSION_LIST_LIMIT);
    });

    it("permissionQuerySchema should reject limit exceeding MAX_PERMISSION_LIST_LIMIT or <= 0", () => {
      assert.throws(() =>
        permissionQuerySchema.parse({
          limit: String(MAX_PERMISSION_LIST_LIMIT + 1),
        }),
      );
      assert.throws(() => permissionQuerySchema.parse({ limit: "0" }));
      assert.throws(() => permissionQuerySchema.parse({ limit: "-5" }));
    });
  });

  describe("2. Pagination Helper maxLimit Support", () => {
    it("should keep default 100 clamp when maxLimit is omitted", () => {
      const skipRes = calculatePaginationSkip(1, 200);
      assert.strictEqual(skipRes.limit, 100);
      assert.strictEqual(skipRes.take, 100);

      const metaRes = formatPaginationMeta(1, 200, 250);
      assert.strictEqual(metaRes.limit, 100);
      assert.strictEqual(metaRes.totalPages, 3);
    });

    it("should allow higher limit up to MAX_PERMISSION_LIST_LIMIT when maxLimit is provided", () => {
      const skip200 = calculatePaginationSkip(
        1,
        200,
        50,
        MAX_PERMISSION_LIST_LIMIT,
      );
      assert.strictEqual(skip200.limit, 200);
      assert.strictEqual(skip200.take, 200);
      assert.strictEqual(skip200.skip, 0);

      const skipMax = calculatePaginationSkip(
        1,
        MAX_PERMISSION_LIST_LIMIT,
        50,
        MAX_PERMISSION_LIST_LIMIT,
      );
      assert.strictEqual(skipMax.limit, MAX_PERMISSION_LIST_LIMIT);

      const skipClamped = calculatePaginationSkip(
        2,
        MAX_PERMISSION_LIST_LIMIT + 100,
        50,
        MAX_PERMISSION_LIST_LIMIT,
      );
      assert.strictEqual(skipClamped.limit, MAX_PERMISSION_LIST_LIMIT);
      assert.strictEqual(skipClamped.skip, MAX_PERMISSION_LIST_LIMIT);

      const meta200 = formatPaginationMeta(
        1,
        200,
        250,
        MAX_PERMISSION_LIST_LIMIT,
      );
      assert.strictEqual(meta200.limit, 200);
      assert.strictEqual(meta200.totalPages, 2);
    });
  });

  describe("3. RbacRepository.findAllPermissions", () => {
    it("should return all permissions without take: 100 truncation when unpaginated", async () => {
      let capturedArgs: any = null;
      const mockPerms = Array.from({ length: 120 }, (_, i) => ({
        id: `perm-${i}`,
        name: `PERM_${i}`,
      }));

      const db = {
        permission: {
          findMany: async (args: any) => {
            capturedArgs = args;
            return mockPerms;
          },
        },
      } as any;

      const repo = new RbacRepository(db);
      const res = await repo.findAllPermissions();

      assert.strictEqual(Array.isArray(res), true);
      assert.strictEqual((res as any[]).length, 120);
      assert.strictEqual(capturedArgs.take, undefined);
      assert.strictEqual(capturedArgs.skip, undefined);
    });

    it("should support paginated queries with limit=200 using MAX_PERMISSION_LIST_LIMIT", async () => {
      let capturedFindManyArgs: any = null;
      const mockPerms = [{ id: permReadId, name: PERMISSIONS.USER_READ }];

      const db = {
        permission: {
          findMany: (args: any) => {
            capturedFindManyArgs = args;
            return { type: "findMany", args };
          },
          count: (args: any) => ({ type: "count", args }),
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [mockPerms, 130];
        },
      } as any;

      const repo = new RbacRepository(db);
      const res = (await repo.findAllPermissions({
        page: 1,
        limit: 200,
      })) as any;

      assert.strictEqual(capturedFindManyArgs.take, 200);
      assert.strictEqual(capturedFindManyArgs.skip, 0);
      assert.deepStrictEqual(res.meta, {
        page: 1,
        limit: 200,
        total: 130,
        totalPages: 1,
      });
    });
  });

  describe("4. RbacService.syncRolePermissions Empty Array & Anti-Lockout", () => {
    let roles: Record<string, any>;
    let users: Record<string, any>;
    let findPermissionsByIdsCalls = 0;
    let auditLogs: any[] = [];
    let rolePermissionAssignPresent = true;
    let rbacService: RbacService;

    const permissionsMap: Record<string, { id: string; name: string }> = {
      [permReadId]: { id: permReadId, name: PERMISSIONS.USER_READ },
      [permAssignId]: {
        id: permAssignId,
        name: PERMISSIONS.ROLE_PERMISSION_ASSIGN,
      },
      [permConfigId]: {
        id: permConfigId,
        name: PERMISSIONS.SYSTEM_CONFIG_MANAGE,
      },
    };

    beforeEach(() => {
      permissionCacheService.clear();
      findPermissionsByIdsCalls = 0;
      auditLogs = [];
      rolePermissionAssignPresent = true;

      (permissionCacheService as any).cache.set(adminRoleId, {
        permissions: new Set([
          PERMISSIONS.USER_READ,
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
          PERMISSIONS.SYSTEM_CONFIG_MANAGE,
        ]),
        expiresAt: Date.now() + 60_000,
      });
      (permissionCacheService as any).cache.set(operatorRoleId, {
        permissions: new Set([
          PERMISSIONS.USER_READ,
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
        ]),
        expiresAt: Date.now() + 60_000,
      });
      (permissionCacheService as any).cache.set(customRoleId, {
        permissions: new Set([PERMISSIONS.USER_READ]),
        expiresAt: Date.now() + 60_000,
      });

      roles = {
        [adminRoleId]: {
          id: adminRoleId,
          name: ROLES.ADMIN,
          isSystem: true,
          permissions: [
            { id: permReadId, name: PERMISSIONS.USER_READ },
            { id: permAssignId, name: PERMISSIONS.ROLE_PERMISSION_ASSIGN },
          ],
        },
        [operatorRoleId]: {
          id: operatorRoleId,
          name: "OPERATOR",
          isSystem: false,
          permissions: [
            { id: permReadId, name: PERMISSIONS.USER_READ },
            { id: permAssignId, name: PERMISSIONS.ROLE_PERMISSION_ASSIGN },
          ],
        },
        [customRoleId]: {
          id: customRoleId,
          name: "CUSTOM_SITE_VIEWER",
          isSystem: false,
          permissions: [{ id: permReadId, name: PERMISSIONS.USER_READ }],
        },
      };

      users = {
        [adminUserId]: {
          id: adminUserId,
          roleId: adminRoleId,
          role: { id: adminRoleId, name: ROLES.ADMIN },
          isActive: true,
        },
        [operatorUserId]: {
          id: operatorUserId,
          roleId: operatorRoleId,
          role: { id: operatorRoleId, name: "OPERATOR" },
          isActive: true,
        },
      };

      const mockRepo: any = {
        findRoleById: async (id: string) => {
          const r = roles[id];
          return r ? { ...r, permissions: [...r.permissions] } : null;
        },
        findPermissionsByIds: async (ids: string[]) => {
          findPermissionsByIdsCalls++;
          return ids.map((id) => permissionsMap[id]).filter(Boolean);
        },
        findPermissionByName: async (name: string) => {
          if (!rolePermissionAssignPresent) return null;
          return (
            Object.values(permissionsMap).find((p) => p.name === name) || null
          );
        },
        syncRolePermissions: async (roleId: string, permissionIds: string[]) => {
          roles[roleId].permissions = permissionIds
            .map((id) => permissionsMap[id])
            .filter(Boolean);
          return roles[roleId];
        },
        createAuditLog: async (entry: any) => {
          auditLogs.push(entry);
        },
        findUserById: async (id: string) => users[id] || null,
      };

      rbacService = new RbacService(mockRepo);
    });

    it("should allow ADMIN to sync empty permissionIds [] on a Custom Role, skip findPermissionsByIds, invalidate cache, and log audit", async () => {
      const updated = await rbacService.syncRolePermissions(customRoleId, [], {
        actorId: adminUserId,
      });

      assert.strictEqual(findPermissionsByIdsCalls, 0);
      assert.deepStrictEqual(updated.permissions, []);
      assert.strictEqual(
        (permissionCacheService as any).cache.has(customRoleId),
        false,
      );
      assert.strictEqual(auditLogs.length, 1);
      assert.strictEqual(auditLogs[0].details.previousCount, 1);
      assert.strictEqual(auditLogs[0].details.newCount, 0);
    });

    it("should allow non-admin with ROLE_PERMISSION_ASSIGN to clear permissions [] of another Custom Role", async () => {
      const updated = await rbacService.syncRolePermissions(customRoleId, [], {
        actorId: operatorUserId,
      });
      assert.deepStrictEqual(updated.permissions, []);
    });

    it("should forbid non-admin from clearing permissions [] on their own role or on ADMIN", async () => {
      await assert.rejects(
        () =>
          rbacService.syncRolePermissions(operatorRoleId, [], {
            actorId: operatorUserId,
          }),
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );

      await assert.rejects(
        () =>
          rbacService.syncRolePermissions(adminRoleId, [], {
            actorId: operatorUserId,
          }),
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });

    it("should reject ADMIN syncing empty permissionIds [] on ADMIN role with 400 Anti-lockout (even if lookup returns null)", async () => {
      await assert.rejects(
        () =>
          rbacService.syncRolePermissions(adminRoleId, [], {
            actorId: adminUserId,
          }),
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );

      rolePermissionAssignPresent = false;
      await assert.rejects(
        () =>
          rbacService.syncRolePermissions(adminRoleId, [], {
            actorId: adminUserId,
          }),
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });
  });

  describe("5. OpenAPI Specification", () => {
    it("should expose updated limit max on GET /rbac/permissions and allow empty array in AssignPermissionsRequest", () => {
      const getPermsOp = swaggerSpec.paths?.["/rbac/permissions"]?.get;
      assert.ok(getPermsOp, "GET /rbac/permissions must exist in OpenAPI spec");

      const limitParam = (getPermsOp.parameters || []).find(
        (p: any) => p.name === "limit",
      );
      assert.ok(limitParam, "limit query param must exist in OpenAPI");
      assert.strictEqual(
        limitParam.schema?.maximum,
        MAX_PERMISSION_LIST_LIMIT,
      );

      const postSyncOp =
        swaggerSpec.paths?.["/rbac/roles/{id}/permissions"]?.post;
      assert.ok(
        postSyncOp,
        "POST /rbac/roles/{id}/permissions must exist in OpenAPI spec",
      );
      assert.ok(postSyncOp.responses?.["400"]);

      const assignSchema =
        swaggerSpec.components?.schemas?.AssignPermissionsRequest;
      assert.ok(assignSchema);
      const minItems = assignSchema.properties?.permissionIds?.minItems;
      assert.ok(
        minItems === undefined || minItems === 0,
        `Expected minItems to be 0 or undefined, got ${minItems}`,
      );
    });
  });

  describe("6. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let dbAvailable = false;
    let accessToken = "";
    let adminRoleIdDb = "";
    let customRoleIdDb = "";
    let tempAdminUserIdDb = "";
    let createdTempAdminRoleId: string | null = null;
    const createdTempPermIds: string[] = [];
    const createdPermissionIdsForRole: string[] = [];

    async function requestJson(
      method: "GET" | "POST",
      path: string,
      body?: unknown,
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${accessToken}`,
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      if (body !== undefined) {
        headers["content-type"] = "application/json";
      }
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();
      return {
        status: res.status,
        body: text ? JSON.parse(text) : null,
      };
    }

    before(async () => {
      try {
        await prisma.$queryRaw`SELECT 1`;
        dbAvailable = true;
      } catch {
        dbAvailable = false;
        return;
      }

      permissionCacheService.clear();

      let adminRole = await prisma.role.findFirst({
        where: { name: ROLES.ADMIN },
      });
      if (!adminRole) {
        adminRole = await prisma.role.create({
          data: {
            name: ROLES.ADMIN,
            description: "Temporary test admin role",
            isSystem: true,
          },
        });
        createdTempAdminRoleId = adminRole.id;
      }
      adminRoleIdDb = adminRole.id;

      const suffix = crypto.randomBytes(4).toString("hex");
      const adminUser = await prisma.user.create({
        data: {
          email: `it-rbac-admin-${suffix}@smartppe.local`,
          fullName: `RBAC Integration Admin ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
        },
      });
      tempAdminUserIdDb = adminUser.id;

      const existingPerms = await prisma.permission.findMany({ take: 2 });
      for (const p of existingPerms) {
        createdPermissionIdsForRole.push(p.id);
      }

      const customRole = await prisma.role.create({
        data: {
          name: `IT_CUSTOM_${suffix.toUpperCase()}`,
          description: "Temporary custom role for Issue #5 test",
          isSystem: false,
          permissions: {
            create: createdPermissionIdsForRole.map((permissionId) => ({
              permissionId,
            })),
          },
        },
      });
      customRoleIdDb = customRole.id;

      const totalExistingPerms = await prisma.permission.count();
      const neededToExceed100 = Math.max(2, 105 - totalExistingPerms);
      for (let i = 0; i < neededToExceed100; i++) {
        const tempPerm = await prisma.permission.create({
          data: {
            name: `IT_PERM_${suffix.toUpperCase()}_${i}`,
            description: "Temp perm for Issue #5 pagination limit test",
            resource: `it_test_${suffix}`,
            action: `action_${i}`,
            isSystem: false,
          },
        });
        createdTempPermIds.push(tempPerm.id);
      }

      accessToken = jwtKeyService.signAccessToken({
        id: adminUser.id,
        email: adminUser.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
          PERMISSIONS.PERMISSION_READ,
          PERMISSIONS.ROLE_READ,
        ],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      server = await new Promise<http.Server>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      if (dbAvailable) {
        if (tempAdminUserIdDb) {
          await prisma.user
            .deleteMany({ where: { id: tempAdminUserIdDb } })
            .catch(() => {});
        }
        if (customRoleIdDb) {
          await prisma.role
            .deleteMany({ where: { id: customRoleIdDb } })
            .catch(() => {});
        }
        if (createdTempPermIds.length > 0) {
          await prisma.permission
            .deleteMany({ where: { id: { in: createdTempPermIds } } })
            .catch(() => {});
        }
        if (createdTempAdminRoleId) {
          await prisma.role
            .deleteMany({ where: { id: createdTempAdminRoleId } })
            .catch(() => {});
        }
      }
      permissionCacheService.clear();
      if (server) {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });
      }
      await prisma.$disconnect().catch(() => {});
    });

    it("POST /api/v1/rbac/roles/:id/permissions with { permissionIds: [] } should clear Custom Role permissions (200)", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson(
        "POST",
        `/api/v1/rbac/roles/${customRoleIdDb}/permissions`,
        { permissionIds: [] },
      );

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.deepStrictEqual(res.body.data.permissions, []);

      const remaining = await prisma.rolePermission.count({
        where: { roleId: customRoleIdDb },
      });
      assert.strictEqual(remaining, 0);
    });

    it("POST /api/v1/rbac/roles/:id/permissions with { permissionIds: [] } on ADMIN should return 400 Anti-lockout", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const beforeCount = await prisma.rolePermission.count({
        where: { roleId: adminRoleIdDb },
      });

      const res = await requestJson(
        "POST",
        `/api/v1/rbac/roles/${adminRoleIdDb}/permissions`,
        { permissionIds: [] },
      );

      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.body.code, ERROR_CODE.VALIDATION_ERROR);

      const afterCount = await prisma.rolePermission.count({
        where: { roleId: adminRoleIdDb },
      });
      assert.strictEqual(afterCount, beforeCount);
    });

    it("GET /api/v1/rbac/permissions should return all >100 permissions unpaginated and support limit=200", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const totalInDb = await prisma.permission.count();
      assert.ok(
        totalInDb > 100,
        `Expected > 100 permissions in DB for truncation test, got ${totalInDb}`,
      );

      const unpaginated = await requestJson("GET", "/api/v1/rbac/permissions");
      assert.strictEqual(unpaginated.status, 200);
      assert.strictEqual(unpaginated.body.success, true);
      assert.strictEqual(unpaginated.body.data.length, totalInDb);

      const paginated = await requestJson(
        "GET",
        "/api/v1/rbac/permissions?page=1&limit=200",
      );
      assert.strictEqual(paginated.status, 200);
      assert.strictEqual(paginated.body.data.length, totalInDb);
      assert.strictEqual(paginated.body.meta.limit, 200);
      assert.strictEqual(paginated.body.meta.total, totalInDb);

      const overLimit = await requestJson(
        "GET",
        `/api/v1/rbac/permissions?limit=${MAX_PERMISSION_LIST_LIMIT + 1}`,
      );
      assert.strictEqual(overLimit.status, 422);
      assert.strictEqual(overLimit.body.code, ERROR_CODE.VALIDATION_ERROR);
    });
  });
});
