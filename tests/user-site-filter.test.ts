import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Prisma } from "@prisma/client";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { findAllUserSchema } from "../src/modules/users/user.validation";
import { UserRepository } from "../src/modules/users/user.repository";
import { UserService } from "../src/modules/users/user.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { ROLES } from "../src/common/constants/role.constant";
import { swaggerSpec } from "../src/config/swagger.config";

describe("Issue #3: GET /api/v1/users siteId & excludeSiteId Filtering", () => {
  const siteIdA = "018f2345-6789-7abc-def0-1234567890ab";
  const siteIdB = "018f2345-6789-7abc-def0-1234567890cd";
  const userId1 = "018f0000-0000-7000-8000-000000000001";
  const roleIdUser = "018f0000-0000-7000-8000-000000000011";
  const roleIdAdmin = "018f0000-0000-7000-8000-000000000012";

  beforeEach(() => {
    permissionCacheService.clear();
    (permissionCacheService as any).cache.set(roleIdUser, {
      permissions: new Set(["USER_READ"]),
      expiresAt: Date.now() + 60_000,
    });
    (permissionCacheService as any).cache.set(roleIdAdmin, {
      permissions: new Set(["ADMIN_ALL"]),
      expiresAt: Date.now() + 60_000,
    });
  });

  describe("1. findAllUserSchema Validation", () => {
    it("should accept empty query with default pagination and undefined site filters", () => {
      const parsed = findAllUserSchema.parse({});
      assert.strictEqual(parsed.page, 1);
      assert.strictEqual(parsed.limit, 20);
      assert.strictEqual(parsed.siteId, undefined);
      assert.strictEqual(parsed.excludeSiteId, undefined);
    });

    it("should accept valid UUID siteId, excludeSiteId, and combined query filters", () => {
      const parsed = findAllUserSchema.parse({
        siteId: siteIdA,
        excludeSiteId: siteIdB,
        search: "nguyen",
        roleName: ROLES.SAFETY_OFFICER,
        isActive: "true",
        page: "2",
        limit: "10",
      });
      assert.strictEqual(parsed.siteId, siteIdA);
      assert.strictEqual(parsed.excludeSiteId, siteIdB);
      assert.strictEqual(parsed.search, "nguyen");
      assert.strictEqual(parsed.roleName, ROLES.SAFETY_OFFICER);
      assert.strictEqual(parsed.isActive, true);
      assert.strictEqual(parsed.page, 2);
      assert.strictEqual(parsed.limit, 10);
    });

    it("should reject invalid non-UUID siteId", () => {
      assert.throws(() => findAllUserSchema.parse({ siteId: "invalid-id" }));
      assert.throws(() => findAllUserSchema.parse({ siteId: "" }));
    });

    it("should reject invalid non-UUID excludeSiteId", () => {
      assert.throws(() =>
        findAllUserSchema.parse({ excludeSiteId: "not-a-uuid" }),
      );
      assert.throws(() => findAllUserSchema.parse({ excludeSiteId: "" }));
    });
  });

  describe("2. UserRepository.findAll Site Filtering", () => {
    function createMockDb(returnedRows: any[] = [], totalCount: number = 0) {
      let capturedFindManyArgs: any = null;
      let capturedCountArgs: any = null;

      const db = {
        user: {
          findMany: (args: any) => {
            capturedFindManyArgs = args;
            return { type: "findMany", args };
          },
          count: (args: any) => {
            capturedCountArgs = args;
            return { type: "count", args };
          },
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [returnedRows, totalCount];
        },
      } as any;

      return {
        db,
        getCaptured: () => ({ capturedFindManyArgs, capturedCountArgs }),
      };
    }

    it("should omit siteIds filters when siteId and excludeSiteId are not provided", async () => {
      const { db, getCaptured } = createMockDb([], 0);
      const repo = new UserRepository(db);

      const res = await repo.findAll({ page: 1, limit: 20 });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.deepStrictEqual(capturedFindManyArgs.where.AND, [
        { deletedAt: null },
      ]);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
      assert.deepStrictEqual(res.meta, {
        total: 0,
        page: 1,
        limit: 20,
        totalPages: 0,
      });
    });

    it("should filter by siteIds: { has: siteId } when siteId is provided", async () => {
      const mockUsers = [
        { id: userId1, email: "officer@ppe.vn", siteIds: [siteIdA] },
      ];
      const { db, getCaptured } = createMockDb(mockUsers, 1);
      const repo = new UserRepository(db);

      const res = await repo.findAll({ siteId: siteIdA, page: 1, limit: 10 });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.deepStrictEqual(capturedFindManyArgs.where.AND, [
        { deletedAt: null },
        { siteIds: { has: siteIdA } },
      ]);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
      assert.strictEqual(res.data.length, 1);
      assert.deepStrictEqual(res.meta, {
        total: 1,
        page: 1,
        limit: 10,
        totalPages: 1,
      });
    });

    it("should filter by NOT: { siteIds: { has: excludeSiteId } } when excludeSiteId is provided", async () => {
      const mockUsers = [
        { id: userId1, email: "other@ppe.vn", siteIds: [siteIdB] },
      ];
      const { db, getCaptured } = createMockDb(mockUsers, 1);
      const repo = new UserRepository(db);

      const res = await repo.findAll({
        excludeSiteId: siteIdA,
        page: 2,
        limit: 5,
      });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.deepStrictEqual(capturedFindManyArgs.where.AND, [
        { deletedAt: null },
        { NOT: { siteIds: { has: siteIdA } } },
      ]);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
      assert.deepStrictEqual(res.meta, {
        total: 1,
        page: 2,
        limit: 5,
        totalPages: 1,
      });
    });

    it("should combine siteId, excludeSiteId, roleName, and isActive identically in findMany and count", async () => {
      const { db, getCaptured } = createMockDb([], 0);
      const repo = new UserRepository(db);

      await repo.findAll({
        siteId: siteIdA,
        excludeSiteId: siteIdB,
        roleName: ROLES.SAFETY_OFFICER,
        isActive: true,
        page: 1,
        limit: 20,
      });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.deepStrictEqual(capturedFindManyArgs.where.AND, [
        { deletedAt: null },
        { isActive: true },
        { role: { name: ROLES.SAFETY_OFFICER } },
        { siteIds: { has: siteIdA } },
        { NOT: { siteIds: { has: siteIdB } } },
      ]);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
    });
  });

  describe("3. UserRepository.searchFts Site Filtering", () => {
    function createMockFtsDb(rawRows: any[] = [], totalCount: number = 0) {
      const capturedSqls: Array<{ sql: string; values: unknown[] }> = [];

      const db = {
        $queryRaw: (stringsOrSql: any, ...args: any[]) => {
          const sqlObj = Array.isArray(stringsOrSql)
            ? Prisma.sql(stringsOrSql as unknown as TemplateStringsArray, ...args)
            : stringsOrSql;
          const entry = {
            sql: String(sqlObj?.sql ?? sqlObj),
            values: Array.isArray(sqlObj?.values) ? sqlObj.values : [],
          };
          capturedSqls.push(entry);
          return entry;
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [rawRows, [{ count: BigInt(totalCount) }]];
        },
      } as any;

      return { db, capturedSqls };
    }

    function createRawUserRow(overrides: Record<string, any> = {}) {
      const now = new Date();
      return {
        id: userId1,
        email: "officer@ppe.vn",
        full_name: "Nguyen Van A",
        avatar_url: null,
        phone_number: "0901234567",
        role_id: roleIdUser,
        role_name: ROLES.SAFETY_OFFICER,
        site_ids: [siteIdA],
        is_active: true,
        two_factor_enabled: false,
        must_change_password: false,
        failed_login_attempts: 0,
        locked_until: null,
        deleted_at: null,
        created_at: now,
        updated_at: now,
        rank: 0.5,
        ...overrides,
      };
    }

    it("should filter by u.site_ids @> ARRAY[siteId]::text[] and map siteIds in searchFts", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      const res = await repo.searchFts({
        search: "Nguyen",
        siteId: siteIdA,
        page: 1,
        limit: 15,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(
          q.sql.includes("u.site_ids @> ARRAY["),
          `Expected site_ids containment check in SQL: ${q.sql}`,
        );
        assert.ok(
          q.values.includes(siteIdA),
          "Expected siteId value to be bound as parameter",
        );
      }
      assert.ok(capturedSqls[0].sql.includes("u.site_ids"));
      assert.deepStrictEqual(res.data[0].siteIds, [siteIdA]);
      assert.deepStrictEqual(res.meta, {
        total: 1,
        page: 1,
        limit: 15,
        totalPages: 1,
      });
    });

    it("should filter by NOT (coalesce(u.site_ids, ARRAY[]::text[]) @> ARRAY[excludeSiteId]::text[]) in searchFts", async () => {
      const { db, capturedSqls } = createMockFtsDb(
        [createRawUserRow({ site_ids: null })],
        1,
      );
      const repo = new UserRepository(db);

      const res = await repo.searchFts({
        search: "Nguyen",
        excludeSiteId: siteIdB,
        page: 1,
        limit: 20,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(
          q.sql.includes(
            "NOT (coalesce(u.site_ids, ARRAY[]::text[]) @> ARRAY[",
          ),
          `Expected excludeSiteId check in SQL: ${q.sql}`,
        );
        assert.ok(
          q.values.includes(siteIdB),
          "Expected excludeSiteId value to be bound as parameter",
        );
      }
      assert.deepStrictEqual(res.data[0].siteIds, []);
    });

    it("should not include site_ids filter clauses when siteId and excludeSiteId are omitted", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      const res = await repo.searchFts({
        search: "Nguyen",
        page: 1,
        limit: 20,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(!q.sql.includes("site_ids @>"));
      }
      assert.deepStrictEqual(res.data[0].siteIds, [siteIdA]);
    });
  });

  describe("4. UserService.findAll Delegation & SEC-23 Redaction", () => {
    it("should forward siteId and excludeSiteId to repository.findAll and redact sensitive fields for non-admin", async () => {
      let receivedQuery: any = null;
      const mockRepo = {
        findAll: async (query: any) => {
          receivedQuery = query;
          return {
            data: [
              {
                id: userId1,
                email: "officer@ppe.vn",
                siteIds: [siteIdA],
                failedLoginAttempts: 3,
                lockedUntil: new Date(),
                mustChangePassword: true,
              },
            ],
            meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
          };
        },
      } as any;

      const service = new UserService(mockRepo, {} as any, {} as any);
      const res = await service.findAll(
        { siteId: siteIdA, excludeSiteId: siteIdB, page: 1, limit: 20 },
        { roleId: roleIdUser, role: ROLES.USER },
      );

      assert.strictEqual(receivedQuery.siteId, siteIdA);
      assert.strictEqual(receivedQuery.excludeSiteId, siteIdB);
      assert.deepStrictEqual(res.data[0].siteIds, [siteIdA]);
      assert.strictEqual(res.data[0].failedLoginAttempts, undefined);
      assert.strictEqual(res.data[0].lockedUntil, undefined);
      assert.strictEqual(res.data[0].mustChangePassword, undefined);
    });

    it("should forward search, siteId and excludeSiteId to repository.searchFts when search is present", async () => {
      let receivedQuery: any = null;
      const mockRepo = {
        searchFts: async (query: any) => {
          receivedQuery = query;
          return {
            data: [
              {
                id: userId1,
                email: "officer@ppe.vn",
                siteIds: [siteIdA],
                failedLoginAttempts: 2,
                lockedUntil: null,
                mustChangePassword: true,
              },
            ],
            meta: { total: 1, page: 1, limit: 10, totalPages: 1 },
          };
        },
      } as any;

      const service = new UserService(mockRepo, {} as any, {} as any);
      const res = await service.findAll(
        {
          search: "officer",
          siteId: siteIdA,
          excludeSiteId: siteIdB,
          page: 1,
          limit: 10,
        },
        { roleId: roleIdUser, role: ROLES.USER },
      );

      assert.strictEqual(receivedQuery.search, "officer");
      assert.strictEqual(receivedQuery.siteId, siteIdA);
      assert.strictEqual(receivedQuery.excludeSiteId, siteIdB);
      assert.deepStrictEqual(res.data[0].siteIds, [siteIdA]);
      assert.strictEqual(res.data[0].failedLoginAttempts, undefined);
      assert.strictEqual(res.data[0].lockedUntil, undefined);
      assert.strictEqual(res.data[0].mustChangePassword, undefined);
    });
  });

  describe("5. OpenAPI Specification", () => {
    it("should expose siteId and excludeSiteId query parameters and siteIds response field on GET /users", () => {
      const getUsersOp = swaggerSpec.paths?.["/users"]?.get;
      assert.ok(getUsersOp, "GET /users operation must exist in OpenAPI spec");

      const params: any[] = getUsersOp.parameters || [];
      const siteIdParam = params.find((p) => p.name === "siteId");
      const excludeSiteIdParam = params.find((p) => p.name === "excludeSiteId");

      assert.ok(siteIdParam, "siteId query parameter must exist in OpenAPI");
      assert.strictEqual(siteIdParam.in, "query");
      assert.strictEqual(siteIdParam.required, false);
      assert.strictEqual(siteIdParam.schema?.type, "string");
      assert.strictEqual(siteIdParam.schema?.format, "uuid");

      assert.ok(
        excludeSiteIdParam,
        "excludeSiteId query parameter must exist in OpenAPI",
      );
      assert.strictEqual(excludeSiteIdParam.in, "query");
      assert.strictEqual(excludeSiteIdParam.required, false);
      assert.strictEqual(excludeSiteIdParam.schema?.type, "string");
      assert.strictEqual(excludeSiteIdParam.schema?.format, "uuid");

      const itemProps =
        getUsersOp.responses?.["200"]?.content?.["application/json"]?.schema
          ?.properties?.data?.items?.properties;
      assert.ok(
        itemProps?.siteIds,
        "GET /users 200 response item schema must include siteIds",
      );
      assert.strictEqual(itemProps.siteIds.type, "array");
      assert.strictEqual(itemProps.siteIds.items?.type, "string");
      assert.strictEqual(itemProps.siteIds.items?.format, "uuid");
    });
  });

  describe("6. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let dbAvailable = false;
    let accessToken = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const liveSiteA = crypto.randomUUID();
    const liveSiteB = crypto.randomUUID();
    const searchToken = `sitefilter${crypto.randomBytes(4).toString("hex")}`;

    let userSiteAOnlyId = "";
    let userBothSitesId = "";
    let userSiteBOnlyId = "";
    let userUnassignedId = "";
    let userDeletedInSiteAId = "";

    async function requestJson(path: string) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${accessToken}`,
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      const res = await fetch(`${baseUrl}${path}`, { method: "GET", headers });
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
        createdTempRoleId = adminRole.id;
      }

      const memberRole =
        (await prisma.role.findFirst({
          where: { name: { in: [ROLES.SAFETY_OFFICER, ROLES.USER] } },
        })) || adminRole;

      const suffix = crypto.randomBytes(4).toString("hex");
      const adminCaller = await prisma.user.create({
        data: {
          email: `it-admin-${suffix}@smartppe.local`,
          fullName: `Admin Caller ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(adminCaller.id);

      const uA = await prisma.user.create({
        data: {
          email: `it-sitea-${suffix}@smartppe.local`,
          fullName: `Nguyen ${searchToken} Alpha`,
          roleId: memberRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [liveSiteA],
        },
      });
      userSiteAOnlyId = uA.id;
      createdUserIds.push(uA.id);

      const uBoth = await prisma.user.create({
        data: {
          email: `it-both-${suffix}@smartppe.local`,
          fullName: `Tran ${searchToken} Both`,
          roleId: memberRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [liveSiteA, liveSiteB],
        },
      });
      userBothSitesId = uBoth.id;
      createdUserIds.push(uBoth.id);

      const uB = await prisma.user.create({
        data: {
          email: `it-siteb-${suffix}@smartppe.local`,
          fullName: `Le ${searchToken} Beta`,
          roleId: memberRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [liveSiteB],
        },
      });
      userSiteBOnlyId = uB.id;
      createdUserIds.push(uB.id);

      const uNone = await prisma.user.create({
        data: {
          email: `it-none-${suffix}@smartppe.local`,
          fullName: `Pham ${searchToken} None`,
          roleId: memberRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      userUnassignedId = uNone.id;
      createdUserIds.push(uNone.id);

      const uDeleted = await prisma.user.create({
        data: {
          email: `it-deleted-${suffix}@smartppe.local`,
          fullName: `Vo ${searchToken} Deleted`,
          roleId: memberRole.id,
          isActive: false,
          deletedAt: new Date(),
          siteIds: [liveSiteA],
        },
      });
      userDeletedInSiteAId = uDeleted.id;
      createdUserIds.push(uDeleted.id);

      accessToken = jwtKeyService.signAccessToken({
        id: adminCaller.id,
        email: adminCaller.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [PERMISSIONS.USER_READ],
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
      if (createdUserIds.length > 0 && dbAvailable) {
        await prisma.user
          .deleteMany({ where: { id: { in: createdUserIds } } })
          .catch(() => {});
      }
      if (createdTempRoleId && dbAvailable) {
        await prisma.role
          .deleteMany({ where: { id: createdTempRoleId } })
          .catch(() => {});
      }
      permissionCacheService.clear();
      if (server) {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });
      }
      await prisma.$disconnect().catch(() => {});
    });

    it("GET /api/v1/users?siteId=<uuid> should return only active non-deleted users assigned to siteA", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson(`/api/v1/users?siteId=${liveSiteA}`);
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);

      const ids = (res.body.data as any[]).map((u) => u.id).sort();
      assert.deepStrictEqual(
        ids,
        [userSiteAOnlyId, userBothSitesId].sort(),
      );
      assert.strictEqual(res.body.meta?.total, 2);
      assert.ok(!ids.includes(userSiteBOnlyId));
      assert.ok(!ids.includes(userUnassignedId));
      assert.ok(!ids.includes(userDeletedInSiteAId));
    });

    it("GET /api/v1/users?siteId=<siteA>&excludeSiteId=<siteB> should return only userSiteAOnly", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson(
        `/api/v1/users?siteId=${liveSiteA}&excludeSiteId=${liveSiteB}`,
      );
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.meta?.total, 1);
      assert.deepStrictEqual(
        (res.body.data as any[]).map((u) => u.id),
        [userSiteAOnlyId],
      );
    });

    it("GET /api/v1/users?siteId=<siteA>&search=<token> should apply siteId filter in live PostgreSQL FTS and populate siteIds", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson(
        `/api/v1/users?siteId=${liveSiteA}&search=${searchToken}`,
      );
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.meta?.total, 2);

      const rows = res.body.data as any[];
      const ids = rows.map((u) => u.id).sort();
      assert.deepStrictEqual(
        ids,
        [userSiteAOnlyId, userBothSitesId].sort(),
      );
      for (const u of rows) {
        assert.ok(Array.isArray(u.siteIds), "FTS row must include siteIds");
        assert.ok(u.siteIds.includes(liveSiteA));
      }
    });

    it("GET /api/v1/users?excludeSiteId=<siteA>&search=<token> should exclude siteA users in live PostgreSQL FTS", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson(
        `/api/v1/users?excludeSiteId=${liveSiteA}&search=${searchToken}`,
      );
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.meta?.total, 2);

      const rows = res.body.data as any[];
      const ids = rows.map((u) => u.id).sort();
      assert.deepStrictEqual(
        ids,
        [userSiteBOnlyId, userUnassignedId].sort(),
      );
      for (const u of rows) {
        assert.ok(Array.isArray(u.siteIds), "FTS row must include siteIds");
        assert.ok(!u.siteIds.includes(liveSiteA));
      }
    });

    it("GET /api/v1/users?siteId=not-a-uuid should return 422 VALIDATION_ERROR", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson("/api/v1/users?siteId=not-a-uuid");
      assert.strictEqual(res.status, 422);
      assert.strictEqual(res.body.code, ERROR_CODE.VALIDATION_ERROR);
    });
  });
});
