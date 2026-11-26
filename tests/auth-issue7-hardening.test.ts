import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { envConfig } from "../src/config/env.config";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { hashToken } from "../src/common/helpers/crypto.helper";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { FEATURE_FLAGS } from "../src/common/constants/system-config.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { systemConfigService } from "../src/modules/system-config/system-config.service";
import { swaggerSpec } from "../src/config/swagger.config";
import authRouter from "../src/modules/auth/auth.route";
import { AuthController } from "../src/modules/auth/auth.controller";
import { AuthService } from "../src/modules/auth/auth.service";
import { AuthRepository } from "../src/modules/auth/auth.repository";
import { updateProfileSchema } from "../src/modules/auth/auth.validation";

describe("Issue #7: 2FA Issuer Branding, Sessions Safety, Password Cookie Clear, Phone Clearing & Social Flag Sync", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  describe("1. 2FA Issuer Branding (Smart PPE Monitoring)", () => {
    it("envConfig.twoFactor.issuer should default to Smart PPE Monitoring instead of TemplateBE", () => {
      assert.strictEqual(envConfig.twoFactor.issuer, "Smart PPE Monitoring");
      assert.notStrictEqual(envConfig.twoFactor.issuer, "TemplateBE");
    });

    it("AuthService.setup2FA should use envConfig.twoFactor.issuer in otpauthUrl", async () => {
      const mockRepo: Partial<AuthRepository> = {
        findById: async (id: string) =>
          ({
            id,
            email: "officer@smartppe.vn",
            twoFactorEnabled: false,
          }) as any,
        savePendingTwoFactorSecret: async () => ({}) as any,
      };
      const service = new AuthService(mockRepo as AuthRepository);
      const res = await service.setup2FA("018f0000-0000-7000-8000-000000000001");
      const expectedIssuer = encodeURIComponent(envConfig.twoFactor.issuer);

      assert.ok(res.otpauthUrl.startsWith(`otpauth://totp/${expectedIssuer}:`));
      assert.ok(res.otpauthUrl.includes(`issuer=${expectedIssuer}`));
      assert.ok(!res.otpauthUrl.includes("TemplateBE"));
    });

    it("OpenAPI /auth/2fa/setup example should not reference TemplateBE", () => {
      const paths = swaggerSpec.paths as Record<string, any>;
      const setupOp = paths["/auth/2fa/setup"]?.post;
      assert.ok(setupOp, "POST /auth/2fa/setup must exist in OpenAPI spec");
      const schemaStr = JSON.stringify(setupOp);
      assert.ok(!schemaStr.includes("TemplateBE"));
      assert.ok(schemaStr.includes("Smart%20PPE%20Monitoring"));
    });
  });

  describe("2. Profile Phone Number Clearing (updateProfileSchema & AuthService.updateProfile)", () => {
    it("updateProfileSchema should accept empty string, whitespace, null, undefined, and 10-11 digits while rejecting invalid strings", () => {
      for (const validPhone of [
        undefined,
        null,
        "",
        "   ",
        "0901234567",
        "01234567890",
      ]) {
        const res = updateProfileSchema.safeParse({ phoneNumber: validPhone });
        assert.strictEqual(
          res.success,
          true,
          `Expected phoneNumber=${JSON.stringify(validPhone)} to pass`,
        );
      }

      for (const invalidPhone of ["12345", "090123456a", "090123456789"]) {
        const res = updateProfileSchema.safeParse({ phoneNumber: invalidPhone });
        assert.strictEqual(
          res.success,
          false,
          `Expected phoneNumber=${JSON.stringify(invalidPhone)} to fail`,
        );
      }
    });

    it("AuthService.updateProfile should normalize empty/whitespace/null phoneNumber to null without calling findByPhone", async () => {
      let findByPhoneCalled = false;
      const updatedPayloads: any[] = [];

      const mockRepo: Partial<AuthRepository> = {
        findById: async (id: string) =>
          ({
            id,
            email: "user@smartppe.vn",
            isActive: true,
          }) as any,
        findByPhone: async () => {
          findByPhoneCalled = true;
          return null;
        },
        updateProfile: async (_id: string, data: any) => {
          updatedPayloads.push(data);
          return {} as any;
        },
      };

      const service = new AuthService(mockRepo as AuthRepository);
      const userId = "018f0000-0000-7000-8000-000000000002";

      await service.updateProfile(userId, { phoneNumber: "" });
      await service.updateProfile(userId, { phoneNumber: "   " });
      await service.updateProfile(userId, { phoneNumber: null });
      await service.updateProfile(userId, { fullName: "Only Name" });

      assert.strictEqual(findByPhoneCalled, false);
      assert.strictEqual(updatedPayloads[0].phoneNumber, null);
      assert.strictEqual(updatedPayloads[1].phoneNumber, null);
      assert.strictEqual(updatedPayloads[2].phoneNumber, null);
      assert.strictEqual("phoneNumber" in updatedPayloads[3], false);
    });
  });

  describe("3. Session Endpoints Safety & Cookie Clearing on Password Change", () => {
    it("AuthController.getSessions should not crash when req.body and req.cookies are undefined", async () => {
      let receivedToken: string | undefined = "sentinel";
      const mockService = {
        getActiveSessions: async (_userId: string, currentToken?: string) => {
          receivedToken = currentToken;
          return [];
        },
      } as unknown as AuthService;

      const controller = new AuthController(mockService);
      let jsonResponse: any = null;
      let nextError: any = null;

      await controller.getSessions(
        {
          user: { id: "u-1" },
          headers: {},
          body: undefined,
          cookies: undefined,
        } as any,
        {
          json: (payload: any) => {
            jsonResponse = payload;
          },
        } as any,
        (err?: any) => {
          nextError = err;
        },
      );

      assert.strictEqual(nextError, null);
      assert.strictEqual(receivedToken, undefined);
      assert.deepStrictEqual(jsonResponse, { success: true, data: [] });
    });

    it("AuthService.revokeAllOtherSessions and AuthRepository.deleteOtherSessions should safely handle missing currentToken", async () => {
      const revokeCalls: Array<{ userId: string; token?: string }> = [];
      const mockRepo: Partial<AuthRepository> = {
        revokeOtherSessions: async (userId: string, token?: string) => {
          revokeCalls.push({ userId, token });
          return { count: 0 };
        },
      };

      const service = new AuthService(mockRepo as AuthRepository);
      await service.revokeAllOtherSessions("u-1", undefined);
      await service.revokeAllOtherSessions("u-1", "   ");
      await service.revokeAllOtherSessions("u-1", "  valid-token  ");

      assert.deepStrictEqual(revokeCalls, [
        { userId: "u-1", token: undefined },
        { userId: "u-1", token: undefined },
        { userId: "u-1", token: "valid-token" },
      ]);

      const repo = new AuthRepository();
      let delegatedArgs: any[] = [];
      repo.revokeOtherSessions = async (userId: string, token?: string) => {
        delegatedArgs = [userId, token];
        return { count: 0 };
      };
      await repo.deleteOtherSessions("u-2", undefined);
      assert.deepStrictEqual(delegatedArgs, ["u-2", undefined]);
    });

    it("AuthController.updatePassword should clear accessToken and refreshToken cookies on success only", async () => {
      const clearedCookies: Array<{ name: string; options: any }> = [];
      let shouldThrow = false;

      const mockService = {
        updatePassword: async () => {
          if (shouldThrow) {
            throw new Error("Invalid old password");
          }
        },
      } as unknown as AuthService;

      const controller = new AuthController(mockService);
      const resMock = {
        clearCookie: (name: string, options: any) => {
          clearedCookies.push({ name, options });
        },
        json: () => {},
      } as any;

      await controller.updatePassword(
        {
          user: { id: "u-1" },
          body: { oldPassword: "Old@1234", newPassword: "New@12345" },
        } as any,
        resMock,
        () => {},
      );

      assert.strictEqual(clearedCookies.length, 2);
      assert.strictEqual(clearedCookies[0].name, "accessToken");
      assert.strictEqual(clearedCookies[1].name, "refreshToken");
      assert.deepStrictEqual(clearedCookies[0].options, {
        httpOnly: true,
        secure: envConfig.nodeEnv === "production",
        sameSite: "lax",
        path: "/",
      });

      clearedCookies.length = 0;
      shouldThrow = true;
      let capturedErr: any = null;
      await controller.updatePassword(
        {
          user: { id: "u-1" },
          body: { oldPassword: "Wrong", newPassword: "New@12345" },
        } as any,
        resMock,
        (err?: any) => {
          capturedErr = err;
        },
      );

      assert.ok(capturedErr);
      assert.strictEqual(clearedCookies.length, 0);
    });
  });

  describe("4. Social Login Feature Flag Sync on Auth Routes", () => {
    it("GET /google/url, POST /google, and POST /social/link must enforce SOCIAL_LOGIN_ENABLED", async () => {
      const originalIsFeatureEnabled = systemConfigService.isFeatureEnabled;
      systemConfigService.isFeatureEnabled = async (key: string) => {
        if (key === FEATURE_FLAGS.SOCIAL_LOGIN_ENABLED) return false;
        return true;
      };

      try {
        const expectedRoutes = [
          { path: "/google/url", method: "get", minStack: 4 },
          { path: "/google", method: "post", minStack: 4 },
          { path: "/social/link", method: "post", minStack: 5 },
        ];

        for (const spec of expectedRoutes) {
          const layer = authRouter.stack.find(
            (l: any) =>
              l.route &&
              l.route.path === spec.path &&
              l.route.methods[spec.method],
          );
          assert.ok(
            layer,
            `Route ${spec.method.toUpperCase()} ${spec.path} must exist`,
          );
          assert.ok(
            layer.route.stack.length >= spec.minStack,
            `Route ${spec.method.toUpperCase()} ${spec.path} missing middleware`,
          );

          let rejectedErr: any = null;
          for (const handlerLayer of layer.route.stack) {
            if (handlerLayer.handle.length === 3) {
              // Run middleware probes only up to the featureFlag middleware
              const candidateErr = await new Promise<any>((resolve) => {
                let settled = false;
                const done = (err?: any) => {
                  if (!settled) {
                    settled = true;
                    resolve(err || null);
                  }
                };
                try {
                  const res = handlerLayer.handle(
                    { headers: {}, query: {}, body: {}, ip: "127.0.0.1" } as any,
                    {} as any,
                    done,
                  );
                  if (res && typeof res.catch === "function") {
                    res.catch(done);
                  }
                } catch (e) {
                  done(e);
                }
              });

              if (candidateErr?.code === ERROR_CODE.FEATURE_DISABLED) {
                rejectedErr = candidateErr;
                break;
              }
            }
          }

          assert.ok(
            rejectedErr,
            `${spec.method.toUpperCase()} ${spec.path} must reject with FEATURE_DISABLED`,
          );
          assert.strictEqual(rejectedErr.statusCode, 403);
          assert.strictEqual(rejectedErr.code, ERROR_CODE.FEATURE_DISABLED);
        }

        // GET /social and DELETE /social/:provider should NOT have featureFlag blocking them
        const getSocial = authRouter.stack.find(
          (l: any) => l.route && l.route.path === "/social" && l.route.methods.get,
        );
        const deleteSocial = authRouter.stack.find(
          (l: any) =>
            l.route &&
            l.route.path === "/social/:provider" &&
            l.route.methods.delete,
        );
        assert.strictEqual(getSocial?.route.stack.length, 2);
        assert.strictEqual(deleteSocial?.route.stack.length, 4);
      } finally {
        systemConfigService.isFeatureEnabled = originalIsFeatureEnabled;
      }
    });
  });

  describe("5. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];

    let user1Id = "";
    let user1Token = "";
    let user2Id = "";
    let user2Token = "";
    const initialPassword = "Issue7@Password1";
    const nextPassword = "Issue7@Password2";

    const suffix = crypto.randomBytes(4).toString("hex");

    async function requestApi(
      method: "GET" | "PUT" | "POST" | "DELETE",
      path: string,
      options: { token?: string; body?: unknown; cookie?: string } = {},
    ) {
      const headers: Record<string, string> = {};
      if (options.token) {
        headers.authorization = `Bearer ${options.token}`;
      }
      if (options.cookie) {
        headers.cookie = options.cookie;
      }
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      if (options.body !== undefined) {
        headers["content-type"] = "application/json";
      }

      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      });

      const text = await res.text();
      return {
        status: res.status,
        headers: res.headers,
        setCookies:
          typeof (res.headers as any).getSetCookie === "function"
            ? ((res.headers as any).getSetCookie() as string[])
            : res.headers.get("set-cookie")
              ? [res.headers.get("set-cookie") as string]
              : [],
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

      let userRole = await prisma.role.findFirst({
        where: { name: ROLES.USER },
      });
      if (!userRole) {
        userRole = await prisma.role.create({
          data: {
            name: ROLES.USER,
            description: "Temporary test user role",
            isSystem: true,
          },
        });
        createdTempRoleId = userRole.id;
      }

      const passwordHash = await bcrypt.hash(initialPassword, 10);

      const u1 = await prisma.user.create({
        data: {
          email: `it-issue7-u1-${suffix}@smartppe.local`,
          password: passwordHash,
          fullName: `Issue7 User1 ${suffix}`,
          roleId: userRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      user1Id = u1.id;
      createdUserIds.push(u1.id);

      const u2 = await prisma.user.create({
        data: {
          email: `it-issue7-u2-${suffix}@smartppe.local`,
          password: passwordHash,
          fullName: `Issue7 User2 ${suffix}`,
          roleId: userRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      user2Id = u2.id;
      createdUserIds.push(u2.id);

      user1Token = jwtKeyService.signAccessToken({
        id: u1.id,
        email: u1.email!,
        role: ROLES.USER,
        roleId: userRole.id,
        permissions: [],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      user2Token = jwtKeyService.signAccessToken({
        id: u2.id,
        email: u2.email!,
        role: ROLES.USER,
        roleId: userRole.id,
        permissions: [],
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
      try {
        if (createdUserIds.length > 0 && dbAvailable) {
          await prisma.refreshToken
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.user
            .deleteMany({ where: { id: { in: createdUserIds } } })
            .catch(() => {});
        }
        if (createdTempRoleId && dbAvailable) {
          await prisma.role
            .deleteMany({ where: { id: createdTempRoleId } })
            .catch(() => {});
        }
      } finally {
        permissionCacheService.clear();
        if (server) {
          await new Promise<void>((resolve) => {
            server!.close(() => resolve());
          });
        }
        await prisma.$disconnect().catch(() => {});
      }
    });

    it("GET /api/v1/auth/sessions with Bearer token only should return active sessions and exclude expired ones", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const activeOld = await prisma.refreshToken.create({
        data: {
          userId: user1Id,
          token: hashToken(`active-old-${suffix}`),
          userAgent: "Mozilla/5.0 Chrome/120.0",
          ipAddress: "127.0.0.1",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
          createdAt: new Date(Date.now() - 10_000),
        },
      });
      const activeNew = await prisma.refreshToken.create({
        data: {
          userId: user1Id,
          token: hashToken(`active-new-${suffix}`),
          userAgent: "Mozilla/5.0 Firefox/121.0",
          ipAddress: "127.0.0.2",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
          createdAt: new Date(Date.now() - 1_000),
        },
      });
      const expiredSession = await prisma.refreshToken.create({
        data: {
          userId: user1Id,
          token: hashToken(`expired-${suffix}`),
          userAgent: "ExpiredBrowser",
          ipAddress: "127.0.0.3",
          expiresAt: new Date(Date.now() - 60 * 1000),
        },
      });

      const res = await requestApi("GET", "/api/v1/auth/sessions", {
        token: user1Token,
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);

      const returnedIds = (res.body.data as any[]).map((s) => s.id);
      assert.ok(returnedIds.includes(activeNew.id));
      assert.ok(returnedIds.includes(activeOld.id));
      assert.ok(!returnedIds.includes(expiredSession.id));

      // DELETE /api/v1/auth/sessions without refreshToken keeps latest active session and removes older ones
      const delRes = await requestApi("DELETE", "/api/v1/auth/sessions", {
        token: user1Token,
        body: {},
      });
      assert.strictEqual(delRes.status, 200);
      assert.strictEqual(delRes.body.success, true);

      const remaining = await prisma.refreshToken.findMany({
        where: { userId: user1Id },
      });
      assert.strictEqual(remaining.length, 1);
      assert.strictEqual(remaining[0].id, activeNew.id);
    });

    it("PUT /api/v1/auth/profile should allow clearing phoneNumber to null with empty string or null", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const phone1 = `09${Math.floor(10000000 + Math.random() * 89999999)}`;
      const phone2 = `08${Math.floor(10000000 + Math.random() * 89999999)}`;

      const set1 = await requestApi("PUT", "/api/v1/auth/profile", {
        token: user1Token,
        body: { phoneNumber: phone1 },
      });
      assert.strictEqual(set1.status, 200);
      let dbU1 = await prisma.user.findUnique({ where: { id: user1Id } });
      assert.strictEqual(dbU1?.phoneNumber, phone1);

      const clearEmpty = await requestApi("PUT", "/api/v1/auth/profile", {
        token: user1Token,
        body: { phoneNumber: "" },
      });
      assert.strictEqual(clearEmpty.status, 200);
      dbU1 = await prisma.user.findUnique({ where: { id: user1Id } });
      assert.strictEqual(dbU1?.phoneNumber, null);

      const set2 = await requestApi("PUT", "/api/v1/auth/profile", {
        token: user2Token,
        body: { phoneNumber: phone2 },
      });
      assert.strictEqual(set2.status, 200);

      const clearNull = await requestApi("PUT", "/api/v1/auth/profile", {
        token: user2Token,
        body: { phoneNumber: null },
      });
      assert.strictEqual(clearNull.status, 200);
      const dbU2 = await prisma.user.findUnique({ where: { id: user2Id } });
      assert.strictEqual(dbU2?.phoneNumber, null);
    });

    it("PUT /api/v1/auth/password should clear httpOnly cookies and revoke refresh tokens", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestApi("PUT", "/api/v1/auth/password", {
        token: user1Token,
        cookie: `accessToken=${user1Token}; refreshToken=old`,
        body: {
          oldPassword: initialPassword,
          newPassword: nextPassword,
        },
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);

      const cookieHeaderJoined = res.setCookies.join("; ");
      assert.ok(
        res.setCookies.some((c) => c.startsWith("accessToken=;")),
        `Expected accessToken clear cookie, got: ${cookieHeaderJoined}`,
      );
      assert.ok(
        res.setCookies.some((c) => c.startsWith("refreshToken=;")),
        `Expected refreshToken clear cookie, got: ${cookieHeaderJoined}`,
      );

      const remaining = await prisma.refreshToken.findMany({
        where: { userId: user1Id },
      });
      assert.strictEqual(remaining.length, 0);
    });

    it("GET /api/v1/auth/google/url and POST /api/v1/auth/social/link should return 403 FEATURE_DISABLED when SOCIAL_LOGIN_ENABLED is false", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const originalIsFeatureEnabled = systemConfigService.isFeatureEnabled;
      systemConfigService.isFeatureEnabled = async (key: string) => {
        if (key === FEATURE_FLAGS.SOCIAL_LOGIN_ENABLED) return false;
        return true;
      };

      try {
        const googleUrlRes = await requestApi(
          "GET",
          "/api/v1/auth/google/url",
        );
        assert.strictEqual(googleUrlRes.status, 403);
        assert.strictEqual(googleUrlRes.body.code, ERROR_CODE.FEATURE_DISABLED);

        const linkRes = await requestApi("POST", "/api/v1/auth/social/link", {
          token: user2Token,
          body: { provider: "GOOGLE", idToken: "dummy-token" },
        });
        assert.strictEqual(linkRes.status, 403);
        assert.strictEqual(linkRes.body.code, ERROR_CODE.FEATURE_DISABLED);
      } finally {
        systemConfigService.isFeatureEnabled = originalIsFeatureEnabled;
      }
    });

    it("POST /api/v1/auth/2fa/setup should return otpauthUrl with Smart PPE Monitoring issuer", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestApi("POST", "/api/v1/auth/2fa/setup", {
        token: user2Token,
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      const otpauthUrl: string = res.body.data.otpauthUrl;
      assert.ok(otpauthUrl.includes("Smart%20PPE%20Monitoring"));
      assert.ok(!otpauthUrl.includes("TemplateBE"));
    });
  });
});
