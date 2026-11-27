import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { envConfig } from "../src/config/env.config";
import { jwtConfig } from "../src/config/jwt.config";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { hashToken, encryptSecret } from "../src/common/helpers/crypto.helper";
import { generateTotpCode } from "../src/common/helpers/totp.helper";
import {
  generateGoogleAuthUrl,
  exchangeGoogleCode,
} from "../src/common/helpers/google-auth.helper";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { authRateLimitMiddleware } from "../src/middlewares/rate-limit.middleware";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { systemConfigService } from "../src/modules/system-config/system-config.service";
import { swaggerSpec } from "../src/config/swagger.config";
import authRouter from "../src/modules/auth/auth.route";
import { AuthController } from "../src/modules/auth/auth.controller";
import { AuthService } from "../src/modules/auth/auth.service";
import { AuthRepository } from "../src/modules/auth/auth.repository";
import { clearConsumedTempTokens } from "../src/modules/auth/services/auth-2fa.service";
import {
  googleAuthUrlQuerySchema,
  googleLoginSchema,
  linkSocialAccountSchema,
} from "../src/modules/auth/auth.validation";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { FEATURE_FLAGS } from "../src/common/constants/system-config.constant";
import { VERIFICATION_TOKEN_TYPE } from "../src/common/constants/verification-token.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";

describe("Issue #12: Google OAuth Bypass, mustChangePassword Deadlock, 2FA Verify, User Enumeration & Auth Hardening", () => {
  const originalFetch = globalThis.fetch;
  const originalGoogleClientId = envConfig.google.clientId;
  const originalGoogleClientSecret = envConfig.google.clientSecret;

  beforeEach(() => {
    permissionCacheService.clear();
    clearConsumedTempTokens();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    (envConfig.google as any).clientId = originalGoogleClientId;
    (envConfig.google as any).clientSecret = originalGoogleClientSecret;
  });

  describe("AC #1: authMiddleware mustChangePassword allowlist", () => {
    const roleId = "a0000000-0000-0000-0000-000000000012";
    const userId = "01900000-0000-7000-8000-000000000012";

    async function invokeAuthMiddleware(method: string, originalUrl: string) {
      const token = jwtKeyService.signAccessToken({
        id: userId,
        email: "mcp@smartppe.local",
        role: ROLES.USER,
        roleId,
        permissions: [],
        mustChangePassword: true,
        purpose: JWT_PURPOSE.ACCESS,
      });

      (permissionCacheService as any).userCache.set(userId, {
        user: {
          id: userId,
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: ROLES.USER,
          siteIds: [],
          mustChangePassword: true,
        },
        expiresAt: Date.now() + 60_000,
      });

      const req: any = {
        method,
        path: originalUrl,
        originalUrl,
        headers: { authorization: `Bearer ${token}` },
      };

      let passedError: any = null;
      await new Promise<void>((resolve) => {
        authMiddleware(req, {} as any, (err?: any) => {
          passedError = err || null;
          resolve();
        });
      });

      return { req, error: passedError };
    }

    it("allows GET /auth/me, POST /auth/logout, and PUT /auth/password when mustChangePassword is true", async () => {
      for (const target of [
        { method: "GET", url: "/api/v1/auth/me" },
        { method: "POST", url: "/api/v1/auth/logout" },
        { method: "PUT", url: "/api/v1/auth/password" },
      ]) {
        const { req, error } = await invokeAuthMiddleware(
          target.method,
          target.url,
        );
        assert.strictEqual(
          error,
          null,
          `Expected ${target.method} ${target.url} to be allowed`,
        );
        assert.strictEqual(req.user?.mustChangePassword, true);
      }
    });

    it("still blocks business and other profile endpoints with 403 FORBIDDEN when mustChangePassword is true", async () => {
      for (const target of [
        { method: "GET", url: "/api/v1/users" },
        { method: "PUT", url: "/api/v1/auth/profile" },
        { method: "GET", url: "/api/v1/auth/sessions" },
      ]) {
        const { error } = await invokeAuthMiddleware(target.method, target.url);
        assert.ok(error instanceof AppError);
        assert.strictEqual(error.statusCode, 403);
        assert.strictEqual(error.code, ERROR_CODE.FORBIDDEN);
      }
    });
  });

  describe("AC #2: verify2FALogin standardization & tempToken single-use anti-replay", () => {
    const rawSecret = "JBSWY3DPEHPK3PXP";
    const encryptedSecret = encryptSecret(rawSecret);

    it("returns mustChangePassword, full ADMIN permissions fallback, upserts new device without P2025, and blocks tempToken replay", async () => {
      const adminRoleId = "a0000000-0000-0000-0000-000000000099";
      const upsertedDevices: any[] = [];
      const savedRefreshTokens: any[] = [];
      const auditLogs: any[] = [];

      const adminUser: any = {
        id: "01900000-0000-7000-8000-000000000022",
        email: "admin-2fa@smartppe.local",
        fullName: "Admin 2FA",
        isActive: true,
        deletedAt: null,
        mustChangePassword: true,
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        twoFactorBackupCodes: [],
        failedLoginAttempts: 2,
        lockedUntil: null,
        siteIds: [],
        roleId: adminRoleId,
        role: { id: adminRoleId, name: ROLES.ADMIN },
      };

      const mockRepo: Partial<AuthRepository> = {
        findById: async (id) => (id === adminUser.id ? adminUser : null),
        updateLockout: async (_id, data) => {
          adminUser.failedLoginAttempts = data.failedLoginAttempts;
          adminUser.lockedUntil = data.lockedUntil;
          return adminUser;
        },
        saveRefreshToken: async (userId, token, expiresAt, userAgent, ipAddress) => {
          const entry = { userId, token, expiresAt, userAgent, ipAddress };
          savedRefreshTokens.push(entry);
          return entry as any;
        },
        findUserDevice: async () => null, // New unknown device
        upsertUserDevice: async (data) => {
          upsertedDevices.push(data);
          return data as any;
        },
        updateUserDeviceLastLogin: async () => {
          throw new Error("Should not call updateUserDeviceLastLogin on a new device");
        },
        createAuditLog: async (data) => {
          auditLogs.push(data);
          return data as any;
        },
      };

      // Force permissionCacheService miss without DB lookup
      const originalGetRolePerms = permissionCacheService.getRolePermissions;
      permissionCacheService.getRolePermissions = async () => {
        throw new Error("DB unavailable in unit test");
      };

      try {
        const authService = new AuthService(mockRepo as AuthRepository);
        const tempToken = jwt.sign(
          {
            id: adminUser.id,
            purpose: "2FA_VERIFICATION",
            jti: crypto.randomUUID(),
          },
          jwtConfig.tempSecret,
          { expiresIn: "5m" },
        );

        // Wrong TOTP code must NOT consume tempToken so user can retry
        await assert.rejects(
          () => authService.verify2FALogin({ tempToken, code: "000000" }),
          (err: AppError) =>
            err.statusCode === 400 &&
            err.code === ERROR_CODE.TWO_FACTOR_INVALID_CODE,
        );

        const validCode = generateTotpCode(rawSecret);
        const res = await authService.verify2FALogin(
          { tempToken, code: validCode },
          { userAgent: "Mozilla/5.0 BrandNewBrowser/1.0", ipAddress: "10.0.0.5" },
        );

        assert.ok(res.accessToken);
        assert.ok(res.refreshToken);
        assert.strictEqual(res.user?.mustChangePassword, true);
        assert.strictEqual(
          res.user?.permissions.length,
          Object.values(PERMISSIONS).length,
        );
        assert.strictEqual(upsertedDevices.length, 1);
        assert.strictEqual(savedRefreshTokens.length, 1);
        assert.strictEqual(adminUser.failedLoginAttempts, 0);

        const decodedAccess = jwt.decode(res.accessToken!) as any;
        assert.strictEqual(decodedAccess.mustChangePassword, true);

        // Replaying the consumed tempToken must fail with 401 TOKEN_INVALID
        await assert.rejects(
          () => authService.verify2FALogin({ tempToken, code: validCode }),
          (err: AppError) =>
            err.statusCode === 401 && err.code === ERROR_CODE.TOKEN_INVALID,
        );
      } finally {
        permissionCacheService.getRolePermissions = originalGetRolePerms;
      }
    });
  });

  describe("AC #3: Google OAuth registration flag & Admin-disabled account guard", () => {
    const roleId = "a0000000-0000-0000-0000-000000000033";

    beforeEach(() => {
      (envConfig.google as any).clientId =
        "test-google-client-id.apps.googleusercontent.com";
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            iss: "https://accounts.google.com",
            sub: "google-sub-issue12",
            aud: "test-google-client-id.apps.googleusercontent.com",
            email: "target-user@gmail.com",
            email_verified: true,
            name: "Target User",
            exp: String(Math.floor(Date.now() / 1000) + 3600),
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
    });

    it("blocks new social user creation with 403 FEATURE_DISABLED when REGISTRATION_ENABLED is false", async () => {
      const originalIsFeatureEnabled = systemConfigService.isFeatureEnabled;
      systemConfigService.isFeatureEnabled = async (key: string) => {
        if (key === FEATURE_FLAGS.REGISTRATION_ENABLED) return false;
        return true;
      };

      let createCalled = false;
      const mockRepo: Partial<AuthRepository> = {
        findBySocial: async () => null,
        findByEmail: async () => null,
        createSocialUser: async () => {
          createCalled = true;
          return {} as any;
        },
      };

      try {
        const authService = new AuthService(mockRepo as AuthRepository);
        await assert.rejects(
          () => authService.googleLogin({ idToken: "valid-id-token" }),
          (err: AppError) =>
            err.statusCode === 403 && err.code === ERROR_CODE.FEATURE_DISABLED,
        );
        assert.strictEqual(createCalled, false);
      } finally {
        systemConfigService.isFeatureEnabled = originalIsFeatureEnabled;
      }
    });

    it("blocks Admin-disabled unlinked user (isActive=false, no pending verification token) without reactivating", async () => {
      let linked = false;
      let activated = false;

      const disabledUser: any = {
        id: "disabled-unlinked-1",
        email: "target-user@gmail.com",
        password: "hashed-password",
        isActive: false,
        deletedAt: null,
        roleId,
        role: { id: roleId, name: ROLES.USER },
      };

      const mockRepo: Partial<AuthRepository> = {
        findBySocial: async () => null,
        findByEmail: async () => disabledUser,
        findActiveVerificationTokenByUserId: async () => null, // No pending email verification
        linkAndActivateSocialUser: async () => {
          linked = true;
          activated = true;
          return disabledUser;
        },
        linkSocialAccount: async () => {
          linked = true;
          return {} as any;
        },
        activateUserAndClearPassword: async () => {
          activated = true;
          return disabledUser;
        },
      };

      const authService = new AuthService(mockRepo as AuthRepository);
      await assert.rejects(
        () => authService.googleLogin({ idToken: "valid-id-token" }),
        (err: AppError) =>
          err.statusCode === 403 && err.code === ERROR_CODE.USER_INACTIVE,
      );
      assert.strictEqual(linked, false);
      assert.strictEqual(activated, false);
      assert.strictEqual(disabledUser.isActive, false);
    });
  });

  describe("AC #4: Unified login error message prevents User Enumeration", () => {
    it("returns identical 401 INVALID_CREDENTIALS message for non-existent email, Google-only user, and wrong password", async () => {
      const passwordHash = await bcrypt.hash("CorrectP@ss123", 10);
      const roleId = "a0000000-0000-0000-0000-000000000044";

      const googleOnlyUser: any = {
        id: "google-only-user",
        email: "googleonly@smartppe.local",
        password: null,
        isActive: true,
        deletedAt: null,
        failedLoginAttempts: 0,
        lockedUntil: null,
        roleId,
        role: { id: roleId, name: ROLES.USER },
      };

      const localUser: any = {
        id: "local-user",
        email: "local@smartppe.local",
        password: passwordHash,
        isActive: true,
        deletedAt: null,
        failedLoginAttempts: 0,
        lockedUntil: null,
        roleId,
        role: { id: roleId, name: ROLES.USER },
      };

      const mockRepo: Partial<AuthRepository> = {
        findByEmail: async (email) => {
          if (email === googleOnlyUser.email) return googleOnlyUser;
          if (email === localUser.email) return localUser;
          return null;
        },
        updateLockout: async (id, data) => {
          if (id === localUser.id) {
            localUser.failedLoginAttempts = data.failedLoginAttempts;
            localUser.lockedUntil = data.lockedUntil;
          }
          return localUser;
        },
      };

      const authService = new AuthService(mockRepo as AuthRepository);

      const captured: Array<{ status: number; code: string; message: string }> =
        [];

      for (const creds of [
        { email: "nonexistent@smartppe.local", password: "AnyPassword1!" },
        { email: googleOnlyUser.email, password: "AnyPassword1!" },
        { email: localUser.email, password: "WrongPassword1!" },
      ]) {
        await assert.rejects(
          () => authService.login(creds),
          (err: AppError) => {
            captured.push({
              status: err.statusCode,
              code: err.code,
              message: err.message,
            });
            return true;
          },
        );
      }

      assert.strictEqual(captured.length, 3);
      assert.deepStrictEqual(captured[0], captured[1]);
      assert.deepStrictEqual(captured[1], captured[2]);
      assert.strictEqual(captured[0].status, 401);
      assert.strictEqual(captured[0].code, ERROR_CODE.INVALID_CREDENTIALS);
      assert.strictEqual(captured[0].message.includes("Bạn còn"), false);
    });
  });

  describe("AC #5, #6, #7, #8: Rate limit + POST /verify-email, Same-password guard, Reset password hardening, Google OAuth PKCE & OpenAPI", () => {
    it("GET and POST /verify-email have authRateLimitMiddleware attached and documented in OpenAPI", () => {
      for (const method of ["get", "post"] as const) {
        const layer = authRouter.stack.find(
          (l: any) =>
            l.route &&
            l.route.path === "/verify-email" &&
            l.route.methods[method],
        );
        assert.ok(layer, `Route ${method.toUpperCase()} /verify-email must exist`);
        const hasRateLimiter = layer.route.stack.some(
          (s: any) => s.handle === authRateLimitMiddleware,
        );
        assert.strictEqual(
          hasRateLimiter,
          true,
          `${method.toUpperCase()} /verify-email must include authRateLimitMiddleware`,
        );
      }

      const paths = swaggerSpec.paths as Record<string, any>;
      const verifyPath =
        paths["/api/v1/auth/verify-email"] || paths["/auth/verify-email"];
      assert.ok(verifyPath?.get, "GET /auth/verify-email must exist in OpenAPI");
      assert.ok(verifyPath?.post, "POST /auth/verify-email must exist in OpenAPI");
    });

    it("updatePassword blocks newPassword === oldPassword with distinct ERROR_CODE.PASSWORD_UNCHANGED", async () => {
      const currentPass = "SamePass@123";
      const passwordHash = await bcrypt.hash(currentPass, 10);

      const mockRepo: Partial<AuthRepository> = {
        findById: async (id) =>
          ({
            id,
            email: "user@smartppe.local",
            password: passwordHash,
            isActive: true,
          }) as any,
      };

      const authService = new AuthService(mockRepo as AuthRepository);
      await assert.rejects(
        () =>
          authService.updatePassword("user-1", {
            oldPassword: currentPass,
            newPassword: currentPass,
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.PASSWORD_UNCHANGED,
      );
      assert.notStrictEqual(ERROR_CODE.PASSWORD_UNCHANGED, ERROR_CODE.BAD_REQUEST);
    });

    it("resetPassword rejects soft-deleted users, invalidates permissionCacheService, and controller clears auth cookies", async () => {
      let deletedTokenId = "";
      let resetTokensCalled = false;
      const userId = "01900000-0000-7000-8000-000000000077";

      const deletedResetRepo: Partial<AuthRepository> = {
        findPasswordResetToken: async () =>
          ({
            id: "reset-tok-del",
            userId,
            expiresAt: new Date(Date.now() + 60_000),
            user: { id: userId, deletedAt: new Date(), isActive: false },
          }) as any,
        deletePasswordResetToken: async (id) => {
          deletedTokenId = id;
          return {} as any;
        },
        resetPasswordAndRevokeTokens: async () => {
          resetTokensCalled = true;
          return [] as any;
        },
      };

      const svc1 = new AuthService(deletedResetRepo as AuthRepository);
      await assert.rejects(
        () => svc1.resetPassword({ token: "tok", newPassword: "NewPass@123" }),
        (err: AppError) =>
          err.statusCode === 403 && err.code === ERROR_CODE.USER_INACTIVE,
      );
      assert.strictEqual(deletedTokenId, "reset-tok-del");
      assert.strictEqual(resetTokensCalled, false);

      // Now test active user -> invalidates user cache + controller clears cookies
      let invalidatedUserId = "";
      const originalInvalidate = permissionCacheService.invalidateUser.bind(
        permissionCacheService,
      );
      permissionCacheService.invalidateUser = (id: string) => {
        invalidatedUserId = id;
        return originalInvalidate(id);
      };

      try {
        const activeResetRepo: Partial<AuthRepository> = {
          findPasswordResetToken: async () =>
            ({
              id: "reset-tok-ok",
              userId,
              expiresAt: new Date(Date.now() + 60_000),
              user: { id: userId, deletedAt: null, isActive: true },
            }) as any,
          resetPasswordAndRevokeTokens: async () => [] as any,
        };

        const svc2 = new AuthService(activeResetRepo as AuthRepository);
        const controller = new AuthController(svc2);
        const clearedCookies: string[] = [];

        await controller.resetPassword(
          { body: { token: "tok-ok", newPassword: "NewStrongPass@123" } } as any,
          {
            clearCookie: (name: string) => {
              clearedCookies.push(name);
            },
            json: () => {},
          } as any,
          (err?: any) => {
            if (err) throw err;
          },
        );

        assert.strictEqual(invalidatedUserId, userId);
        assert.deepStrictEqual(clearedCookies, ["accessToken", "refreshToken"]);
      } finally {
        permissionCacheService.invalidateUser = originalInvalidate;
      }
    });

    it("Google OAuth helper & schemas support PKCE and omit access_type=offline and prompt=consent", async () => {
      const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

      const url = generateGoogleAuthUrl(
        "client-id-pkce",
        "http://localhost:3000/auth/callback",
        "state-xyz",
        { codeChallenge, codeChallengeMethod: "S256" },
      );

      const parsed = new URL(url);
      assert.strictEqual(parsed.searchParams.get("access_type"), null);
      assert.strictEqual(parsed.searchParams.get("prompt"), null);
      assert.strictEqual(parsed.searchParams.get("code_challenge"), codeChallenge);
      assert.strictEqual(parsed.searchParams.get("code_challenge_method"), "S256");

      let sentBody = "";
      globalThis.fetch = async (_url: any, opts: any) => {
        sentBody = String(opts?.body || "");
        return new Response(
          JSON.stringify({ id_token: "id-tok", access_token: "acc-tok" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      };

      await exchangeGoogleCode(
        "auth-code-1",
        "http://localhost:3000/auth/callback",
        "client-id",
        "client-secret",
        codeVerifier,
      );
      const sentParams = new URLSearchParams(sentBody);
      assert.strictEqual(sentParams.get("code_verifier"), codeVerifier);

      assert.strictEqual(
        googleAuthUrlQuerySchema.safeParse({
          redirectUri: "http://localhost:3000/auth/callback",
          codeChallenge,
          codeChallengeMethod: "S256",
        }).success,
        true,
      );
      assert.strictEqual(
        googleAuthUrlQuerySchema.safeParse({
          codeChallenge: "too-short",
        }).success,
        false,
      );
      assert.strictEqual(
        googleAuthUrlQuerySchema.safeParse({
          codeChallengeMethod: "S256",
        }).success,
        false,
      );
      assert.strictEqual(
        googleLoginSchema.safeParse({
          code: "auth-code",
          redirectUri: "http://localhost:3000/auth/callback",
          codeVerifier,
        }).success,
        true,
      );
      assert.strictEqual(
        linkSocialAccountSchema.safeParse({
          provider: "GOOGLE",
          code: "auth-code",
          redirectUri: "http://localhost:3000/auth/callback",
          codeVerifier: "invalid space char",
        }).success,
        false,
      );
    });
  });

  describe("Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let userRoleId = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const suffix = crypto.randomBytes(4).toString("hex");

    async function requestApi(
      method: "GET" | "POST" | "PUT",
      path: string,
      options: { token?: string; body?: unknown; userAgent?: string } = {},
    ) {
      const headers: Record<string, string> = {};
      if (options.token) {
        headers.authorization = `Bearer ${options.token}`;
      }
      if (options.userAgent) {
        headers["user-agent"] = options.userAgent;
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
      await prisma.$queryRaw`SELECT 1`;
      permissionCacheService.clear();
      clearConsumedTempTokens();

      let userRole = await prisma.role.findFirst({
        where: { name: ROLES.USER },
      });
      if (!userRole) {
        userRole = await prisma.role.create({
          data: {
            name: ROLES.USER,
            description: "Temporary Issue12 test role",
            isSystem: true,
          },
        });
        createdTempRoleId = userRole.id;
      }
      userRoleId = userRole.id;

      server = await new Promise<http.Server>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      try {
        if (createdUserIds.length > 0) {
          await prisma.auditLog
            .deleteMany({
              where: {
                OR: [
                  { actorId: { in: createdUserIds } },
                  { targetId: { in: createdUserIds } },
                ],
              },
            })
            .catch(() => {});
          await prisma.userSocial
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.userDevice
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.verificationToken
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.passwordResetToken
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.refreshToken
            .deleteMany({ where: { userId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.user
            .deleteMany({ where: { id: { in: createdUserIds } } })
            .catch(() => {});
        }
        if (createdTempRoleId) {
          await prisma.role
            .deleteMany({ where: { id: createdTempRoleId } })
            .catch(() => {});
        }
      } finally {
        permissionCacheService.clear();
        clearConsumedTempTokens();
        if (server) {
          await new Promise<void>((resolve) => server!.close(() => resolve()));
        }
        await prisma.$disconnect().catch(() => {});
      }
    });

    it("HTTP GET /auth/me succeeds while GET /users is blocked (403) when mustChangePassword=true", async () => {
      const passwordHash = await bcrypt.hash("McpPass@123", 10);
      const user = await prisma.user.create({
        data: {
          email: `it-i12-mcp-${suffix}@smartppe.local`,
          password: passwordHash,
          fullName: "Issue12 MCP User",
          roleId: userRoleId,
          isActive: true,
          mustChangePassword: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(user.id);

      const accessToken = jwtKeyService.signAccessToken({
        id: user.id,
        email: user.email!,
        role: ROLES.USER,
        roleId: userRoleId,
        permissions: [],
        mustChangePassword: true,
        purpose: JWT_PURPOSE.ACCESS,
      });

      const meRes = await requestApi("GET", "/api/v1/auth/me", {
        token: accessToken,
      });
      assert.strictEqual(meRes.status, 200);
      assert.strictEqual(meRes.body.data.mustChangePassword, true);

      const usersRes = await requestApi("GET", "/api/v1/users", {
        token: accessToken,
      });
      assert.strictEqual(usersRes.status, 403);
      assert.strictEqual(usersRes.body.code, ERROR_CODE.FORBIDDEN);

      // AC #6 via live HTTP: same password returns PASSWORD_UNCHANGED
      const samePassRes = await requestApi("PUT", "/api/v1/auth/password", {
        token: accessToken,
        body: { oldPassword: "McpPass@123", newPassword: "McpPass@123" },
      });
      assert.strictEqual(samePassRes.status, 400);
      assert.strictEqual(
        samePassRes.body.code,
        ERROR_CODE.PASSWORD_UNCHANGED,
      );
    });

    it("HTTP POST /auth/2fa/verify works on a brand-new device (zero P2025) and rejects tempToken replay", async () => {
      const rawSecret = "JBSWY3DPEHPK3PXP";
      const user = await prisma.user.create({
        data: {
          email: `it-i12-2fa-${suffix}@smartppe.local`,
          password: await bcrypt.hash("TwoFaPass@123", 10),
          fullName: "Issue12 2FA User",
          roleId: userRoleId,
          isActive: true,
          mustChangePassword: true,
          twoFactorEnabled: true,
          twoFactorSecret: encryptSecret(rawSecret),
          twoFactorBackupCodes: [],
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(user.id);

      const loginRes = await requestApi("POST", "/api/v1/auth/login", {
        body: { email: user.email, password: "TwoFaPass@123" },
      });
      assert.strictEqual(loginRes.status, 200);
      assert.strictEqual(loginRes.body.data.requires2FA, true);
      const tempToken = loginRes.body.data.tempToken;

      const validCode = generateTotpCode(rawSecret);
      const verifyRes = await requestApi("POST", "/api/v1/auth/2fa/verify", {
        body: { tempToken, code: validCode },
        userAgent: "Mozilla/5.0 Issue12NewDevice/1.0",
      });
      assert.strictEqual(verifyRes.status, 200);
      assert.strictEqual(verifyRes.body.data.user.mustChangePassword, true);

      const devices = await prisma.userDevice.findMany({
        where: { userId: user.id },
      });
      assert.strictEqual(devices.length, 1);

      const replayRes = await requestApi("POST", "/api/v1/auth/2fa/verify", {
        body: { tempToken, code: validCode },
      });
      assert.strictEqual(replayRes.status, 401);
      assert.strictEqual(replayRes.body.code, ERROR_CODE.TOKEN_INVALID);
    });

    it("HTTP POST /auth/verify-email activates pending user and POST /auth/reset-password clears auth cookies", async () => {
      const pendingUser = await prisma.user.create({
        data: {
          email: `it-i12-verify-${suffix}@smartppe.local`,
          password: await bcrypt.hash("OldPass@123", 10),
          fullName: "Issue12 Verify User",
          roleId: userRoleId,
          isActive: false,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(pendingUser.id);

      const verifyToken = `verif-${crypto.randomUUID()}`;
      await prisma.verificationToken.create({
        data: {
          userId: pendingUser.id,
          token: hashToken(verifyToken),
          type: VERIFICATION_TOKEN_TYPE.EMAIL_VERIFICATION,
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        },
      });

      const verifyRes = await requestApi("POST", "/api/v1/auth/verify-email", {
        body: { token: verifyToken },
      });
      assert.strictEqual(verifyRes.status, 200);
      assert.ok(verifyRes.headers.get("x-ratelimit-limit"));

      const refreshedUser = await prisma.user.findUnique({
        where: { id: pendingUser.id },
      });
      assert.strictEqual(refreshedUser?.isActive, true);

      // Reset password clears auth cookies
      const resetTokenPlain = `reset-${crypto.randomUUID()}`;
      await prisma.passwordResetToken.create({
        data: {
          userId: pendingUser.id,
          token: hashToken(resetTokenPlain),
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        },
      });

      const resetRes = await requestApi("POST", "/api/v1/auth/reset-password", {
        body: { token: resetTokenPlain, newPassword: "ResetNew@123" },
      });
      assert.strictEqual(resetRes.status, 200);
      const cookieHeaderJoined = resetRes.setCookies.join("; ");
      assert.ok(cookieHeaderJoined.includes("accessToken="));
      assert.ok(cookieHeaderJoined.includes("refreshToken="));
    });
  });
});
