import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import { AuthService } from "../src/modules/auth/auth.service";
import { AuthRepository } from "../src/modules/auth/auth.repository";
import { jwtConfig } from "../src/config/jwt.config";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";

describe("AuthService.refresh & Access Token Permissions Test Suite (SEC-15)", () => {
  let authService: AuthService;
  let mockRepository: Partial<AuthRepository>;
  const roleId = "b0000000-0000-0000-0000-000000000002";
  const adminRoleId = "a0000000-0000-0000-0000-000000000001";

  beforeEach(() => {
    permissionCacheService.clear();
    (permissionCacheService as any).cache.set(roleId, {
      permissions: new Set([PERMISSIONS.USER_READ, PERMISSIONS.USER_UPDATE]),
      expiresAt: Date.now() + 600000,
    });
  });

  it("SEC-15: should include permissions claim in refreshed access token for regular user", async () => {
    const userId = "c0000000-0000-0000-0000-000000000003";
    const user = {
      id: userId,
      email: "operator@company.local",
      roleId,
      role: { id: roleId, name: ROLES.OPERATOR },
      isActive: true,
      deletedAt: null,
    };

    const validRefreshToken = jwt.sign(
      {
        id: userId,
        email: user.email,
        role: user.role.name,
        roleId: user.roleId,
        purpose: JWT_PURPOSE.ACCESS,
        jti: "test-jti-uuid",
      },
      jwtConfig.refreshSecret,
      { expiresIn: "7d" },
    );

    mockRepository = {
      findById: async () => user as any,
      rotateRefreshToken: async () => ({ rotated: true }) as any,
    };

    authService = new AuthService();
    (authService as any).repository = mockRepository;

    const result = await authService.refresh(validRefreshToken);

    assert.ok(result.accessToken, "Must return new access token");
    assert.ok(result.refreshToken, "Must return rotated refresh token");

    const decoded = jwtKeyService.verifyAccessToken(result.accessToken) as any;
    assert.equal(decoded.id, userId);
    assert.equal(decoded.email, "operator@company.local");
    assert.equal(decoded.role, ROLES.OPERATOR);
    assert.ok(Array.isArray(decoded.permissions), "permissions must be an array");
    assert.deepEqual(decoded.permissions.sort(), [
      PERMISSIONS.USER_READ,
      PERMISSIONS.USER_UPDATE,
    ]);
  });

  it("SEC-15: should populate full PERMISSIONS list in refreshed access token for ADMIN", async () => {
    const adminId = "d0000000-0000-0000-0000-000000000004";
    const adminUser = {
      id: adminId,
      email: "admin@company.local",
      roleId: adminRoleId,
      role: { id: adminRoleId, name: ROLES.ADMIN },
      isActive: true,
      deletedAt: null,
    };

    const validAdminRefreshToken = jwt.sign(
      {
        id: adminId,
        email: adminUser.email,
        role: adminUser.role.name,
        roleId: adminUser.roleId,
        purpose: JWT_PURPOSE.ACCESS,
        jti: "admin-jti-uuid",
      },
      jwtConfig.refreshSecret,
      { expiresIn: "7d" },
    );

    mockRepository = {
      findById: async () => adminUser as any,
      rotateRefreshToken: async () => ({ rotated: true }) as any,
    };

    authService = new AuthService();
    (authService as any).repository = mockRepository;

    const result = await authService.refresh(validAdminRefreshToken);
    const decoded = jwtKeyService.verifyAccessToken(result.accessToken) as any;

    assert.equal(decoded.role, ROLES.ADMIN);
    assert.ok(Array.isArray(decoded.permissions));
    const allPermissions = Object.values(PERMISSIONS);
    assert.equal(decoded.permissions.length, allPermissions.length);
    for (const perm of allPermissions) {
      assert.ok(
        decoded.permissions.includes(perm),
        `Admin must have permission ${perm}`,
      );
    }
  });

  it("should reject refresh if user is inactive or deleted with 401 USER_INACTIVE", async () => {
    const userId = "e0000000-0000-0000-0000-000000000005";
    const token = jwt.sign(
      { id: userId, email: "inactive@company.local", purpose: JWT_PURPOSE.ACCESS },
      jwtConfig.refreshSecret,
      { expiresIn: "7d" },
    );

    mockRepository = {
      findById: async () =>
        ({
          id: userId,
          email: "inactive@company.local",
          roleId,
          role: { id: roleId, name: ROLES.USER },
          isActive: false,
          deletedAt: null,
        }) as any,
    };

    authService = new AuthService();
    (authService as any).repository = mockRepository;

    await assert.rejects(
      async () => authService.refresh(token),
      (err: AppError) =>
        err.statusCode === 401 && err.code === ERROR_CODE.USER_INACTIVE,
    );
  });

  it("should reject refresh if token signature or structure is invalid", async () => {
    authService = new AuthService();
    await assert.rejects(
      async () => authService.refresh("malformed-or-tampered-token"),
      (err: AppError) =>
        err.statusCode === 401 && err.code === ERROR_CODE.TOKEN_INVALID,
    );
  });
});
