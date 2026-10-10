import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { UserService } from "../src/modules/users/user.service";
import { AuthService } from "../src/modules/auth/auth.service";
import { UserRepository } from "../src/modules/users/user.repository";
import { AuthRepository } from "../src/modules/auth/auth.repository";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../src/common/constants/audit-log.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import {
  adminResetPasswordSchema,
  findAllUserSchema,
} from "../src/modules/users/user.validation";
import { swaggerSpec } from "../src/config/swagger.config";

describe("User Lifecycle & Security Hardening Test Suite", () => {
  let userService: UserService;
  let authService: AuthService;
  let mockUserRepo: Partial<UserRepository>;
  let mockAuthRepo: Partial<AuthRepository>;
  let auditLogs: Array<any> = [];

  const adminRoleId = "11111111-1111-1111-1111-111111111111";
  const userRoleId = "22222222-2222-2222-2222-222222222222";
  const adminUserId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const regularUserId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  const deletedUserId = "cccccccc-cccc-cccc-cccc-cccccccccccc";

  let adminUser: any;
  let regularUser: any;
  let deletedUser: any;

  beforeEach(async () => {
    auditLogs = [];
    permissionCacheService.clear();

    // Cache setup
    (permissionCacheService as any).cache.set(adminRoleId, {
      permissions: new Set([
        PERMISSIONS.USER_READ,
        PERMISSIONS.USER_CREATE,
        PERMISSIONS.USER_UPDATE,
        PERMISSIONS.USER_DELETE,
        PERMISSIONS.USER_RESTORE,
        PERMISSIONS.USER_ROLE_ASSIGN,
        PERMISSIONS.ROLE_PERMISSION_ASSIGN,
      ]),
      expiresAt: Date.now() + 600000,
    });
    (permissionCacheService as any).cache.set(userRoleId, {
      permissions: new Set([PERMISSIONS.USER_READ]),
      expiresAt: Date.now() + 600000,
    });

    const hashedPassword = await bcrypt.hash("P@ssword123", 10);

    adminUser = {
      id: adminUserId,
      email: "admin@example.com",
      password: hashedPassword,
      fullName: "Admin System",
      phoneNumber: "0901234567",
      isActive: true,
      failedLoginAttempts: 0,
      lockedUntil: null,
      mustChangePassword: false,
      deletedAt: null,
      deletedBy: null,
      roleId: adminRoleId,
      role: { id: adminRoleId, name: ROLES.ADMIN },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    regularUser = {
      id: regularUserId,
      email: "user@example.com",
      password: hashedPassword,
      fullName: "Normal User",
      phoneNumber: "0907654321",
      isActive: true,
      twoFactorEnabled: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      mustChangePassword: false,
      deletedAt: null,
      deletedBy: null,
      roleId: userRoleId,
      role: { id: userRoleId, name: ROLES.USER },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    deletedUser = {
      id: deletedUserId,
      email: "deleted@example.com",
      password: hashedPassword,
      fullName: "Deleted User",
      phoneNumber: "0909999999",
      isActive: false,
      twoFactorEnabled: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      mustChangePassword: false,
      deletedAt: new Date(Date.now() - 3600000),
      deletedBy: adminUserId,
      roleId: userRoleId,
      role: { id: userRoleId, name: ROLES.USER },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    mockUserRepo = {
      findById: async (id: string) => {
        if (id === adminUser.id) return adminUser;
        if (id === regularUser.id) return regularUser;
        if (id === deletedUser.id) return null; // regular find excludes soft-deleted
        return null;
      },
      findWithDeleted: async (id: string) => {
        if (id === adminUser.id) return adminUser;
        if (id === regularUser.id) return regularUser;
        if (id === deletedUser.id) return deletedUser;
        return null;
      },
      restore: async (id: string) => {
        if (id === deletedUser.id) {
          deletedUser.deletedAt = null;
          deletedUser.deletedBy = null;
          deletedUser.isActive = true;
          return deletedUser;
        }
        return null;
      },
      adminResetPassword: async (
        id: string,
        passwordHash: string,
        mustChangePassword: boolean,
      ) => {
        const u = id === adminUser.id ? adminUser : regularUser;
        u.password = passwordHash;
        u.mustChangePassword = mustChangePassword;
        u.failedLoginAttempts = 0;
        u.lockedUntil = null;
        return u;
      },
      createAuditLog: async (data: any) => {
        auditLogs.push(data);
        return data;
      },
      countActiveAdmins: async () => 1,
    };

    mockAuthRepo = {
      findByEmail: async (email: string) => {
        if (email === regularUser.email) return regularUser;
        if (email === adminUser.email) return adminUser;
        return null;
      },
      findById: async (id: string) => {
        if (id === regularUser.id) return regularUser;
        if (id === adminUser.id) return adminUser;
        return null;
      },
      findProfileById: async (id: string) => {
        const u = id === regularUser.id ? regularUser : adminUser;
        return {
          id: u.id,
          email: u.email,
          fullName: u.fullName,
          avatarUrl: null,
          phoneNumber: u.phoneNumber,
          isActive: u.isActive,
          twoFactorEnabled: u.twoFactorEnabled ?? false,
          mustChangePassword: u.mustChangePassword ?? false,
          createdAt: u.createdAt,
          roleId: u.roleId,
          role: u.role,
        };
      },
      updateLockout: async (userId: string, data: any) => {
        const u = userId === regularUser.id ? regularUser : adminUser;
        u.failedLoginAttempts = data.failedLoginAttempts;
        u.lockedUntil = data.lockedUntil;
        return u;
      },
      updatePassword: async (userId: string, passwordHash: string) => {
        const u = userId === regularUser.id ? regularUser : adminUser;
        u.password = passwordHash;
        u.mustChangePassword = false;
        return u;
      },
      updatePasswordAndRevokeTokens: async (
        userId: string,
        passwordHash: string,
      ) => {
        const u = userId === regularUser.id ? regularUser : adminUser;
        u.password = passwordHash;
        u.mustChangePassword = false;
        return u;
      },
      saveRefreshToken: async () => ({}) as any,
      createAuditLog: async (data: any) => {
        auditLogs.push(data);
        return data;
      },
    };

    userService = new UserService();
    (userService as any).repository = mockUserRepo;

    authService = new AuthService(
      mockAuthRepo as any,
      undefined,
      undefined,
      undefined,
      { notify: async () => {} } as any,
    );
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 1. User Restore Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe("1. User Restore (Khôi phục tài khoản)", () => {
    it("should restore a soft-deleted user successfully and create audit log", async () => {
      const restored = await userService.restore(deletedUser.id, adminUser.id, {
        ipAddress: "127.0.0.1",
        userAgent: "Mozilla/5.0",
      });

      assert.strictEqual(restored.isActive, true);
      assert.strictEqual(restored.deletedAt, null);
      assert.strictEqual(restored.deletedBy, null);

      assert.strictEqual(auditLogs.length, 1);
      assert.strictEqual(auditLogs[0].action, AUDIT_ACTION.RESTORE_USER);
      assert.strictEqual(auditLogs[0].targetType, AUDIT_TARGET_TYPE.USER);
      assert.strictEqual(auditLogs[0].targetId, deletedUser.id);
      assert.strictEqual(auditLogs[0].actorId, adminUser.id);
    });

    it("should reject restore if user is not deleted (deletedAt is null)", async () => {
      await assert.rejects(
        async () => {
          await userService.restore(regularUser.id, adminUser.id);
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.BAD_REQUEST);
          return true;
        },
      );
    });

    it("should reject restore if user does not exist", async () => {
      await assert.rejects(
        async () => {
          await userService.restore(
            "00000000-0000-0000-0000-000000000000",
            adminUser.id,
          );
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.BAD_REQUEST);
          return true;
        },
      );
    });

    it("should prevent non-admin from restoring an administrative user", async () => {
      const deletedAdmin = {
        ...adminUser,
        id: "deleted-admin-99",
        deletedAt: new Date(),
        deletedBy: "admin-id-1",
      };
      (mockUserRepo.findWithDeleted as any) = async () => deletedAdmin;

      await assert.rejects(
        async () => {
          await userService.restore(deletedAdmin.id, regularUser.id);
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 2. Account Lockout Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe("2. Account Lockout (Khóa tạm do nhập sai mật khẩu)", () => {
    it("should increment failedLoginAttempts and show remaining attempts on invalid password", async () => {
      await assert.rejects(
        async () => {
          await authService.login({
            email: regularUser.email,
            password: "WrongPassword1",
          });
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 401);
          assert.strictEqual(err.code, ERROR_CODE.INVALID_CREDENTIALS);
          assert.match(err.message, /Bạn còn 4 lần thử/);
          return true;
        },
      );

      assert.strictEqual(regularUser.failedLoginAttempts, 1);
      assert.strictEqual(regularUser.lockedUntil, null);
    });

    it("should lock account for 15 minutes after 5 failed attempts", async () => {
      regularUser.failedLoginAttempts = 4;

      await assert.rejects(
        async () => {
          await authService.login(
            {
              email: regularUser.email,
              password: "WrongPassword5",
            },
            { ipAddress: "192.168.1.10", userAgent: "TestClient" },
          );
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 423);
          assert.strictEqual(err.code, ERROR_CODE.ACCOUNT_LOCKED);
          assert.match(err.message, /tạm khóa 15 phút/);
          return true;
        },
      );

      assert.strictEqual(regularUser.failedLoginAttempts, 5);
      assert.ok(regularUser.lockedUntil instanceof Date);
      assert.ok(regularUser.lockedUntil.getTime() > Date.now());

      // Should have recorded ACCOUNT_LOCKED audit log
      const lockAudit = auditLogs.find(
        (l) => l.action === AUDIT_ACTION.ACCOUNT_LOCKED,
      );
      assert.ok(lockAudit);
      assert.strictEqual(lockAudit.targetId, regularUser.id);
    });

    it("should reject login immediately when account is currently locked without verifying password", async () => {
      regularUser.lockedUntil = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes remaining
      regularUser.failedLoginAttempts = 5;

      await assert.rejects(
        async () => {
          // Even with correct password, login must be blocked
          await authService.login({
            email: regularUser.email,
            password: "P@ssword123",
          });
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 423);
          assert.strictEqual(err.code, ERROR_CODE.ACCOUNT_LOCKED);
          assert.match(err.message, /tạm khóa/);
          return true;
        },
      );
    });

    it("should reset failedLoginAttempts to 0 when login succeeds with valid password", async () => {
      regularUser.failedLoginAttempts = 3;
      regularUser.lockedUntil = null;

      const result = await authService.login({
        email: regularUser.email,
        password: "P@ssword123",
      });

      assert.ok(result.accessToken);
      assert.strictEqual(regularUser.failedLoginAttempts, 0);
      assert.strictEqual(regularUser.lockedUntil, null);
    });

    it("should reset attempt counter and not immediately relock after lockout period has expired", async () => {
      regularUser.lockedUntil = new Date(Date.now() - 1000); // Lockout expired 1s ago
      regularUser.failedLoginAttempts = 5;

      await assert.rejects(
        async () => {
          await authService.login({
            email: regularUser.email,
            password: "WrongPasswordAfterExpiry",
          });
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 401);
          assert.strictEqual(err.code, ERROR_CODE.INVALID_CREDENTIALS);
          assert.match(err.message, /Bạn còn 4 lần thử/);
          return true;
        },
      );

      assert.strictEqual(regularUser.failedLoginAttempts, 1);
      assert.strictEqual(regularUser.lockedUntil, null);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 3. Admin Force Password Reset & Must Change Password Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe("3. Admin Force Password Reset & Must Change Password", () => {
    it("should reset user password, set mustChangePassword = true, and record audit log", async () => {
      const newCustomPass = "NewSecureP@ss123";
      const result = await userService.adminResetPassword(
        regularUser.id,
        { newPassword: newCustomPass, mustChangePassword: true },
        adminUser.id,
        { ipAddress: "127.0.0.1", userAgent: "AdminBrowser" },
      );

      assert.ok(result);
      assert.strictEqual(result.id, regularUser.id);
      assert.strictEqual(result.email, regularUser.email);
      assert.strictEqual(regularUser.mustChangePassword, true);
      assert.strictEqual(regularUser.failedLoginAttempts, 0);
      assert.strictEqual(regularUser.lockedUntil, null);

      const isMatch = await bcrypt.compare(newCustomPass, regularUser.password);
      assert.strictEqual(isMatch, true);

      const audit = auditLogs.find(
        (l) => l.action === AUDIT_ACTION.ADMIN_RESET_PASSWORD,
      );
      assert.ok(audit);
      assert.strictEqual(audit.targetId, regularUser.id);
      assert.strictEqual(audit.actorId, adminUser.id);
    });

    it("should auto-generate temporary password when newPassword is not provided", async () => {
      const result = await userService.adminResetPassword(
        regularUser.id,
        { mustChangePassword: true },
        adminUser.id,
      );

      assert.ok(result.temporaryPassword);
      assert.ok(result.temporaryPassword.length >= 8);
      const isMatch = await bcrypt.compare(
        result.temporaryPassword,
        regularUser.password,
      );
      assert.strictEqual(isMatch, true);
    });

    it("should reject admin reset password if non-admin attempts to reset admin password", async () => {
      await assert.rejects(
        async () => {
          await userService.adminResetPassword(
            adminUser.id,
            { newPassword: "SomePass@123" },
            regularUser.id,
          );
        },
        (err: any) => {
          assert.strictEqual(err instanceof AppError, true);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });

    it("should return mustChangePassword: true on login and me when flag is set", async () => {
      regularUser.mustChangePassword = true;

      const loginRes = await authService.login({
        email: regularUser.email,
        password: "P@ssword123",
      });

      assert.strictEqual(loginRes.user?.mustChangePassword, true);

      const meRes = await authService.getMe(regularUser.id);
      assert.strictEqual(meRes.mustChangePassword, true);
    });

    it("should clear mustChangePassword when user changes password via updatePassword", async () => {
      regularUser.mustChangePassword = true;

      await authService.updatePassword(regularUser.id, {
        oldPassword: "P@ssword123",
        newPassword: "BrandNewPass@999",
      });

      assert.strictEqual(regularUser.mustChangePassword, false);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. Validation & OpenAPI Specification Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe("4. Validation & OpenAPI Registrations", () => {
    it("adminResetPasswordSchema should validate strong password when provided", () => {
      const valid = adminResetPasswordSchema.safeParse({
        newPassword: "ValidPassword@123",
        mustChangePassword: true,
      });
      assert.strictEqual(valid.success, true);

      const invalid = adminResetPasswordSchema.safeParse({
        newPassword: "short",
      });
      assert.strictEqual(invalid.success, false);

      const tooLong = adminResetPasswordSchema.safeParse({
        newPassword: "A".repeat(101) + "a1@!",
      });
      assert.strictEqual(tooLong.success, false);

      const empty = adminResetPasswordSchema.safeParse({});
      assert.strictEqual(empty.success, true);
      assert.strictEqual(empty.data?.mustChangePassword, true);
    });

    it("findAllUserSchema should parse isDeleted query parameter correctly", () => {
      const parsedTrue = findAllUserSchema.parse({ isDeleted: "true" });
      assert.strictEqual(parsedTrue.isDeleted, true);

      const parsedFalse = findAllUserSchema.parse({ isDeleted: "false" });
      assert.strictEqual(parsedFalse.isDeleted, false);

      const parsedNone = findAllUserSchema.parse({});
      assert.strictEqual(parsedNone.isDeleted, undefined);
    });

    it("OpenAPI Swagger specification should include /users/{id}/restore and /users/{id}/reset-password", () => {
      const paths = (swaggerSpec as any).paths;
      assert.ok(paths["/users/{id}/restore"]);
      assert.ok(paths["/users/{id}/restore"].post);

      assert.ok(paths["/users/{id}/reset-password"]);
      assert.ok(paths["/users/{id}/reset-password"].post);
    });
  });
});
