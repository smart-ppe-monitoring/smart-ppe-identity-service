import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  requirePermission,
  requireAnyPermission,
} from "../src/middlewares/permission.middleware";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { RbacService } from "../src/modules/rbac/rbac.service";
import { userRepository } from "../src/modules/users/user.repository";

describe("Dynamic RBAC Permission Middleware", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  it("should deny unauthenticated requests with 401 Unauthorized", async () => {
    const middleware = requirePermission(PERMISSIONS.USER_READ);
    const req = {} as any;
    const res = {} as any;
    let nextError: any = null;

    await middleware(req, res, (err) => {
      nextError = err;
    });

    assert.ok(nextError instanceof AppError);
    assert.equal(nextError.statusCode, 401);
    assert.equal(nextError.code, ERROR_CODE.UNAUTHORIZED);
  });

  it("should grant access when user role possesses required permission", async () => {
    const middleware = requirePermission(PERMISSIONS.USER_READ);
    const mockRoleId = "11111111-1111-1111-1111-111111111111";

    // Mock cache to simulate role with permissions
    (permissionCacheService as any).cache.set(mockRoleId, {
      permissions: new Set([PERMISSIONS.USER_READ, PERMISSIONS.USER_CREATE]),
      expiresAt: Date.now() + 60000,
    });
    (permissionCacheService as any).userCache.set("user-1", {
      user: {
        id: "user-1",
        isActive: true,
        deletedAt: null,
        roleId: mockRoleId,
        roleName: ROLES.ADMIN,
      },
      expiresAt: Date.now() + 60000,
    });

    const req = {
      user: {
        id: "user-1",
        email: "admin@ppe.local",
        role: ROLES.ADMIN,
        roleId: mockRoleId,
      },
    } as any;
    const res = {} as any;
    let nextCalled = false;
    let nextError: any = null;

    await middleware(req, res, (err) => {
      if (err) nextError = err;
      else nextCalled = true;
    });

    assert.equal(nextError, null);
    assert.equal(nextCalled, true);
    assert.ok(req.user.permissions.includes(PERMISSIONS.USER_READ));
  });

  it("should deny access with 403 Forbidden when user role lacks required permission", async () => {
    const middleware = requirePermission(PERMISSIONS.ROLE_DELETE);
    const mockRoleId = "22222222-2222-2222-2222-222222222222";

    // Mock cache with read-only user permissions
    (permissionCacheService as any).cache.set(mockRoleId, {
      permissions: new Set([PERMISSIONS.NOTIFICATION_READ]),
      expiresAt: Date.now() + 60000,
    });
    (permissionCacheService as any).userCache.set("user-2", {
      user: {
        id: "user-2",
        isActive: true,
        deletedAt: null,
        roleId: mockRoleId,
        roleName: ROLES.USER,
      },
      expiresAt: Date.now() + 60000,
    });

    const req = {
      user: {
        id: "user-2",
        email: "user@ppe.local",
        role: ROLES.USER,
        roleId: mockRoleId,
      },
    } as any;
    const res = {} as any;
    let nextError: any = null;

    await middleware(req, res, (err) => {
      nextError = err;
    });

    assert.ok(nextError instanceof AppError);
    assert.equal(nextError.statusCode, 403);
    assert.equal(nextError.code, ERROR_CODE.FORBIDDEN);
  });

  it("should support requireAnyPermission when at least one permission matches", async () => {
    const middleware = requireAnyPermission(
      PERMISSIONS.USER_READ,
      PERMISSIONS.ROLE_READ,
    );
    const mockRoleId = "33333333-3333-3333-3333-333333333333";

    (permissionCacheService as any).cache.set(mockRoleId, {
      permissions: new Set([PERMISSIONS.ROLE_READ]),
      expiresAt: Date.now() + 60000,
    });
    (permissionCacheService as any).userCache.set("user-3", {
      user: {
        id: "user-3",
        isActive: true,
        deletedAt: null,
        roleId: mockRoleId,
        roleName: ROLES.MANAGER,
      },
      expiresAt: Date.now() + 60000,
    });

    const req = {
      user: {
        id: "user-3",
        email: "manager@ppe.local",
        role: ROLES.MANAGER,
        roleId: mockRoleId,
      },
    } as any;
    const res = {} as any;
    let nextCalled = false;

    await middleware(req, res, (err) => {
      if (!err) nextCalled = true;
    });

    assert.equal(nextCalled, true);
  });

  it("should accurately invalidate role permission cache upon mutation", () => {
    const mockRoleId = "44444444-4444-4444-4444-444444444444";
    (permissionCacheService as any).cache.set(mockRoleId, {
      permissions: new Set([PERMISSIONS.USER_READ]),
      expiresAt: Date.now() + 60000,
    });

    assert.ok((permissionCacheService as any).cache.has(mockRoleId));

    permissionCacheService.invalidateRole(mockRoleId);

    assert.equal((permissionCacheService as any).cache.has(mockRoleId), false);
  });

  describe("RbacService: Role & Permission Assignment Security (SEC-04)", () => {
    const adminRoleId = "11111111-1111-1111-1111-111111111111";
    const operatorRoleId = "22222222-2222-2222-2222-222222222222";
    const targetCustomRoleId = "33333333-3333-3333-3333-333333333333";

    const adminUserId = "admin-user-uuid";
    const operatorUserId = "operator-user-uuid";

    const permReadId = "perm-user-read-uuid";
    const permAssignId = "perm-role-permission-assign-uuid";
    const permSystemConfigId = "perm-system-config-uuid";

    const permissionsMap: Record<string, { id: string; name: string }> = {
      [permReadId]: { id: permReadId, name: PERMISSIONS.USER_READ },
      [permAssignId]: {
        id: permAssignId,
        name: PERMISSIONS.ROLE_PERMISSION_ASSIGN,
      },
      [permSystemConfigId]: {
        id: permSystemConfigId,
        name: PERMISSIONS.SYSTEM_CONFIG_MANAGE,
      },
    };

    let rbacService: RbacService;
    let roles: Record<string, any> = {};
    let users: Record<string, any> = {};

    beforeEach(() => {
      permissionCacheService.clear();

      // Operator has USER_READ and ROLE_PERMISSION_ASSIGN (but NOT SYSTEM_CONFIG_MANAGE)
      (permissionCacheService as any).cache.set(operatorRoleId, {
        permissions: new Set([
          PERMISSIONS.USER_READ,
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
        ]),
        expiresAt: Date.now() + 60000,
      });

      // Admin has all permissions
      (permissionCacheService as any).cache.set(adminRoleId, {
        permissions: new Set([
          PERMISSIONS.USER_READ,
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
          PERMISSIONS.SYSTEM_CONFIG_MANAGE,
        ]),
        expiresAt: Date.now() + 60000,
      });

      // Target custom role permissions
      (permissionCacheService as any).cache.set(targetCustomRoleId, {
        permissions: new Set([PERMISSIONS.USER_READ]),
        expiresAt: Date.now() + 60000,
      });

      roles = {
        [adminRoleId]: {
          id: adminRoleId,
          name: ROLES.ADMIN,
          isSystem: true,
          permissions: [{ id: permReadId }, { id: permAssignId }],
        },
        [operatorRoleId]: {
          id: operatorRoleId,
          name: "OPERATOR",
          isSystem: false,
          permissions: [{ id: permReadId }, { id: permAssignId }],
        },
        [targetCustomRoleId]: {
          id: targetCustomRoleId,
          name: "CUSTOM_ROLE",
          isSystem: false,
          permissions: [{ id: permReadId }],
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
          if (!r) throw new AppError("Role not found", 404, ERROR_CODE.NOT_FOUND);
          return r;
        },
        findPermissionsByIds: async (ids: string[]) =>
          ids.map((id) => permissionsMap[id]).filter(Boolean),
        findPermissionByName: async (name: string) =>
          Object.values(permissionsMap).find((p) => p.name === name) || null,
        syncRolePermissions: async (roleId: string, permissionIds: string[]) => {
          roles[roleId].permissions = permissionIds.map((id) => ({ id }));
          return roles[roleId];
        },
        createAuditLog: async () => {},
        findUserById: async (id: string) => users[id] || null,
        assignUserRole: async (userId: string, roleId: string) => {
          if (users[userId]) {
            users[userId].roleId = roleId;
            users[userId].role = roles[roleId];
          }
          return users[userId];
        },
        createRole: async (data: any) => ({
          id: "new-role-uuid",
          ...data,
          permissions: (data.permissionIds || []).map((id: string) => ({ id })),
        }),
        findRoleByName: async () => null,
      };

      rbacService = new RbacService(mockRepo);
    });

    it("should prevent non-admin from modifying permissions of the ADMIN role", async () => {
      await assert.rejects(
        async () => {
          await rbacService.syncRolePermissions(
            adminRoleId,
            [permReadId, permAssignId],
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(err.message, /Chỉ Quản trị viên/);
          return true;
        },
      );
    });

    it("should prevent non-admin from modifying their own role's permissions (anti-self-escalation)", async () => {
      await assert.rejects(
        async () => {
          await rbacService.syncRolePermissions(
            operatorRoleId,
            [permReadId],
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(
            err.message,
            /Không được phép tự gán hoặc thay đổi quyền cho vai trò của chính mình/,
          );
          return true;
        },
      );
    });

    it("should reject non-admin assigning permissions beyond their own permissions (subset validation)", async () => {
      await assert.rejects(
        async () => {
          // Operator attempts to assign SYSTEM_CONFIG_MANAGE which operator does not have
          await rbacService.syncRolePermissions(
            targetCustomRoleId,
            [permReadId, permSystemConfigId],
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(err.message, /Subset Validation/);
          return true;
        },
      );
    });

    it("should reject non-admin from granting ROLE_PERMISSION_ASSIGN delegation permission", async () => {
      await assert.rejects(
        async () => {
          // Operator has ROLE_PERMISSION_ASSIGN, but cannot delegate this admin power to another role
          await rbacService.syncRolePermissions(
            targetCustomRoleId,
            [permReadId, permAssignId],
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(err.message, /đặc quyền quản trị vai trò/);
          return true;
        },
      );
    });

    it("should allow ADMIN to sync permissions with any valid permissions", async () => {
      const result = await rbacService.syncRolePermissions(
        targetCustomRoleId,
        [permReadId, permSystemConfigId],
        { actorId: adminUserId },
      );

      assert.ok(result);
      assert.strictEqual(result.id, targetCustomRoleId);
    });

    it("should enforce subset validation on createRole when called by non-admin", async () => {
      await assert.rejects(
        async () => {
          await rbacService.createRole(
            {
              name: "ILLEGAL_NEW_ROLE",
              description: "Test",
              permissionIds: [permSystemConfigId],
            },
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(err.message, /Subset Validation/);
          return true;
        },
      );
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SEC-05: Privilege Escalation Guard (Circle Admin Check Fix)
    // ──────────────────────────────────────────────────────────────────────────
    it("should reject Operator with USER_ROLE_ASSIGN from promoting another user to ADMIN role (SEC-05)", async () => {
      // Add a third user that operator wants to promote to ADMIN
      users["victim-user-uuid"] = {
        id: "victim-user-uuid",
        roleId: targetCustomRoleId,
        role: roles[targetCustomRoleId],
        isActive: true,
      };

      await assert.rejects(
        async () => {
          await rbacService.assignUserRole(
            "victim-user-uuid",
            adminRoleId,
            { actorId: operatorUserId },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          assert.match(
            err.message,
            /Chỉ Quản trị viên \(Admin\) mới có quyền cấp vai trò Quản trị viên/,
          );
          return true;
        },
      );
    });

    it("should allow true ADMIN to promote another user to ADMIN role", async () => {
      users["candidate-user-uuid"] = {
        id: "candidate-user-uuid",
        roleId: targetCustomRoleId,
        role: roles[targetCustomRoleId],
        isActive: true,
      };

      const result = await rbacService.assignUserRole(
        "candidate-user-uuid",
        adminRoleId,
        { actorId: adminUserId },
      );

      assert.ok(result);
      assert.strictEqual(result.roleId, adminRoleId);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SEC-06: Anti-Lockout Sole Admin Demotion Defense
    // ──────────────────────────────────────────────────────────────────────────
    it("should reject demoting the sole active ADMIN user with 400 Validation Error (SEC-06)", async () => {
      // Stub userRepository.countActiveAdmins to return 1 active admin
      (userRepository as any).countActiveAdmins = async () => 1;

      // Create another admin user attempting to demote adminUserId
      users["second-admin-uuid"] = {
        id: "second-admin-uuid",
        roleId: adminRoleId,
        role: roles[adminRoleId],
        isActive: true,
      };

      await assert.rejects(
        async () => {
          await rbacService.assignUserRole(
            adminUserId,
            targetCustomRoleId,
            { actorId: "second-admin-uuid" },
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.match(
            err.message,
            /Không thể hạ quyền Quản trị viên \(Admin\) duy nhất/,
          );
          return true;
        },
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SEC-07: API Key Scoped Permissions & Admin Bypass Elimination
  // ──────────────────────────────────────────────────────────────────────────
  describe("API Key Authorization Scoping (SEC-07)", () => {
    it("should strictly enforce scoped permissions for API Key and ignore ADMIN role bypass", async () => {
      // Giả lập request dùng API Key của một tài khoản ADMIN, nhưng chỉ được cấp quyền đọc PPE_SITE_READ
      const req = {
        user: {
          id: "admin-user-id",
          email: "admin@ppe.local",
          role: ROLES.ADMIN,
          roleId: "admin-role-id",
          permissions: [PERMISSIONS.PPE_SITE_READ],
        },
        apiKey: {
          id: "key-123",
          name: "Monitoring Service Key",
          prefix: "ppe_live_abc",
          permissions: [PERMISSIONS.PPE_SITE_READ],
        },
      } as any;
      const res = {} as any;

      // 1. Endpoint yêu cầu quyền PPE_SITE_READ -> ĐƯỢC PHÉP
      const siteReadMiddleware = requirePermission(PERMISSIONS.PPE_SITE_READ);
      let passedSiteRead = false;
      await siteReadMiddleware(req, res, (err) => {
        if (!err) passedSiteRead = true;
      });
      assert.strictEqual(passedSiteRead, true);

      // 2. Endpoint yêu cầu quyền USER_DELETE -> PHẢI BỊ CHẶN 403 (không được admin bypass)
      const userDeleteMiddleware = requirePermission(PERMISSIONS.USER_DELETE);
      let deleteError: any = null;
      await userDeleteMiddleware(req, res, (err) => {
        deleteError = err;
      });
      assert.ok(deleteError instanceof AppError);
      assert.strictEqual(deleteError.statusCode, 403);
      assert.strictEqual(deleteError.code, ERROR_CODE.FORBIDDEN);

      // 3. Endpoint yêu cầu SYSTEM_CONFIG_MANAGE -> PHẢI BỊ CHẶN 403
      const configMiddleware = requirePermission(PERMISSIONS.SYSTEM_CONFIG_MANAGE);
      let configError: any = null;
      await configMiddleware(req, res, (err) => {
        configError = err;
      });
      assert.ok(configError instanceof AppError);
      assert.strictEqual(configError.statusCode, 403);
      assert.strictEqual(configError.code, ERROR_CODE.FORBIDDEN);
    });

    it("should reject API Key when attempting access to permissions outside its granted array", async () => {
      (permissionCacheService as any).cache.set("operator-role-id", {
        permissions: new Set([PERMISSIONS.PPE_INCIDENT_READ]),
        expiresAt: Date.now() + 60000,
      });

      const req = {
        user: {
          id: "operator-user-id",
          email: "operator@ppe.local",
          role: "OPERATOR",
          roleId: "operator-role-id",
          permissions: [PERMISSIONS.PPE_INCIDENT_READ],
        },
        apiKey: {
          id: "key-456",
          name: "Incident Reader Key",
          prefix: "ppe_live_xyz",
          permissions: [PERMISSIONS.PPE_INCIDENT_READ],
        },
      } as any;
      const res = {} as any;

      const incidentReadMiddleware = requirePermission(PERMISSIONS.PPE_INCIDENT_READ);
      let passedRead = false;
      await incidentReadMiddleware(req, res, (err) => {
        if (!err) passedRead = true;
      });
      assert.strictEqual(passedRead, true);

      const roleDeleteMiddleware = requirePermission(PERMISSIONS.ROLE_DELETE);
      let roleDeleteError: any = null;
      await roleDeleteMiddleware(req, res, (err) => {
        roleDeleteError = err;
      });
      assert.ok(roleDeleteError instanceof AppError);
      assert.strictEqual(roleDeleteError.statusCode, 403);
    });
  });
});
