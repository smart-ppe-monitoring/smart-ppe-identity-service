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

      const roles: Record<string, any> = {
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

      const users: Record<string, any> = {
        [adminUserId]: {
          id: adminUserId,
          roleId: adminRoleId,
          role: { id: adminRoleId, name: ROLES.ADMIN },
        },
        [operatorUserId]: {
          id: operatorUserId,
          roleId: operatorRoleId,
          role: { id: operatorRoleId, name: "OPERATOR" },
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
  });
});
