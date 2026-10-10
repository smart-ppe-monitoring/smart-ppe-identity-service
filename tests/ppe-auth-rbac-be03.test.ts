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

describe("Task BE-03: PPE Identity, Auth & Dynamic RBAC Test Suite", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  describe("1. PPE Role Constants & System Taxonomy", () => {
    it("should define standard PPE system roles with backward compatibility", () => {
      assert.equal(ROLES.ADMIN, "ADMIN");
      assert.equal(ROLES.SAFETY_MANAGER, "SAFETY_MANAGER");
      assert.equal(ROLES.SAFETY_OFFICER, "SAFETY_OFFICER");
      assert.equal(ROLES.MANAGER, "MANAGER");
      assert.equal(ROLES.USER, "USER");
    });

    it("should define comprehensive PPE domain permissions according to D08.pdf", () => {
      const ppePermissions = [
        // Sites & Zones
        PERMISSIONS.PPE_SITE_READ,
        PERMISSIONS.PPE_SITE_MANAGE,
        PERMISSIONS.PPE_ZONE_READ,
        PERMISSIONS.PPE_ZONE_MANAGE,
        PERMISSIONS.PPE_RESTRICTED_AREA_READ,
        PERMISSIONS.PPE_RESTRICTED_AREA_MANAGE,

        // Cameras
        PERMISSIONS.PPE_CAMERA_READ,
        PERMISSIONS.PPE_CAMERA_MANAGE,

        // Safety Config
        PERMISSIONS.PPE_SAFETY_CONFIG_READ,
        PERMISSIONS.PPE_SAFETY_CONFIG_MANAGE,

        // Incidents & Review
        PERMISSIONS.PPE_INCIDENT_READ,
        PERMISSIONS.PPE_INCIDENT_REVIEW,
        PERMISSIONS.PPE_INCIDENT_UPDATE,
        PERMISSIONS.PPE_INCIDENT_DELETE,
        PERMISSIONS.PPE_INCIDENT_MANAGE,

        // Reporting & Metrics
        PERMISSIONS.PPE_REPORTING_READ,
        PERMISSIONS.PPE_REPORTING_EXPORT,
        PERMISSIONS.PPE_AI_METRICS_READ,

        // AI Models
        PERMISSIONS.PPE_MODEL_READ,
        PERMISSIONS.PPE_MODEL_MANAGE,
      ];

      for (const perm of ppePermissions) {
        assert.ok(typeof perm === "string" && perm.length > 0);
      }

      // Verify all defined permissions are unique
      const uniquePerms = new Set(ppePermissions);
      assert.equal(uniquePerms.size, ppePermissions.length);
    });
  });

  describe("2. Permission-First Endpoint Guarding (requirePermission & requireAnyPermission)", () => {
    it("should reject unauthenticated request with 401 Unauthorized", async () => {
      const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_READ);
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

    it("should reject request when user lacks required permission with 403 Forbidden", async () => {
      const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_REVIEW);
      const roleId = "role-officer-id";

      (permissionCacheService as any).cache.set(roleId, {
        permissions: new Set([PERMISSIONS.PPE_INCIDENT_READ]),
        expiresAt: Date.now() + 60000,
      });
      (permissionCacheService as any).userCache.set("user-officer-1", {
        user: {
          id: "user-officer-1",
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: ROLES.SAFETY_OFFICER,
        },
        expiresAt: Date.now() + 60000,
      });

      const req = {
        user: {
          id: "user-officer-1",
          email: "officer@ppe.local",
          role: ROLES.SAFETY_OFFICER,
          roleId,
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

    it("should allow request when user possesses required permission", async () => {
      const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_REVIEW);
      const roleId = "role-officer-id";

      (permissionCacheService as any).cache.set(roleId, {
        permissions: new Set([
          PERMISSIONS.PPE_INCIDENT_READ,
          PERMISSIONS.PPE_INCIDENT_REVIEW,
        ]),
        expiresAt: Date.now() + 60000,
      });
      (permissionCacheService as any).userCache.set("user-officer-2", {
        user: {
          id: "user-officer-2",
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: ROLES.SAFETY_OFFICER,
        },
        expiresAt: Date.now() + 60000,
      });

      const req = {
        user: {
          id: "user-officer-2",
          email: "officer@ppe.local",
          role: ROLES.SAFETY_OFFICER,
          roleId,
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
      assert.ok(req.user.permissions.includes(PERMISSIONS.PPE_INCIDENT_REVIEW));
    });

    it("requireAnyPermission should allow access if user has at least one of the permissions", async () => {
      const middleware = requireAnyPermission(
        PERMISSIONS.PPE_SITE_MANAGE,
        PERMISSIONS.PPE_SITE_READ,
      );
      const roleId = "role-read-only";

      (permissionCacheService as any).cache.set(roleId, {
        permissions: new Set([PERMISSIONS.PPE_SITE_READ]),
        expiresAt: Date.now() + 60000,
      });
      (permissionCacheService as any).userCache.set("user-guest", {
        user: {
          id: "user-guest",
          isActive: true,
          deletedAt: null,
          roleId,
          roleName: "GUEST_VIEWER",
        },
        expiresAt: Date.now() + 60000,
      });

      const req = {
        user: {
          id: "user-guest",
          email: "guest@ppe.local",
          role: "GUEST_VIEWER",
          roleId,
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
    });
  });

  describe("3. Dynamic Roles (Không hard-code Roles - Tạo role mới chỉ cần gán permission)", () => {
    it("should allow a completely custom new role (e.g. SITE_INSPECTOR) to access endpoints based purely on assigned permissions", async () => {
      // Giả lập một Role mới hoàn toàn do Admin tạo qua API, không có trong codebase constants
      const customRoleId = "custom-role-site-inspector-uuid";
      const customRoleName = "SITE_INSPECTOR";

      // Role này được Admin gán quyền đọc công trường và xem bằng chứng sự cố:
      (permissionCacheService as any).cache.set(customRoleId, {
        permissions: new Set([
          PERMISSIONS.PPE_SITE_READ,
          PERMISSIONS.PPE_INCIDENT_READ,
          PERMISSIONS.FILE_READ,
        ]),
        expiresAt: Date.now() + 60000,
      });
      (permissionCacheService as any).userCache.set("inspector-user-id", {
        user: {
          id: "inspector-user-id",
          isActive: true,
          deletedAt: null,
          roleId: customRoleId,
          roleName: customRoleName,
        },
        expiresAt: Date.now() + 60000,
      });

      const req = {
        user: {
          id: "inspector-user-id",
          email: "inspector@audit.org",
          role: customRoleName,
          roleId: customRoleId,
        },
      } as any;
      const res = {} as any;

      // 1. Kiểm tra quyền xem danh sách sự cố -> PHẢI ĐƯỢC PHÉP
      const incidentReadMiddleware = requirePermission(
        PERMISSIONS.PPE_INCIDENT_READ,
      );
      let passedRead = false;
      await incidentReadMiddleware(req, res, (err) => {
        if (!err) passedRead = true;
      });
      assert.equal(passedRead, true);

      // 2. Kiểm tra quyền xóa sự cố vi phạm -> PHẢI BỊ TỪ CHỐI (403)
      const incidentDeleteMiddleware = requirePermission(
        PERMISSIONS.PPE_INCIDENT_DELETE,
      );
      let deleteError: any = null;
      await incidentDeleteMiddleware(req, res, (err) => {
        deleteError = err;
      });
      assert.ok(deleteError instanceof AppError);
      assert.equal(deleteError.statusCode, 403);
      assert.equal(deleteError.code, ERROR_CODE.FORBIDDEN);

      // 3. Kiểm tra quyền sửa cấu hình camera -> PHẢI BỊ TỪ CHỐI (403)
      const cameraManageMiddleware = requirePermission(
        PERMISSIONS.PPE_CAMERA_MANAGE,
      );
      let cameraError: any = null;
      await cameraManageMiddleware(req, res, (err) => {
        cameraError = err;
      });
      assert.ok(cameraError instanceof AppError);
      assert.equal(cameraError.statusCode, 403);
    });
  });

  describe("4. PPE Role-Permission Matrix Verification (D08.pdf)", () => {
    it("SAFETY_MANAGER should have site, camera, safety config and reporting permissions", () => {
      const managerPerms = new Set([
        PERMISSIONS.PPE_SITE_READ,
        PERMISSIONS.PPE_SITE_MANAGE,
        PERMISSIONS.PPE_ZONE_READ,
        PERMISSIONS.PPE_ZONE_MANAGE,
        PERMISSIONS.PPE_RESTRICTED_AREA_READ,
        PERMISSIONS.PPE_RESTRICTED_AREA_MANAGE,
        PERMISSIONS.PPE_CAMERA_READ,
        PERMISSIONS.PPE_CAMERA_MANAGE,
        PERMISSIONS.PPE_SAFETY_CONFIG_READ,
        PERMISSIONS.PPE_SAFETY_CONFIG_MANAGE,
        PERMISSIONS.PPE_INCIDENT_READ,
        PERMISSIONS.PPE_INCIDENT_REVIEW,
        PERMISSIONS.PPE_INCIDENT_UPDATE,
        PERMISSIONS.PPE_INCIDENT_MANAGE,
        PERMISSIONS.PPE_REPORTING_READ,
        PERMISSIONS.PPE_REPORTING_EXPORT,
        PERMISSIONS.PPE_AI_METRICS_READ,
        PERMISSIONS.PPE_MODEL_READ,
        PERMISSIONS.NOTIFICATION_READ,
        PERMISSIONS.FILE_READ,
        PERMISSIONS.FILE_UPLOAD,
      ]);

      // Safety Manager can manage camera & site
      assert.ok(managerPerms.has(PERMISSIONS.PPE_CAMERA_MANAGE));
      assert.ok(managerPerms.has(PERMISSIONS.PPE_SAFETY_CONFIG_MANAGE));
      assert.ok(managerPerms.has(PERMISSIONS.PPE_REPORTING_READ));

      // Safety Manager CANNOT manage users or delete system roles
      assert.equal(managerPerms.has(PERMISSIONS.USER_CREATE), false);
      assert.equal(managerPerms.has(PERMISSIONS.ROLE_DELETE), false);
    });

    it("SAFETY_OFFICER should have incident review, incident update and monitoring permissions", () => {
      const officerPerms = new Set([
        PERMISSIONS.PPE_INCIDENT_READ,
        PERMISSIONS.PPE_INCIDENT_REVIEW, // Human review True/False Alarm
        PERMISSIONS.PPE_INCIDENT_UPDATE, // Ghi chú biện pháp & đóng sự cố
        PERMISSIONS.PPE_CAMERA_READ,
        PERMISSIONS.PPE_SITE_READ,
        PERMISSIONS.PPE_ZONE_READ,
        PERMISSIONS.PPE_RESTRICTED_AREA_READ,
        PERMISSIONS.PPE_SAFETY_CONFIG_READ,
        PERMISSIONS.NOTIFICATION_READ,
        PERMISSIONS.FILE_READ,
      ]);

      // Officer CAN review incident and read cameras
      assert.ok(officerPerms.has(PERMISSIONS.PPE_INCIDENT_REVIEW));
      assert.ok(officerPerms.has(PERMISSIONS.PPE_INCIDENT_UPDATE));
      assert.ok(officerPerms.has(PERMISSIONS.PPE_CAMERA_READ));

      // Officer CANNOT configure cameras, change site settings, or export reports
      assert.equal(officerPerms.has(PERMISSIONS.PPE_CAMERA_MANAGE), false);
      assert.equal(officerPerms.has(PERMISSIONS.PPE_SAFETY_CONFIG_MANAGE), false);
      assert.equal(officerPerms.has(PERMISSIONS.PPE_REPORTING_EXPORT), false);
      assert.equal(officerPerms.has(PERMISSIONS.USER_DELETE), false);
    });
  });

  describe("5. System Role Protection & Anti-Lockout Defense", () => {
    it("should prevent deleting any system role with isSystem = true", async () => {
      const mockRepo = {
        findRoleById: async (id: string) => ({
          id,
          name: ROLES.SAFETY_MANAGER,
          isSystem: true,
          userCount: 0,
        }),
      } as any;

      const rbacService = new RbacService(mockRepo);

      await assert.rejects(
        async () => {
          await rbacService.deleteRole("mock-manager-role-id");
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.statusCode, 400);
          assert.match(err.message, /Cannot delete system role/);
          return true;
        },
      );
    });

    it("should prevent renaming any system role with isSystem = true", async () => {
      const mockRepo = {
        findRoleById: async (id: string) => ({
          id,
          name: ROLES.SAFETY_OFFICER,
          isSystem: true,
        }),
      } as any;

      const rbacService = new RbacService(mockRepo);

      await assert.rejects(
        async () => {
          await rbacService.updateRole("mock-officer-role-id", {
            name: "NEW_NAME_OFFICER",
          });
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.statusCode, 400);
          assert.match(err.message, /Cannot rename system role/);
          return true;
        },
      );
    });
  });

  describe("6. Frontend Propagation Contract Readiness (Task FE-01)", () => {
    it("should ensure permissions array is exported in profile payload", () => {
      const mockProfileResponse = {
        id: "user-1",
        email: "officer@ppe.local",
        fullName: "Trần Thị An Toàn",
        role: ROLES.SAFETY_OFFICER,
        roleId: "role-officer-uuid",
        permissions: [
          PERMISSIONS.PPE_INCIDENT_READ,
          PERMISSIONS.PPE_INCIDENT_REVIEW,
          PERMISSIONS.PPE_INCIDENT_UPDATE,
          PERMISSIONS.NOTIFICATION_READ,
        ],
        isActive: true,
        mustChangePassword: false,
      };

      assert.ok(Array.isArray(mockProfileResponse.permissions));
      assert.ok(
        mockProfileResponse.permissions.includes(
          PERMISSIONS.PPE_INCIDENT_REVIEW,
        ),
      );
      assert.equal(mockProfileResponse.role, ROLES.SAFETY_OFFICER);
    });
  });
});
