import { Router } from "express";
import { UserController } from "./user.controller";
import { authMiddleware } from "../../middlewares/auth.middleware";
import { requireInternalServiceToken } from "../../middlewares/internal-auth.middleware";
import {
  requirePermission,
  requireAnyPermission,
} from "../../middlewares/permission.middleware";
import { validate } from "../../middlewares/validate.middleware";
import {
  createUserSchema,
  findAllUserSchema,
  updateUserSchema,
  assignUserSitesSchema,
  userIdParamSchema,
  userSessionParamsSchema,
  userDeviceParamsSchema,
  adminResetPasswordSchema,
  internalIncidentRecipientsQuerySchema,
} from "./user.validation";
import { PERMISSIONS } from "../../common/constants/permission.constant";

const router = Router();
const controller = new UserController();

router.get(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_READ),
  validate(findAllUserSchema, "query"),
  controller.findAll,
);
// Summary KPI endpoint (MUST stay before /:id param route)
router.get(
  "/summary",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_READ),
  controller.getSummary,
);
// Internal M2M endpoint (MUST stay before /:id param route)
router.get(
  "/internal/incident-recipients",
  requireInternalServiceToken,
  validate(internalIncidentRecipientsQuerySchema, "query"),
  controller.findIncidentNotificationRecipients,
);
router.get(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_READ),
  validate(userIdParamSchema, "params"),
  controller.findById,
);
router.post(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_CREATE),
  validate(createUserSchema),
  controller.create,
);
router.put(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userIdParamSchema, "params"),
  validate(updateUserSchema),
  controller.update,
);
router.put(
  "/:id/sites",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userIdParamSchema, "params"),
  validate(assignUserSitesSchema),
  controller.assignSites,
);
router.delete(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_DELETE),
  validate(userIdParamSchema, "params"),
  controller.softDelete,
);
router.post(
  "/:id/restore",
  authMiddleware,
  requireAnyPermission(PERMISSIONS.USER_RESTORE, PERMISSIONS.USER_DELETE),
  validate(userIdParamSchema, "params"),
  controller.restore,
);
router.post(
  "/:id/reset-password",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userIdParamSchema, "params"),
  validate(adminResetPasswordSchema),
  controller.adminResetPassword,
);

router.get(
  "/:id/sessions",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_READ),
  validate(userIdParamSchema, "params"),
  controller.getUserSessions,
);
router.delete(
  "/:id/sessions/:sessionId",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userSessionParamsSchema, "params"),
  controller.revokeUserSession,
);
router.delete(
  "/:id/sessions",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userIdParamSchema, "params"),
  controller.revokeAllUserSessions,
);

router.get(
  "/:id/devices",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_READ),
  validate(userIdParamSchema, "params"),
  controller.getUserDevices,
);
router.delete(
  "/:id/devices/:deviceId",
  authMiddleware,
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate(userDeviceParamsSchema, "params"),
  controller.deleteUserDevice,
);

export default router;
