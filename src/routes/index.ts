import { Router } from "express";
import authRoute from "../modules/auth/auth.route";
import userRoute from "../modules/users/user.route";
import rbacRoute from "../modules/rbac/rbac.route";
import maintenanceRoute from "../modules/maintenance/maintenance.route";
import integrationRoute from "../modules/integration/integration.route";
import systemConfigRoute from "../modules/system-config/system-config.route";
import cronRoute from "../modules/cron/cron.route";
import healthRoute from "../modules/health/health.route";
import securityTxtRoute from "../modules/security-txt/security-txt.route";
import { jwksRoute } from "../modules/jwks/jwks.route";
import { maintenanceGuard } from "../middlewares/maintenance.middleware";

import auditRoute from "../modules/audit/audit.route";

const router = Router();

// Observability, Diagnostics & Security Disclosure
router.use("/health", healthRoute);
router.use(securityTxtRoute);
router.use(jwksRoute);

// Maintenance Mode Controls & Public Status
router.use("/maintenance", maintenanceRoute);

// Maintenance Enforcement Guard for all Business APIs below
router.use(maintenanceGuard());

// System Configuration & Feature Flags Endpoints (exempted public paths handled inside guard)
router.use("/system", systemConfigRoute);
router.use("/auth", authRoute);
router.use("/users", userRoute);
router.use("/rbac", rbacRoute);
router.use("/integration", integrationRoute);
router.use("/cron", cronRoute);
router.use("/audit-logs", auditRoute);

export default router;

