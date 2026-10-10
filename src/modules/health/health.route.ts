import { Router } from "express";
import { healthController } from "./health.controller";
import { rateLimitMiddleware } from "../../middlewares/rate-limit.middleware";

const router = Router();

router.get("/", healthController.getHealth);
router.get("/liveness", healthController.getLiveness);
router.get("/readiness", rateLimitMiddleware, healthController.getReadiness);

export default router;
