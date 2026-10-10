import { Router, Request, Response, NextFunction } from "express";
import { AuthController } from "./auth.controller";
import { authMiddleware } from "../../middlewares/auth.middleware";
import { authRateLimitMiddleware } from "../../middlewares/rate-limit.middleware";
import { turnstileGuard } from "../../middlewares/turnstile.middleware";
import { TURNSTILE_ACTION } from "../../common/constants/turnstile.constant";
import { validate } from "../../middlewares/validate.middleware";
import {
  loginSchema,
  refreshSchema,
  logoutSchema,
  revokeOtherSessionsSchema,
  registerSchema,
  verifyEmailSchema,
  updateProfileSchema,
  updatePasswordSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  resendVerificationSchema,
  sessionIdParamSchema,
  getAvatarUploadUrlSchema,
  confirmAvatarUploadSchema,
  requestDeactivateSchema,
  confirmDeactivateSchema,
  enable2FASchema,
  verify2FALoginSchema,
  disable2FASchema,
  regenerateBackupCodesSchema,
  googleLoginSchema,
  googleAuthUrlQuerySchema,
  linkSocialAccountSchema,
  unlinkSocialAccountParamSchema,
} from "./auth.validation";

const router = Router();
const controller = new AuthController();

router.post(
  "/register",
  authRateLimitMiddleware,
  turnstileGuard({ action: TURNSTILE_ACTION.REGISTER }),
  validate(registerSchema),
  controller.register,
);
router.get(
  "/verify-email",
  validate(verifyEmailSchema, "query"),
  controller.verifyEmail,
);
router.post(
  "/login",
  authRateLimitMiddleware,
  validate(loginSchema),
  controller.login,
);
router.get("/me", authMiddleware, controller.me);

const populateRefreshToken = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  if (!req.body) {
    req.body = {};
  }
  if (!req.body.refreshToken && req.cookies?.refreshToken) {
    req.body.refreshToken = req.cookies.refreshToken;
  }
  next();
};

router.post(
  "/refresh",
  authRateLimitMiddleware,
  populateRefreshToken,
  validate(refreshSchema),
  controller.refresh,
);
router.post("/logout", validate(logoutSchema), controller.logout);
router.put(
  "/profile",
  authMiddleware,
  validate(updateProfileSchema),
  controller.updateProfile,
);
router.put(
  "/password",
  authMiddleware,
  validate(updatePasswordSchema),
  controller.updatePassword,
);
router.post(
  "/forgot-password",
  authRateLimitMiddleware,
  turnstileGuard({ action: TURNSTILE_ACTION.FORGOT_PASSWORD }),
  validate(forgotPasswordSchema),
  controller.forgotPassword,
);
router.post(
  "/reset-password",
  authRateLimitMiddleware,
  validate(resetPasswordSchema),
  controller.resetPassword,
);
router.post(
  "/resend-verification",
  authRateLimitMiddleware,
  turnstileGuard({ action: TURNSTILE_ACTION.RESEND_VERIFICATION }),
  validate(resendVerificationSchema),
  controller.resendVerification,
);

router.get("/sessions", authMiddleware, controller.getSessions);
router.delete(
  "/sessions/:id",
  authMiddleware,
  validate(sessionIdParamSchema, "params"),
  controller.revokeSession,
);
router.delete(
  "/sessions",
  authMiddleware,
  populateRefreshToken,
  validate(revokeOtherSessionsSchema),
  controller.revokeOtherSessions,
);

router.post(
  "/avatar/upload-url",
  authMiddleware,
  validate(getAvatarUploadUrlSchema),
  controller.getAvatarUploadUrl,
);
router.post(
  "/avatar/confirm",
  authMiddleware,
  validate(confirmAvatarUploadSchema),
  controller.confirmAvatarUpload,
);

router.post(
  "/deactivate/request",
  authMiddleware,
  authRateLimitMiddleware,
  validate(requestDeactivateSchema),
  controller.requestDeactivate,
);
router.post(
  "/deactivate/confirm",
  authRateLimitMiddleware,
  validate(confirmDeactivateSchema),
  controller.confirmDeactivate,
);

router.post(
  "/2fa/setup",
  authMiddleware,
  authRateLimitMiddleware,
  controller.setup2FA,
);
router.post(
  "/2fa/enable",
  authMiddleware,
  authRateLimitMiddleware,
  validate(enable2FASchema),
  controller.enable2FA,
);
router.post(
  "/2fa/verify",
  authRateLimitMiddleware,
  validate(verify2FALoginSchema),
  controller.verify2FALogin,
);
router.post(
  "/2fa/disable",
  authMiddleware,
  authRateLimitMiddleware,
  validate(disable2FASchema),
  controller.disable2FA,
);
router.post(
  "/2fa/backup-codes/regenerate",
  authMiddleware,
  authRateLimitMiddleware,
  validate(regenerateBackupCodesSchema),
  controller.regenerateBackupCodes,
);

router.get(
  "/google/url",
  authRateLimitMiddleware,
  validate(googleAuthUrlQuerySchema, "query"),
  controller.getGoogleAuthUrl,
);
router.post(
  "/google",
  authRateLimitMiddleware,
  validate(googleLoginSchema),
  controller.googleLogin,
);

router.get("/social", authMiddleware, controller.getSocialAccounts);
router.post(
  "/social/link",
  authMiddleware,
  authRateLimitMiddleware,
  validate(linkSocialAccountSchema),
  controller.linkSocialAccount,
);
router.delete(
  "/social/:provider",
  authMiddleware,
  authRateLimitMiddleware,
  validate(unlinkSocialAccountParamSchema, "params"),
  controller.unlinkSocialAccount,
);

export default router;
