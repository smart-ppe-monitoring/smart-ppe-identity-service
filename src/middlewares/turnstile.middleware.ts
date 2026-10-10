import { Request, Response, NextFunction } from "express";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import {
  TURNSTILE_HEADERS,
  TURNSTILE_BODY_KEY,
  TurnstileAction,
} from "../common/constants/turnstile.constant";
import {
  turnstileService,
  TurnstileService,
} from "../common/services/turnstile.service";

export interface TurnstileGuardOptions {
  /** Hành động (Action) dự kiến khớp với client (vd: 'register', 'forgot_password') */
  action?: TurnstileAction | string;
  /** Service tuỳ biến phục vụ kiểm thử đơn vị */
  service?: TurnstileService;
}

/**
 * Trích xuất Turnstile token từ Request Headers hoặc Request Body.
 */
export function extractTurnstileToken(req: Request): string | undefined {
  // 1. Kiểm tra headers
  const headerResponse = req.headers[TURNSTILE_HEADERS.RESPONSE];
  if (typeof headerResponse === "string" && headerResponse.trim().length > 0) {
    return headerResponse.trim();
  }

  const headerToken = req.headers[TURNSTILE_HEADERS.TOKEN];
  if (typeof headerToken === "string" && headerToken.trim().length > 0) {
    return headerToken.trim();
  }

  // 2. Kiểm tra body
  if (req.body && typeof req.body === "object") {
    const bodyToken = req.body[TURNSTILE_BODY_KEY];
    if (typeof bodyToken === "string" && bodyToken.trim().length > 0) {
      return bodyToken.trim();
    }

    const bodyAltToken = req.body[TURNSTILE_HEADERS.RESPONSE];
    if (typeof bodyAltToken === "string" && bodyAltToken.trim().length > 0) {
      return bodyAltToken.trim();
    }
  }

  return undefined;
}

/**
 * Factory tạo Middleware bảo vệ endpoint bằng Cloudflare Turnstile CAPTCHA.
 * Tự động trích xuất token, lấy client IP thật (hỗ trợ Cloudflare cf-connecting-ip)
 * và chuyển giao kiểm tra cho TurnstileService.
 */
export function turnstileGuard(options?: TurnstileGuardOptions) {
  const service = options?.service ?? turnstileService;

  return async (
    req: Request,
    _res: Response,
    next: NextFunction,
  ): Promise<void> => {
    // Nếu tính năng Turnstile chưa được kích hoạt, cho qua ngay
    if (!service.isEnabled()) {
      return next();
    }

    const token = extractTurnstileToken(req);

    // Lấy client IP từ Cloudflare header, req.ip hoặc socket
    const remoteIp = (
      (req.headers["cf-connecting-ip"] as string) ||
      req.ip ||
      req.socket?.remoteAddress ||
      ""
    ).replace(/^::ffff:/, "");

    const result = await service.verifyToken(token, {
      remoteIp,
      action: options?.action,
    });

    if (!result.isValid) {
      if (result.error === "CAPTCHA_REQUIRED") {
        return next(
          new AppError(
            "Captcha verification token is required",
            400,
            ERROR_CODE.CAPTCHA_REQUIRED,
          ),
        );
      }

      return next(
        new AppError(
          "Captcha verification failed. Please try again.",
          400,
          ERROR_CODE.CAPTCHA_INVALID,
        ),
      );
    }

    next();
  };
}

/**
 * Shorthand middleware cho các endpoint không yêu cầu xác thực action cụ thể
 */
export const turnstileMiddleware = turnstileGuard();
