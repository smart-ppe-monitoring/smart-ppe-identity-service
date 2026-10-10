import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../config/jwt.config";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { permissionCacheService } from "../common/services/permission-cache.service";
import { jwtKeyService } from "../common/services/jwt-key.service";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../common/constants/jwt.constant";

export function extractTokenFromRequest(req: Request): string | undefined {
  let token = req.cookies?.accessToken;
  if (!token) {
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }
  }

  // Chống rò rỉ JWT qua Query String:
  // Chỉ cho phép nhận token/ticket qua query string cho các endpoint SSE (/stream) hoặc direct download (/download)
  // (tránh bị lưu trong proxy log, web server log và browser history).
  const cleanPath = (
    (req.baseUrl || "") + (req.path || req.originalUrl || "")
  ).split("?")[0];
  const isAllowedQueryTokenEndpoint =
    cleanPath.endsWith("/stream") || cleanPath.endsWith("/download");

  if (!token && isAllowedQueryTokenEndpoint) {
    const queryToken = req.query?.ticket || req.query?.token;
    if (typeof queryToken === "string") {
      token = queryToken;
    }
  }
  return token;
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const cleanPath = (
    (req.baseUrl || "") + (req.path || req.originalUrl || "")
  ).split("?")[0];
  const isAllowedQueryTokenEndpoint =
    cleanPath.endsWith("/stream") || cleanPath.endsWith("/download");

  // Chặn hoàn toàn việc nhận ?token= ở các API thông thường
  if (!isAllowedQueryTokenEndpoint && req.query?.token) {
    next(
      new AppError(
        "Không được phép truyền token xác thực qua query string trên API thông thường để tránh rò rỉ qua log và browser history",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      ),
    );
    return;
  }

  const token = extractTokenFromRequest(req);

  if (!token) {
    next(new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED));
    return;
  }

  const isStreamPath = cleanPath.endsWith("/stream");

  try {
    let payload:
      | {
          id: string;
          email: string;
          role: string;
          roleId?: string;
          purpose?: string;
          type?: string;
        }
      | undefined;

    // SEC (F-01): Nếu là stream connection, ưu tiên verify bằng tempSecret dành cho short-lived SSE ticket
    if (isStreamPath) {
      try {
        payload = jwt.verify(token, jwtConfig.tempSecret, {
          algorithms: [JWT_ALGORITHM.HS256],
        }) as any;
      } catch {
        // Fallback sang accessSecret / RS256 bên dưới
      }
    }

    if (!payload) {
      payload = jwtKeyService.verifyAccessToken(token) as any;
    }

    // SEC: Token SSE ticket chỉ được dùng cho /stream, tuyệt đối không được dùng cho route khác
    if (
      payload &&
      payload.purpose === JWT_PURPOSE.SSE_STREAM_TICKET &&
      !isStreamPath
    ) {
      next(
        new AppError(
          "Token SSE ticket chỉ hợp lệ khi kết nối luồng dữ liệu /stream",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // SEC-01: Chặn tuyệt đối token tạm thời khác (2FA verification / temp token) truy cập tài nguyên bảo vệ
    if (
      !payload ||
      payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
      payload.type === "TEMP" ||
      (payload.purpose &&
        payload.purpose !== JWT_PURPOSE.ACCESS &&
        !(isStreamPath && payload.purpose === JWT_PURPOSE.SSE_STREAM_TICKET))
    ) {
      next(
        new AppError(
          "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // Xác thực trạng thái người dùng (cached 60s) chống dùng JWT cũ khi tài khoản bị khóa hoặc xóa mềm
    const userState = await permissionCacheService.getUserState(payload.id);
    if (!userState || !userState.isActive || userState.deletedAt) {
      next(
        new AppError(
          "Tài khoản của bạn đã bị vô hiệu hóa hoặc không tồn tại",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    req.user = {
      id: payload.id,
      email: payload.email,
      role: userState.roleName || payload.role,
      roleId: userState.roleId || payload.roleId,
    };

    next();
  } catch (error) {
    if (error instanceof AppError) {
      next(error);
    } else if (error instanceof jwt.TokenExpiredError) {
      next(new AppError("Token expired", 401, ERROR_CODE.TOKEN_EXPIRED));
    } else {
      next(new AppError("Invalid token", 401, ERROR_CODE.TOKEN_INVALID));
    }
  }
}

/**
 * Middleware xác thực tùy chọn (Optional Auth).
 * Nếu có JWT hợp lệ thì gán req.user, nếu không có hoặc token sai thì bỏ qua và next()
 * không trả 401. Dùng cho các API public nhưng vẫn muốn context user nếu đã đăng nhập.
 */
export async function optionalAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = extractTokenFromRequest(req);

  if (!token) {
    next();
    return;
  }

  try {
    const payload = jwtKeyService.verifyAccessToken(token) as {
      id: string;
      email: string;
      role: string;
      roleId?: string;
      purpose?: string;
      type?: string;
    };

    if (
      payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
      payload.type === "TEMP" ||
      (payload.purpose && payload.purpose !== JWT_PURPOSE.ACCESS)
    ) {
      next();
      return;
    }

    const userState = await permissionCacheService.getUserState(payload.id);
    if (userState && userState.isActive && !userState.deletedAt) {
      req.user = {
        id: payload.id,
        email: payload.email,
        role: userState.roleName || payload.role,
        roleId: userState.roleId || payload.roleId,
      };
    }
  } catch {
    // Bỏ qua lỗi token nếu là optional auth (xem như khách vãng lai)
  }

  next();
}
