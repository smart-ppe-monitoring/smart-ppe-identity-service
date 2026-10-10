import { envConfig } from "../../config/env.config";
import {
  TURNSTILE_VERIFY_URL,
  TURNSTILE_DUMMY_SECRET_PASS,
  TurnstileAction,
} from "../constants/turnstile.constant";

export interface TurnstileVerifyResponse {
  success: boolean;
  "error-codes"?: string[];
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  cdata?: string;
}

export interface TurnstileVerifyOptions {
  remoteIp?: string;
  action?: TurnstileAction | string;
  idempotencyKey?: string;
}

export interface TurnstileVerificationResult {
  isValid: boolean;
  error?: string;
  hostname?: string;
  action?: string;
  challengeTs?: string;
  errorCodes?: string[];
}

export class TurnstileService {
  private enabled: boolean;
  private secretKey: string;
  private timeoutMs: number;

  constructor(options?: {
    enabled?: boolean;
    secretKey?: string;
    timeoutMs?: number;
  }) {
    this.enabled = options?.enabled ?? envConfig.turnstile.enabled;
    this.secretKey = options?.secretKey ?? envConfig.turnstile.secretKey;
    this.timeoutMs = options?.timeoutMs ?? 5000;
  }

  /**
   * Kiểm tra tính hợp lệ của Turnstile Response Token từ client.
   *
   * @param token Token do Cloudflare Turnstile sinh ra ở client
   * @param options Tuỳ chọn xác thực (remoteIp, action, idempotencyKey)
   * @param customFetcher Fetcher tuỳ biến phục vụ kiểm thử đơn vị
   */
  async verifyToken(
    token?: string | null,
    options?: TurnstileVerifyOptions,
    customFetcher?: (
      url: string | URL | Request,
      init?: RequestInit,
    ) => Promise<Response>,
  ): Promise<TurnstileVerificationResult> {
    // 1. Tự động bypass khi tính năng Turnstile chưa được bật (môi trường dev/test)
    if (!this.enabled) {
      return { isValid: true };
    }

    // 2. Chặn ngay nếu client không gửi token
    const trimmedToken = token?.trim();
    if (!trimmedToken) {
      return {
        isValid: false,
        error: "CAPTCHA_REQUIRED",
      };
    }

    // 3. Chuẩn bị payload theo chuẩn Cloudflare siteverify
    const secret = this.secretKey || TURNSTILE_DUMMY_SECRET_PASS;
    const body = new URLSearchParams();
    body.append("secret", secret);
    body.append("response", trimmedToken);

    if (options?.remoteIp) {
      body.append("remoteip", options.remoteIp);
    }
    if (options?.idempotencyKey) {
      body.append("idempotency_key", options.idempotencyKey);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    const fetchImpl = customFetcher ?? fetch;

    try {
      const response = await fetchImpl(TURNSTILE_VERIFY_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          isValid: false,
          error: "CAPTCHA_SERVICE_UNAVAILABLE",
        };
      }

      const data = (await response.json()) as TurnstileVerifyResponse;

      if (!data.success) {
        return {
          isValid: false,
          error: "CAPTCHA_INVALID",
          errorCodes: data["error-codes"],
        };
      }

      // 4. Nếu route yêu cầu kiểm tra hành động cụ thể, so khớp action từ Cloudflare
      if (options?.action && data.action && data.action !== options.action) {
        return {
          isValid: false,
          error: "CAPTCHA_ACTION_MISMATCH",
          action: data.action,
        };
      }

      return {
        isValid: true,
        hostname: data.hostname,
        action: data.action,
        challengeTs: data.challenge_ts,
      };
    } catch (err: any) {
      clearTimeout(timeoutId);
      const isAbort = err?.name === "AbortError";
      console.warn(
        `[TurnstileService] Xác thực Turnstile thất bại (${isAbort ? "Timeout" : "Network error"}):`,
        err?.message || err,
      );

      return {
        isValid: false,
        error: isAbort ? "CAPTCHA_TIMEOUT" : "CAPTCHA_NETWORK_ERROR",
      };
    }
  }

  /**
   * Kiểm tra trạng thái kích hoạt của dịch vụ Turnstile
   */
  isEnabled(): boolean {
    return this.enabled;
  }
}

export const turnstileService = new TurnstileService();
