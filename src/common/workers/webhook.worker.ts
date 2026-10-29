import http from "node:http";
import https from "node:https";
import { Worker, Job } from "bullmq";
import IORedis from "ioredis";
import { envConfig } from "../../config/env.config";
import { WEBHOOK_QUEUE_NAME, WebhookJobData } from "../queues/webhook.queue";
import { decryptSecret, signHmacSha256 } from "../helpers/crypto.helper";
import {
  isPublicHttpUrl,
  resolveAndValidateDns,
  isPrivateOrReservedIp,
} from "../helpers/url.helper";
import { integrationRepository } from "../../modules/integration/integration.repository";
import {
  WEBHOOK_STATUS,
  WEBHOOK_MAX_ATTEMPTS,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_EVENT_HEADER,
  WEBHOOK_DELIVERY_HEADER,
  WEBHOOK_TIMESTAMP_HEADER,
} from "../constants/integration.constant";

export interface WebhookExecutionResult {
  success: boolean;
  statusCode?: number;
  responseBody?: string;
  error?: string;
}

/**
 * SEC-10 Fix: Tạo HTTP Fetcher ghim trực tiếp socket kết nối đến IP cụ thể (pinnedIp)
 * đã được thẩm định an toàn (không phải Private, Loopback, Cloud Metadata hay Reserved IP).
 * Triệt tiêu hoàn toàn khả năng khai thác qua Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding.
 */
function createPinnedFetcher(
  pinnedIp: string,
): (url: string, init: RequestInit) => Promise<Response> {
  return (urlStr: string, init: RequestInit) => {
    return new Promise((resolve, reject) => {
      // Defense-in-depth: Kiểm tra lại IP trước khi mở socket
      if (isPrivateOrReservedIp(pinnedIp)) {
        return reject(
          new Error(
            `SSRF Blocked: Pinned IP '${pinnedIp}' is a private or reserved address`,
          ),
        );
      }

      const parsed = new URL(urlStr);
      const isHttps = parsed.protocol === "https:";
      const client = isHttps ? https : http;
      const defaultPort = isHttps ? 443 : 80;
      const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;

      const req = (client as typeof http).request(
        {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port,
          path: parsed.pathname + parsed.search,
          method: init.method || "POST",
          headers: init.headers as Record<string, string>,
          signal: (init.signal || undefined) as AbortSignal | undefined,
          // Ghim cứng DNS lookup vào IP đã được kiểm chứng an toàn
          lookup: (_hostname: string, opts: any, cb: any) => {
            const family = pinnedIp.includes(":") ? 6 : 4;
            if (opts && opts.all) {
              cb(null, [{ address: pinnedIp, family }]);
            } else {
              cb(null, pinnedIp, family);
            }
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          });
          res.on("end", () => {
            const rawBody = Buffer.concat(chunks).toString("utf8");
            resolve({
              ok: (res.statusCode || 0) >= 200 && (res.statusCode || 0) < 300,
              status: res.statusCode || 500,
              headers: {
                get: (name: string) => {
                  const val = res.headers[name.toLowerCase()];
                  return Array.isArray(val) ? val.join(", ") : val || null;
                },
              },
              text: async () => rawBody,
            } as unknown as Response);
          });
        },
      );

      req.on("error", reject);

      if (init.body) {
        req.write(init.body);
      }
      req.end();
    });
  };
}

export class WebhookWorker {
  private worker?: Worker<WebhookJobData>;
  private redisConnection?: IORedis;

  start(): void {
    if (!envConfig.redis.enabled || process.env.NODE_ENV === "test") {
      return;
    }

    try {
      this.redisConnection = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        retryStrategy: (times) => {
          if (times > 3) return null;
          return Math.min(times * 200, 1000);
        },
      });

      this.worker = new Worker<WebhookJobData>(
        WEBHOOK_QUEUE_NAME,
        async (job: Job<WebhookJobData>) => {
          await this.processJob(job.data, job.attemptsMade);
        },
        {
          connection: this.redisConnection,
          concurrency: 5,
        },
      );

      this.worker.on("completed", (job) => {
        console.log(
          `[WebhookWorker] ✅ Webhook delivery ${job.data.deliveryId} completed successfully`,
        );
      });

      this.worker.on("failed", (job, err) => {
        console.error(
          `[WebhookWorker] ❌ Webhook delivery ${job?.data.deliveryId} failed attempt ${(job?.attemptsMade || 0) + 1}: ${err.message}`,
        );
      });
    } catch (err: any) {
      console.warn(
        "[WebhookWorker] Could not connect to Redis for Webhook Worker:",
        err?.message,
      );
    }
  }

  async stop(): Promise<void> {
    if (this.worker) {
      await this.worker.close().catch(() => {});
    }
    if (this.redisConnection) {
      this.redisConnection.disconnect();
    }
  }

  /**
   * Xử lý gửi 1 webhook job: SSRF check -> Decrypt Secret -> Sign HMAC -> HTTP POST -> Log DB.
   */
  async processJob(
    data: WebhookJobData,
    attemptsMade: number = 0,
    customFetcher?: (url: string, init: RequestInit) => Promise<Response>,
  ): Promise<WebhookExecutionResult> {
    const currentAttempt = attemptsMade + 1;
    const maxAttempts = envConfig.webhook.maxAttempts || WEBHOOK_MAX_ATTEMPTS;

    // 1. SSRF Safety Check: Cú pháp URL & DNS Resolution
    const isUrlSyntaxValid = isPublicHttpUrl(data.url);
    if (!isUrlSyntaxValid) {
      const errorMsg = `SSRF Check Failed: URL '${data.url}' contains private, loopback or invalid host`;
      await integrationRepository
        .updateDeliveryStatus(data.deliveryId, {
          status: WEBHOOK_STATUS.FAILED,
          attempts: currentAttempt,
          lastError: errorMsg,
        })
        .catch(() => {});
      return { success: false, error: errorMsg };
    }

    let pinnedIp: string | undefined;

    // SEC (F-03 & SEC-10): Thực hiện DNS resolution check chống DNS Rebinding trên mọi môi trường
    // (production, staging, development) với allowPrivate: false.
    // Bỏ qua khi customFetcher được cung cấp (mock harness trong unit tests).
    if (!customFetcher) {
      try {
        const parsed = new URL(data.url);
        const dnsCheck = await resolveAndValidateDns(parsed.hostname, {
          allowPrivate: false,
        });
        if (!dnsCheck.isValid || !dnsCheck.ips || dnsCheck.ips.length === 0) {
          const errorMsg = `SSRF DNS Check Failed: ${dnsCheck.reason || "No valid public IP resolved"}`;
          await integrationRepository
            .updateDeliveryStatus(data.deliveryId, {
              status: WEBHOOK_STATUS.FAILED,
              attempts: currentAttempt,
              lastError: errorMsg,
            })
            .catch(() => {});
          return { success: false, error: errorMsg };
        }
        pinnedIp = dnsCheck.ips[0];
      } catch (err: any) {
        return { success: false, error: `Invalid URL: ${err?.message}` };
      }
    }

    // 2. Decrypt HMAC secret
    let plainSecret: string;
    try {
      plainSecret = decryptSecret(data.encryptedSecret);
    } catch (err: any) {
      const errorMsg = `Failed to decrypt webhook secret: ${err?.message}`;
      await integrationRepository
        .updateDeliveryStatus(data.deliveryId, {
          status: WEBHOOK_STATUS.FAILED,
          attempts: currentAttempt,
          lastError: errorMsg,
        })
        .catch(() => {});
      return { success: false, error: errorMsg };
    }

    // 3. Serialize payload & compute HMAC signature
    const payloadString = JSON.stringify(data.payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const { header: signatureHeader, signature } = signHmacSha256(
      payloadString,
      plainSecret,
      timestamp,
    );

    // 4. Update status to PROCESSING
    await integrationRepository
      .updateDeliveryStatus(data.deliveryId, {
        status: WEBHOOK_STATUS.PROCESSING,
        signature,
        attempts: currentAttempt,
      })
      .catch(() => {});

    // 5. Send HTTP POST request
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      envConfig.webhook.timeoutMs || 10000,
    );

    let statusCode: number | undefined;
    let responseText = "";

    try {
      // SEC-10 Fix: Ghim chặt kết nối socket đến IP đã kiểm tra (pinnedIp) chống TOCTOU DNS Rebinding
      const fetchFn =
        customFetcher || (pinnedIp ? createPinnedFetcher(pinnedIp) : fetch);
      const res = await fetchFn(data.url, {
        method: "POST",
        redirect: "manual", // SEC-02: Chặn tự động chuyển hướng HTTP (chống SSRF qua 301/302 redirect sang IP nội bộ)
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "App-Webhook-Dispatcher/1.0",
          [WEBHOOK_EVENT_HEADER]: data.event,
          [WEBHOOK_DELIVERY_HEADER]: data.deliveryId,
          [WEBHOOK_SIGNATURE_HEADER]: signatureHeader,
          [WEBHOOK_TIMESTAMP_HEADER]: String(timestamp),
        },
        body: payloadString,
        signal: controller.signal,
      });

      statusCode = res.status;

      // SEC-02: Nếu nhận mã chuyển hướng 3xx, từ chối xử lý và ghi nhận lỗi bảo mật
      if (res.status >= 300 && res.status < 400) {
        const redirectLocation = res.headers.get("location") || "unknown";
        const errorMsg = `SSRF Protection: Webhook endpoint attempted disallowed redirect to '${redirectLocation}'`;
        await integrationRepository
          .updateDeliveryStatus(data.deliveryId, {
            status: WEBHOOK_STATUS.FAILED,
            statusCode: res.status,
            attempts: currentAttempt,
            lastError: errorMsg,
          })
          .catch(() => {});
        return { success: false, statusCode: res.status, error: errorMsg };
      }

      try {
        responseText = (await res.text()).slice(0, 1000);
      } catch {
        responseText = "";
      }

      if (res.ok) {
        // HTTP 2xx -> Success
        await integrationRepository
          .updateDeliveryStatus(data.deliveryId, {
            status: WEBHOOK_STATUS.SUCCESS,
            statusCode,
            responseBody: responseText,
            deliveredAt: new Date(),
            lastError: null,
            attempts: currentAttempt,
          })
          .catch(() => {});

        return { success: true, statusCode, responseBody: responseText };
      } else {
        // Non-2xx response -> Fail and trigger retry if attempts remain
        const isFinalFail = currentAttempt >= maxAttempts;
        const errorMsg = `Webhook receiver responded with HTTP ${statusCode}: ${responseText}`;

        await integrationRepository
          .updateDeliveryStatus(data.deliveryId, {
            status: isFinalFail
              ? WEBHOOK_STATUS.FAILED
              : WEBHOOK_STATUS.PENDING,
            statusCode,
            responseBody: responseText,
            lastError: errorMsg,
            attempts: currentAttempt,
          })
          .catch(() => {});

        throw new Error(errorMsg);
      }
    } catch (err: any) {
      const isFinalFail = currentAttempt >= maxAttempts;
      const errorMsg = err?.message || "Network request error";

      await integrationRepository
        .updateDeliveryStatus(data.deliveryId, {
          status: isFinalFail ? WEBHOOK_STATUS.FAILED : WEBHOOK_STATUS.PENDING,
          statusCode: statusCode || null,
          responseBody: responseText || null,
          lastError: errorMsg,
          attempts: currentAttempt,
        })
        .catch(() => {});

      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

export const webhookWorker = new WebhookWorker();
