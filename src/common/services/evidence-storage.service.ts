import crypto from "node:crypto";
import path from "node:path";
import { uuidv7 } from "uuidv7";
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { envConfig } from "../../config/env.config";
import { AppError } from "../errors/app-error";
import { ERROR_CODE } from "../errors/error-code";

export interface GenerateStorageKeyParams {
  siteId: string;
  cameraId: string;
  incidentId: string;
  evidenceType: string;
  originalFileName: string;
}

export interface UploadBufferResult {
  storageKey: string;
  fileSize: number;
  checksum: string;
}

export interface VerifyChecksumResult {
  isValid: boolean;
  actualChecksum: string;
  expectedChecksum: string;
}

export class EvidenceStorageService {
  private readonly client: S3Client;
  private readonly bucketName: string;

  constructor(s3Client?: S3Client, bucket?: string) {
    this.bucketName = bucket || envConfig.minio.bucketEvidences || "ppe-evidences";

    if (s3Client) {
      this.client = s3Client;
    } else {
      const minioConfig = envConfig.minio;
      const isMinio = Boolean(minioConfig.endpoint && minioConfig.endpoint.trim());

      if (isMinio) {
        // Cấu hình S3 Client kết nối tới MinIO S3 Object Storage
        this.client = new S3Client({
          region: "us-east-1", // MinIO mặc định us-east-1
          endpoint: minioConfig.endpoint,
          credentials: {
            accessKeyId: minioConfig.accessKeyId,
            secretAccessKey: minioConfig.secretAccessKey,
          },
          forcePathStyle: minioConfig.forcePathStyle, // MinIO yêu cầu forcePathStyle = true
        });
      } else {
        // Fallback sang Cloudflare R2 nếu không dùng MinIO
        const r2 = envConfig.r2;
        this.client = new S3Client({
          region: "auto",
          endpoint: `https://${r2.accountId}.r2.cloudflarestorage.com`,
          credentials: {
            accessKeyId: r2.accessKeyId,
            secretAccessKey: r2.secretAccessKey,
          },
        });
      }
    }
  }

  getBucketName(): string {
    return this.bucketName;
  }

  /**
   * Sinh storageKey chuẩn hóa có phân cấp ngày tháng và thông tin công trường, camera, sự cố
   * Cấu trúc: evidences/{siteId}/{cameraId}/{YYYY}/{MM}/{DD}/{incidentId}/{evidenceType}_{timestamp}_{uuid}.{ext}
   */
  generateStorageKey(params: GenerateStorageKeyParams): string {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    const timestamp = Date.now();
    const uniqueId = uuidv7();

    const rawExt = path.extname(params.originalFileName || "").toLowerCase();
    const ext = rawExt && /^\.[a-z0-9]+$/i.test(rawExt) ? rawExt : ".jpg";

    const cleanType = (params.evidenceType || "SNAPSHOT").toUpperCase();

    return `evidences/${params.siteId}/${params.cameraId}/${year}/${month}/${day}/${params.incidentId}/${cleanType}_${timestamp}_${uniqueId}${ext}`;
  }

  /**
   * Tính toán chuỗi băm mật mã SHA-256 (64 ký tự hex) cho dữ liệu tệp
   */
  calculateSha256(buffer: Buffer): string {
    return crypto.createHash("sha256").update(buffer).digest("hex");
  }

  /**
   * Sinh Presigned PUT URL để client hoặc AI Vision upload trực tiếp lên MinIO/S3
   */
  async getPresignedUploadUrl(
    storageKey: string,
    mimeType: string,
    expiresInSeconds: number = 900, // 15 phút
  ): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: storageKey,
      ContentType: mimeType,
    });

    return getSignedUrl(this.client, command, {
      expiresIn: expiresInSeconds,
    });
  }

  /**
   * Sinh Presigned GET URL để client tải hoặc xem bằng chứng an toàn có hạn định
   * @param action "VIEW" (inline) | "DOWNLOAD" (attachment)
   */
  async getPresignedDownloadUrl(
    storageKey: string,
    expiresInSeconds: number = 3600, // 1 giờ
    originalFileName?: string,
    action: string = "VIEW",
  ): Promise<string> {
    let contentDisposition: string | undefined = undefined;
    if (originalFileName) {
      const asciiFallback = originalFileName
        .replace(/[^\x20-\x7E]/g, "_")
        .replace(/["\\]/g, "");
      const utf8Encoded = encodeURIComponent(originalFileName);
      const dispositionType = action.toUpperCase() === "DOWNLOAD" ? "attachment" : "inline";
      contentDisposition = `${dispositionType}; filename="${asciiFallback}"; filename*=UTF-8''${utf8Encoded}`;
    }

    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: storageKey,
      ResponseContentDisposition: contentDisposition,
    });

    return getSignedUrl(this.client, command, {
      expiresIn: expiresInSeconds,
    });
  }

  /**
   * Đẩy trực tiếp buffer tệp lên Object Storage và tính toán SHA-256 Checksum
   */
  async uploadBuffer(
    storageKey: string,
    buffer: Buffer,
    mimeType: string,
  ): Promise<UploadBufferResult> {
    const checksum = this.calculateSha256(buffer);

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: storageKey,
      Body: buffer,
      ContentType: mimeType,
      Metadata: {
        "sha256-checksum": checksum,
      },
    });

    await this.client.send(command);

    return {
      storageKey,
      fileSize: buffer.length,
      checksum,
    };
  }

  /**
   * Tải toàn bộ nội dung tệp từ Object Storage về bộ nhớ đệm Buffer
   */
  async getObjectBuffer(storageKey: string): Promise<Buffer> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: storageKey,
      });

      const response = await this.client.send(command);
      if (!response.Body) {
        throw new AppError(
          "Tệp trên kho lưu trữ không có nội dung",
          404,
          ERROR_CODE.FILE_NOT_FOUND,
        );
      }

      const chunks: Uint8Array[] = [];
      const stream = response.Body as AsyncIterable<Uint8Array>;
      for await (const chunk of stream) {
        chunks.push(chunk);
      }

      return Buffer.concat(chunks);
    } catch (error: any) {
      if (error instanceof AppError) throw error;
      if (error.name === "NoSuchKey" || error.$metadata?.httpStatusCode === 404) {
        throw new AppError(
          `Không tìm thấy tệp tin trên Object Storage (${storageKey})`,
          404,
          ERROR_CODE.FILE_NOT_FOUND,
        );
      }
      throw new AppError(
        `Lỗi khi truy xuất tệp từ Object Storage: ${error.message}`,
        500,
        ERROR_CODE.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Tính toán SHA-256 Checksum trực tiếp từ Readable Stream trên Object Storage mà không giữ toàn bộ tệp trong RAM
   */
  async computeChecksumFromStorage(storageKey: string): Promise<string> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: storageKey,
      });

      const response = await this.client.send(command);
      if (!response.Body) {
        throw new AppError(
          "Tệp trên kho lưu trữ không có nội dung",
          404,
          ERROR_CODE.FILE_NOT_FOUND,
        );
      }

      const hash = crypto.createHash("sha256");
      const stream = response.Body as AsyncIterable<Uint8Array>;
      for await (const chunk of stream) {
        hash.update(chunk);
      }

      return hash.digest("hex");
    } catch (error: any) {
      if (error instanceof AppError) throw error;
      if (error.name === "NoSuchKey" || error.$metadata?.httpStatusCode === 404) {
        throw new AppError(
          `Không tìm thấy tệp tin trên Object Storage (${storageKey})`,
          404,
          ERROR_CODE.FILE_NOT_FOUND,
        );
      }
      throw new AppError(
        `Lỗi khi truy xuất tệp từ Object Storage: ${error.message}`,
        500,
        ERROR_CODE.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Xác thực tính toàn vẹn pháp lý (Tamper Evidence Checksum Verification)
   * Tải tệp từ MinIO/S3 dạng stream, tính SHA-256 thực tế và so khớp an toàn với expectedChecksum
   */
  async verifyChecksum(
    storageKey: string,
    expectedChecksum: string,
  ): Promise<VerifyChecksumResult> {
    const actualChecksum = await this.computeChecksumFromStorage(storageKey);

    let isValid = false;
    try {
      if (
        actualChecksum &&
        expectedChecksum &&
        actualChecksum.length === expectedChecksum.length
      ) {
        isValid = crypto.timingSafeEqual(
          Buffer.from(actualChecksum, "utf8"),
          Buffer.from(expectedChecksum, "utf8"),
        );
      }
    } catch {
      isValid = false;
    }

    return {
      isValid,
      actualChecksum,
      expectedChecksum,
    };
  }

  /**
   * Xóa đối tượng vật lý trên Object Storage
   */
  async deleteObject(storageKey: string): Promise<void> {
    try {
      const command = new DeleteObjectCommand({
        Bucket: this.bucketName,
        Key: storageKey,
      });
      await this.client.send(command);
    } catch (error: any) {
      console.warn(
        `[EvidenceStorageService] Cảnh báo: Không thể xóa đối tượng ${storageKey} trên Object Storage:`,
        error.message,
      );
    }
  }
}

export const evidenceStorageService = new EvidenceStorageService();
