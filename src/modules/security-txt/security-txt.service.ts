import { envConfig } from "../../config/env.config";
import {
  SECURITY_TXT_PATHS,
  SECURITY_TXT_DEFAULTS,
} from "../../common/constants/security-txt.constant";

export interface SecurityTxtGenerateOptions {
  contactEmail?: string;
  policyUrl?: string;
  acknowledgmentsUrl?: string;
  baseUrl?: string;
  expiryDate?: Date;
}

export class SecurityTxtService {
  /**
   * Sinh nội dung tệp security.txt theo đặc tả chuẩn IETF RFC 9116.
   *
   * Quy định RFC 9116:
   * 1. Trường `Contact:` là bắt buộc và phải có định dạng URI (mailto: hoặc https://).
   * 2. Trường `Expires:` là bắt buộc theo định dạng RFC 3339 / ISO 8601,
   *    và TUYỆT ĐỐI không được xa hơn 1 năm kể từ thời điểm hiện tại.
   * 3. Trường `Canonical:` chỉ định URI chính thức của tệp.
   */
  generateSecurityTxt(options?: SecurityTxtGenerateOptions): string {
    const rawContact =
      options?.contactEmail ??
      envConfig.securityTxt.contactEmail ??
      SECURITY_TXT_DEFAULTS.CONTACT_EMAIL;

    // Chuẩn hóa Contact thành URI hợp lệ (nếu chưa có mailto: hoặc http:// thì thêm mailto:)
    const contactUri =
      rawContact.startsWith("mailto:") || rawContact.startsWith("http")
        ? rawContact
        : `mailto:${rawContact}`;

    // RFC 9116 Mục 2.5.5: Expires không được lớn hơn 365 ngày kể từ ngày hiện tại
    const expires =
      options?.expiryDate ??
      new Date(
        Date.now() + SECURITY_TXT_DEFAULTS.EXPIRY_DAYS * 24 * 60 * 60 * 1000,
      );

    const rawBaseUrl =
      options?.baseUrl ||
      envConfig.renderExternalUrl ||
      envConfig.appUrl ||
      "http://localhost:7777";
    const baseUrl = rawBaseUrl.replace(/\/+$/, "");

    const canonicalUri = `${baseUrl}${SECURITY_TXT_PATHS.WELL_KNOWN}`;

    const lines: string[] = [
      "# Security Vulnerability Disclosure Policy",
      "# Format: IETF RFC 9116 (https://www.rfc-editor.org/rfc/rfc9116)",
      `Contact: ${contactUri}`,
      `Expires: ${expires.toISOString()}`,
      `Preferred-Languages: ${SECURITY_TXT_DEFAULTS.PREFERRED_LANGUAGES}`,
      `Canonical: ${canonicalUri}`,
    ];

    const policyUrl = options?.policyUrl ?? envConfig.securityTxt.policyUrl;
    if (policyUrl && policyUrl.trim().length > 0) {
      lines.push(`Policy: ${policyUrl.trim()}`);
    } else {
      lines.push(`Policy: ${baseUrl}/api/docs`);
    }

    const ackUrl =
      options?.acknowledgmentsUrl ?? envConfig.securityTxt.acknowledgmentsUrl;
    if (ackUrl && ackUrl.trim().length > 0) {
      lines.push(`Acknowledgments: ${ackUrl.trim()}`);
    }

    return lines.join("\n") + "\n";
  }
}

export const securityTxtService = new SecurityTxtService();
