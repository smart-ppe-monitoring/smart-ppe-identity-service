import { openapiRegistry } from "../../config/openapi/openapi.registry";
import { z } from "zod";

export function registerSecurityTxtOpenApi(): void {
  // GET /.well-known/security.txt
  openapiRegistry.registerPath({
    method: "get",
    path: "/.well-known/security.txt",
    tags: ["Security"],
    summary: "Chính sách công bố lỗ hổng bảo mật (RFC 9116)",
    description:
      "Cung cấp thông tin liên hệ và chính sách tiếp nhận báo cáo lỗ hổng bảo mật theo tiêu chuẩn IETF RFC 9116 (Security Vulnerability Disclosure).",
    responses: {
      200: {
        description:
          "Nội dung tệp security.txt định dạng text/plain chuẩn RFC 9116",
        content: {
          "text/plain": {
            schema: z.string().openapi({
              example:
                "# Security Vulnerability Disclosure Policy\nContact: mailto:security@example.com\nExpires: 2027-10-01T00:00:00.000Z\nPreferred-Languages: en, vi\nCanonical: http://localhost:7777/.well-known/security.txt\nPolicy: http://localhost:7777/api/docs",
            }),
          },
        },
      },
    },
  });

  // GET /security.txt
  openapiRegistry.registerPath({
    method: "get",
    path: "/security.txt",
    tags: ["Security"],
    summary: "Đường dẫn legacy security.txt (Chuyển hướng 301)",
    description:
      "Tự động chuyển hướng 301 vĩnh viễn sang /.well-known/security.txt theo khuyến nghị Mục 3 RFC 9116.",
    responses: {
      301: {
        description: "Chuyển hướng sang /.well-known/security.txt",
      },
    },
  });
}
