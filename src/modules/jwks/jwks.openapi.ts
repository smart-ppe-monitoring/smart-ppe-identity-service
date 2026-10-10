import { openapiRegistry } from "../../config/openapi/openapi.registry";
import { jwksResponseSchema } from "./jwks.dto";

export function registerJwksOpenApi(): void {
  // GET /.well-known/jwks.json
  openapiRegistry.registerPath({
    method: "get",
    path: "/.well-known/jwks.json",
    tags: ["Authentication"],
    summary: "JSON Web Key Set (RFC 7517 JWKS)",
    description:
      "Cung cấp danh sách các Public Keys (RS256) công khai theo chuẩn IETF RFC 7517. Các satellite microservices sử dụng endpoint này để tải và xác thực chữ ký của Access Token phân tán mà không cần gọi API xác thực tới Auth Service.",
    responses: {
      200: {
        description: "Tập hợp các Public Keys định dạng RFC 7517 JWKS",
        content: {
          "application/json": {
            schema: jwksResponseSchema,
          },
        },
      },
    },
  });
}
