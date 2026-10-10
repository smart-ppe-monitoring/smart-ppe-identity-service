import { z } from "zod";

/**
 * JWKS Endpoint Validation Schema
 *
 * Endpoint GET /.well-known/jwks.json tuân thủ nghiêm ngặt chuẩn IETF RFC 7517.
 * Không tiếp nhận payload body, query parameters hoặc URL route params.
 */
export const getJwksQuerySchema = z.object({}).strict();

export type GetJwksQueryDto = z.infer<typeof getJwksQuerySchema>;
