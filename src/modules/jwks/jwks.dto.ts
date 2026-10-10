import { z } from "zod";

export const jwkKeySchema = z.object({
  kty: z.string().describe("Loại khóa cryptographic (RSA)"),
  use: z.string().describe("Mục đích sử dụng (sig cho signature)"),
  alg: z.string().describe("Thuật toán mã hóa (RS256)"),
  kid: z.string().describe("Định danh khóa duy nhất (Key ID)"),
  n: z.string().describe("RSA Modulus (Base64URL encoded)"),
  e: z.string().describe("RSA Exponent (Base64URL encoded, e.g. AQAB)"),
});

export type JwkKeyDto = z.infer<typeof jwkKeySchema>;

export const jwksResponseSchema = z.object({
  keys: z.array(jwkKeySchema).describe("Danh sách các public keys hợp lệ"),
});

export type JwksResponseDto = z.infer<typeof jwksResponseSchema>;
