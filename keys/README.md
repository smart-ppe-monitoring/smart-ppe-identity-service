# RSA Key Pair for Asymmetric JWT (RFC 7517 JWKS)

Dịch vụ sử dụng thuật toán ký bất đối xứng **RS256** (RSA 2048-bit):
- `private.key.pem`: Dùng để ký phát Access Token & Refresh Token (giữ bí mật tuyệt đối).
- `public.key.pem`: Dùng để các vệ tinh microservices khác kiểm chứng chữ ký token mà không cần gọi API xác thực ngược lại.

### Khởi tạo cặp khóa (Development):

```bash
# 1. Sinh Private Key RSA 2048-bit
openssl genrsa -out keys/private.key.pem 2048

# 2. Trích xuất Public Key chuẩn PKCS#8
openssl rsa -in keys/private.key.pem -pubout -out keys/public.key.pem
```
