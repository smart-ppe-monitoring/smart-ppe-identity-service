# smart-ppe-identity-service

> **Identity & Access Management (IAM) Microservice (:9999)** cho Hệ thống Giám sát An toàn Lao động Thông minh (**Smart PPE Monitoring System**). Dịch vụ lõi đảm nhiệm xác thực người dùng, phân quyền RBAC phân cấp, phát hành và kiểm chứng Asymmetric JWT RS256, chuẩn hóa JWKS (RFC 7517), xác thực 2 bước (TOTP 2FA) và quản trị vòng đời tài khoản theo chuẩn **D08.pdf (Mục 3.5 & Task BE-03)**.

---

## 🏛️ Trách nhiệm kiến trúc (Architectural Responsibilities)

1. **Xác thực & Ủy quyền (Authentication & Authorization)**:
   - Đăng ký, đăng nhập tài khoản Cán bộ an toàn, Quản trị viên, Giám sát viên công trường.
   - Cơ chế bảo mật: Khóa tài khoản sau 5 lần nhập sai (`failed_login_attempts`), chính sách mật khẩu phức tạp và bắt buộc đổi mật khẩu khi cần.
   - Cấp phát Access Token (15 phút) và Refresh Token xoay vòng (Token Rotation) có phát hiện tái sử dụng trái phép (Token Reuse Detection).

2. **Chữ ký số bất đối xứng (Asymmetric JWT & RFC 7517 JWKS)**:
   - Sử dụng thuật toán ký RS256 với cặp khóa RSA 2048-bit.
   - Cung cấp endpoint công khai `/.well-known/jwks.json` để các vệ tinh microservices khác (`site-service`, `camera-service`, `incident-service`, `notification-service`) thẩm định chữ ký token cục bộ trong bộ nhớ RAM mà không tạo nút thắt cổ chai (Decoupled Auth Propagation).

3. **Phân quyền dựa trên vai trò phân cấp (Dynamic RBAC)**:
   - Hệ thống 34 quyền chuẩn hóa (`SYSTEM_PERMISSIONS`) bao phủ toàn bộ các miền nghiệp vụ.
   - Quản lý gán vai trò (`ADMIN`, `MANAGER`, `USER`) và tùy biến quyền hạn linh hoạt.

4. **Bảo mật nâng cao (Advanced Security Controls)**:
   - Xác thực 2 bước đa yếu tố (TOTP 2FA) qua Google Authenticator kèm mã dự phòng (Backup Codes).
   - Chống bot tự động qua Cloudflare Turnstile CAPTCHA.
   - Chế độ bảo trì hệ thống toàn cục (`maintenanceGuard`) với danh sách IP đặc quyền (Bypass IPs).

---

## 🔌 Đặc tả kỹ thuật (Technical Specifications)

- **Cổng dịch vụ (Service Port)**: `9999` (Prefix qua API Gateway: `/api/v1/auth`, `/api/v1/users`, `/api/v1/rbac`, `/api/v1/system`, `/api/v1/integration`)
- **Cơ sở dữ liệu (Database)**: PostgreSQL (`ppe_identity_db`), Prisma ORM
- **Cơ chế Token**: JWT RS256 (RFC 7519, RFC 7517)
- **Cache & Event Bus**: Redis, BullMQ (Outbox Relay)

---

## 🚀 Khởi chạy cục bộ (Local Development)

```bash
# 1. Cài đặt dependencies
pnpm install

# 2. Cấu hình biến môi trường
cp .env.example .env

# 3. Tạo cặp khóa RSA 2048-bit (nếu chưa có)
openssl genrsa -out keys/private.key.pem 2048
openssl rsa -in keys/private.key.pem -pubout -out keys/public.key.pem

# 4. Sinh Prisma Client và chạy migration
pnpm run prisma:generate
pnpm run db:migrate

# 5. Nạp dữ liệu ban đầu (Roles, Permissions, Super Admin)
pnpm run db:seed

# 6. Chạy server phát triển
pnpm run dev
# Server lắng nghe tại http://localhost:9999
```

---

## 🧪 Kiểm thử tự động (Unit & Integration Tests)

```bash
pnpm test
```

---

## 🐳 Triển khai Docker

```bash
docker build -t smart-ppe-identity-service .
docker run -p 9999:9999 --env-file .env smart-ppe-identity-service
```
