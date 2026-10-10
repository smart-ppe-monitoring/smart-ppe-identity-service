import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

const SYSTEM_PERMISSIONS = [
  // User Management
  {
    name: "USER_READ",
    resource: "USER",
    action: "READ",
    description: "Xem danh sách và chi tiết người dùng",
  },
  {
    name: "USER_CREATE",
    resource: "USER",
    action: "CREATE",
    description: "Tạo tài khoản người dùng mới",
  },
  {
    name: "USER_UPDATE",
    resource: "USER",
    action: "UPDATE",
    description: "Cập nhật trạng thái và thông tin người dùng",
  },
  {
    name: "USER_DELETE",
    resource: "USER",
    action: "DELETE",
    description: "Xóa mềm người dùng",
  },
  {
    name: "USER_RESTORE",
    resource: "USER",
    action: "RESTORE",
    description: "Khôi phục tài khoản người dùng đã bị xóa mềm",
  },
  {
    name: "USER_ROLE_ASSIGN",
    resource: "USER",
    action: "ASSIGN_ROLE",
    description: "Phân vai trò cho người dùng",
  },

  // Role & Permission Management
  {
    name: "ROLE_READ",
    resource: "ROLE",
    action: "READ",
    description: "Xem danh sách vai trò và phân quyền",
  },
  {
    name: "ROLE_CREATE",
    resource: "ROLE",
    action: "CREATE",
    description: "Tạo vai trò mới",
  },
  {
    name: "ROLE_UPDATE",
    resource: "ROLE",
    action: "UPDATE",
    description: "Chỉnh sửa thông tin vai trò",
  },
  {
    name: "ROLE_DELETE",
    resource: "ROLE",
    action: "DELETE",
    description: "Xóa vai trò",
  },
  {
    name: "PERMISSION_READ",
    resource: "PERMISSION",
    action: "READ",
    description: "Xem danh mục quyền hệ thống",
  },
  {
    name: "ROLE_PERMISSION_ASSIGN",
    resource: "ROLE_PERMISSION",
    action: "ASSIGN",
    description: "Gán và thu hồi quyền của vai trò",
  },

  // Notifications & Emails
  {
    name: "NOTIFICATION_READ",
    resource: "NOTIFICATION",
    action: "READ",
    description: "Xem danh sách và lịch sử email/thông báo hệ thống",
  },
  {
    name: "NOTIFICATION_CREATE",
    resource: "NOTIFICATION",
    action: "CREATE",
    description: "Tạo và bắn thông báo tới người dùng / toàn hệ thống",
  },
  {
    name: "NOTIFICATION_UPDATE",
    resource: "NOTIFICATION",
    action: "UPDATE",
    description: "Kích hoạt retry gửi lại email bị lỗi",
  },
  {
    name: "NOTIFICATION_DELETE",
    resource: "NOTIFICATION",
    action: "DELETE",
    description: "Xóa thông báo và nhật ký email",
  },
  {
    name: "NOTIFICATION_TEMPLATE_READ",
    resource: "NOTIFICATION_TEMPLATE",
    action: "READ",
    description: "Xem danh sách và chi tiết mẫu thông báo/email",
  },
  {
    name: "NOTIFICATION_TEMPLATE_MANAGE",
    resource: "NOTIFICATION_TEMPLATE",
    action: "MANAGE",
    description: "Quản lý, tạo mới, cập nhật và test mẫu thông báo",
  },

  // Audit Logs
  {
    name: "AUDIT_LOG_READ",
    resource: "AUDIT_LOG",
    action: "READ",
    description: "Xem nhật ký kiểm toán hệ thống",
  },

  // System Maintenance
  {
    name: "MAINTENANCE_READ",
    resource: "MAINTENANCE",
    action: "READ",
    description: "Xem trạng thái và cấu hình bảo trì hệ thống",
  },
  {
    name: "MAINTENANCE_MANAGE",
    resource: "MAINTENANCE",
    action: "MANAGE",
    description: "Bật/tắt và quản lý lịch bảo trì hệ thống",
  },
  {
    name: "MAINTENANCE_BYPASS",
    resource: "MAINTENANCE",
    action: "BYPASS",
    description: "Truy cập hệ thống khi đang bật chế độ bảo trì",
  },

  // API Keys & Integrations
  {
    name: "API_KEY_READ",
    resource: "API_KEY",
    action: "READ",
    description: "Xem danh sách và chi tiết API Keys",
  },
  {
    name: "API_KEY_MANAGE",
    resource: "API_KEY",
    action: "MANAGE",
    description: "Tạo, thu hồi và quản lý API Keys",
  },

  // Webhooks
  {
    name: "WEBHOOK_READ",
    resource: "WEBHOOK",
    action: "READ",
    description: "Xem danh sách Webhook Endpoints và lịch sử giao nhận",
  },
  {
    name: "WEBHOOK_MANAGE",
    resource: "WEBHOOK",
    action: "MANAGE",
    description: "Đăng ký, cấu hình và kích hoạt retry Webhook deliveries",
  },

  // System Configuration & Feature Flags
  {
    name: "SYSTEM_CONFIG_READ",
    resource: "SYSTEM_CONFIG",
    action: "READ",
    description: "Xem cấu hình hệ thống và feature flags",
  },
  {
    name: "SYSTEM_CONFIG_MANAGE",
    resource: "SYSTEM_CONFIG",
    action: "MANAGE",
    description: "Cập nhật, thay đổi và quản lý cấu hình hệ thống",
  },

  // Scheduled / Cron Jobs Management
  {
    name: "CRON_JOB_READ",
    resource: "CRON_JOB",
    action: "READ",
    description: "Xem trạng thái và lịch sử thực thi các tác vụ định kỳ",
  },
  {
    name: "CRON_JOB_MANAGE",
    resource: "CRON_JOB",
    action: "MANAGE",
    description: "Kích hoạt thủ công hoặc thay đổi cấu hình tác vụ định kỳ",
  },

  // Files & Media Storage
  {
    name: "FILE_READ",
    resource: "FILE",
    action: "READ",
    description: "Xem và tải tệp tin trong hệ thống",
  },
  {
    name: "FILE_UPLOAD",
    resource: "FILE",
    action: "UPLOAD",
    description: "Tải tệp tin mới lên hệ thống lưu trữ",
  },
  {
    name: "FILE_DELETE",
    resource: "FILE",
    action: "DELETE",
    description: "Xóa tệp tin khỏi hệ thống lưu trữ",
  },
  {
    name: "FILE_MANAGE",
    resource: "FILE",
    action: "MANAGE",
    description:
      "Toàn quyền quản trị tất cả tệp tin của người dùng trong hệ thống",
  },

  // PPE Domain Permissions (Sites, Zones, Cameras, Safety Config, Incidents, Reporting, AI Models)
  {
    name: "PPE_SITE_READ",
    resource: "PPE_SITE",
    action: "READ",
    description: "Xem danh sách và chi tiết công trường",
  },
  {
    name: "PPE_SITE_MANAGE",
    resource: "PPE_SITE",
    action: "MANAGE",
    description: "Quản trị tạo mới, cập nhật, xóa công trường",
  },
  {
    name: "PPE_ZONE_READ",
    resource: "PPE_ZONE",
    action: "READ",
    description: "Xem danh sách và chi tiết khu vực/zone",
  },
  {
    name: "PPE_ZONE_MANAGE",
    resource: "PPE_ZONE",
    action: "MANAGE",
    description: "Quản trị tạo mới, cập nhật, xóa khu vực",
  },
  {
    name: "PPE_RESTRICTED_AREA_READ",
    resource: "PPE_RESTRICTED_AREA",
    action: "READ",
    description: "Xem cấu hình vùng hạn chế nguy hiểm",
  },
  {
    name: "PPE_RESTRICTED_AREA_MANAGE",
    resource: "PPE_RESTRICTED_AREA",
    action: "MANAGE",
    description: "Khai báo, vẽ và cấu hình vùng hạn chế trên camera",
  },
  {
    name: "PPE_CAMERA_READ",
    resource: "PPE_CAMERA",
    action: "READ",
    description: "Xem danh sách camera, luồng RTSP và trạng thái",
  },
  {
    name: "PPE_CAMERA_MANAGE",
    resource: "PPE_CAMERA",
    action: "MANAGE",
    description: "Thêm mới, cấu hình luồng RTSP và quản lý camera",
  },
  {
    name: "PPE_SAFETY_CONFIG_READ",
    resource: "PPE_SAFETY_CONFIG",
    action: "READ",
    description: "Xem cấu hình ngưỡng an toàn và quy tắc phát hiện vi phạm",
  },
  {
    name: "PPE_SAFETY_CONFIG_MANAGE",
    resource: "PPE_SAFETY_CONFIG",
    action: "MANAGE",
    description: "Cập nhật ngưỡng confidence, thời gian xác nhận và cooldown",
  },
  {
    name: "PPE_INCIDENT_READ",
    resource: "PPE_INCIDENT",
    action: "READ",
    description: "Tra cứu danh sách sự cố vi phạm PPE và bằng chứng",
  },
  {
    name: "PPE_INCIDENT_REVIEW",
    resource: "PPE_INCIDENT",
    action: "REVIEW",
    description: "Xác nhận vi phạm: True Violation hoặc False Alarm",
  },
  {
    name: "PPE_INCIDENT_UPDATE",
    resource: "PPE_INCIDENT",
    action: "UPDATE",
    description: "Ghi chú xử lý, phân công và đóng sự cố vi phạm",
  },
  {
    name: "PPE_INCIDENT_DELETE",
    resource: "PPE_INCIDENT",
    action: "DELETE",
    description: "Xóa bản ghi sự cố vi phạm",
  },
  {
    name: "PPE_INCIDENT_MANAGE",
    resource: "PPE_INCIDENT",
    action: "MANAGE",
    description: "Toàn quyền quản trị sự cố vi phạm PPE",
  },
  {
    name: "PPE_REPORTING_READ",
    resource: "PPE_REPORTING",
    action: "READ",
    description: "Xem dashboard tổng hợp, thống kê vi phạm an toàn",
  },
  {
    name: "PPE_REPORTING_EXPORT",
    resource: "PPE_REPORTING",
    action: "EXPORT",
    description: "Xuất báo cáo vi phạm an toàn (PDF/Excel)",
  },
  {
    name: "PPE_AI_METRICS_READ",
    resource: "PPE_REPORTING",
    action: "READ_METRICS",
    description: "Theo dõi False Alert Rate và hiệu quả hệ thống AI",
  },
  {
    name: "PPE_MODEL_READ",
    resource: "PPE_MODEL",
    action: "READ",
    description: "Xem danh sách và thông tin phiên bản mô hình AI (YOLO)",
  },
  {
    name: "PPE_MODEL_MANAGE",
    resource: "PPE_MODEL",
    action: "MANAGE",
    description: "Quản lý triển khai, cập nhật mô hình AI",
  },
];

const USER_BASE_PERMISSIONS: string[] = [
  "NOTIFICATION_READ",
  "FILE_READ",
  "FILE_UPLOAD",
  "FILE_DELETE",
];

const SAFETY_MANAGER_PERMISSIONS: string[] = [
  "PPE_SITE_READ",
  "PPE_SITE_MANAGE",
  "PPE_ZONE_READ",
  "PPE_ZONE_MANAGE",
  "PPE_RESTRICTED_AREA_READ",
  "PPE_RESTRICTED_AREA_MANAGE",
  "PPE_CAMERA_READ",
  "PPE_CAMERA_MANAGE",
  "PPE_SAFETY_CONFIG_READ",
  "PPE_SAFETY_CONFIG_MANAGE",
  "PPE_INCIDENT_READ",
  "PPE_INCIDENT_REVIEW",
  "PPE_INCIDENT_UPDATE",
  "PPE_INCIDENT_MANAGE",
  "PPE_REPORTING_READ",
  "PPE_REPORTING_EXPORT",
  "PPE_AI_METRICS_READ",
  "PPE_MODEL_READ",
  "NOTIFICATION_READ",
  "FILE_READ",
  "FILE_UPLOAD",
];

const SAFETY_OFFICER_PERMISSIONS: string[] = [
  "PPE_INCIDENT_READ",
  "PPE_INCIDENT_REVIEW",
  "PPE_INCIDENT_UPDATE",
  "PPE_CAMERA_READ",
  "PPE_SITE_READ",
  "PPE_ZONE_READ",
  "PPE_RESTRICTED_AREA_READ",
  "PPE_SAFETY_CONFIG_READ",
  "NOTIFICATION_READ",
  "FILE_READ",
];

const MANAGER_PERMISSIONS: string[] = [
  "USER_READ",
  "USER_RESTORE",
  "ROLE_READ",
  "PERMISSION_READ",
  "NOTIFICATION_READ",
  "NOTIFICATION_CREATE",
  "NOTIFICATION_UPDATE",
  "NOTIFICATION_TEMPLATE_READ",
  "MAINTENANCE_READ",
  "AUDIT_LOG_READ",
  "API_KEY_READ",
  "WEBHOOK_READ",
  "SYSTEM_CONFIG_READ",
  "CRON_JOB_READ",
  "FILE_READ",
  "FILE_UPLOAD",
  "FILE_MANAGE",
];

async function main() {
  console.log("Starting Dynamic RBAC Seeding...");

  // 1. Seed Permissions
  const permissionMap: Record<string, string> = {};
  for (const perm of SYSTEM_PERMISSIONS) {
    const record = await prisma.permission.upsert({
      where: { name: perm.name },
      update: {
        description: perm.description,
        resource: perm.resource,
        action: perm.action,
        isSystem: true,
      },
      create: {
        name: perm.name,
        description: perm.description,
        resource: perm.resource,
        action: perm.action,
        isSystem: true,
      },
    });
    permissionMap[perm.name] = record.id;
  }
  console.log(
    `Upserted ${Object.keys(permissionMap).length} system permissions`,
  );

  // 2. Seed System Roles
  const roles = [
    {
      name: "ADMIN",
      description: "Quản trị viên toàn quyền hệ thống",
      isSystem: true,
    },
    {
      name: "SAFETY_MANAGER",
      description: "Quản lý an toàn công trường (Công trường, Camera, Cấu hình AI, Báo cáo)",
      isSystem: true,
    },
    {
      name: "SAFETY_OFFICER",
      description: "Cán bộ an toàn trực ban (Giám sát cảnh báo, Duyệt True/False Alarm, Xử lý sự cố)",
      isSystem: true,
    },
    {
      name: "MANAGER",
      description: "Quản lý tài chính và người dùng",
      isSystem: true,
    },
    { name: "USER", description: "Người dùng thông thường", isSystem: true },
  ];

  const roleMap: Record<string, string> = {};
  for (const r of roles) {
    const role = await prisma.role.upsert({
      where: { name: r.name },
      update: {
        description: r.description,
        isSystem: r.isSystem,
      },
      create: {
        name: r.name,
        description: r.description,
        isSystem: r.isSystem,
      },
    });
    roleMap[r.name] = role.id;
    console.log(`Role ${r.name} upserted with ID ${role.id}`);
  }

  // 3. Seed Role-Permissions Mapping
  const rolePermissionAssignments: Record<string, string[]> = {
    ADMIN: SYSTEM_PERMISSIONS.map((p) => p.name),
    SAFETY_MANAGER: SAFETY_MANAGER_PERMISSIONS,
    SAFETY_OFFICER: SAFETY_OFFICER_PERMISSIONS,
    MANAGER: MANAGER_PERMISSIONS,
    USER: USER_BASE_PERMISSIONS,
  };

  for (const [roleName, permList] of Object.entries(
    rolePermissionAssignments,
  )) {
    const roleId = roleMap[roleName];
    for (const permName of permList) {
      const permissionId = permissionMap[permName];
      if (roleId && permissionId) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId,
              permissionId,
            },
          },
          update: {},
          create: {
            roleId,
            permissionId,
          },
        });
      }
    }
    console.log(`Mapped ${permList.length} permissions to role ${roleName}`);
  }

  // 4. Seed Standard Users
  const adminPassword = await bcrypt.hash("Admin@123456", 10);
  const managerPassword = await bcrypt.hash("Manager@123456", 10);
  const officerPassword = await bcrypt.hash("Officer@123456", 10);
  const userPassword = await bcrypt.hash("User@123456", 10);

  // 4.1 PPE Standard Accounts (D08.pdf specifications)
  const ppeUsers = [
    {
      email: "admin@ppe.local",
      password: adminPassword,
      fullName: "Quản Trị Viên Hệ Thống",
      role: "ADMIN",
    },
    {
      email: "manager@ppe.local",
      password: managerPassword,
      fullName: "Nguyễn Văn Quản Lý (Safety Manager)",
      role: "SAFETY_MANAGER",
    },
    {
      email: "officer@ppe.local",
      password: officerPassword,
      fullName: "Trần Thị An Toàn (Safety Officer)",
      role: "SAFETY_OFFICER",
    },
  ];

  for (const u of ppeUsers) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {
        password: u.password,
        fullName: u.fullName,
        roleId: roleMap[u.role],
        isActive: true,
      },
      create: {
        email: u.email,
        password: u.password,
        fullName: u.fullName,
        roleId: roleMap[u.role],
        isActive: true,
      },
    });
    console.log(`User ${u.email} upserted with role ${u.role}`);
  }

  // 4.2 Legacy Template Accounts (Backward Compatibility)
  await prisma.user.upsert({
    where: { email: "admin@template.local" },
    update: {
      password: adminPassword,
      fullName: "Admin",
      roleId: roleMap["ADMIN"],
      isActive: true,
    },
    create: {
      email: "admin@template.local",
      password: adminPassword,
      fullName: "Admin",
      roleId: roleMap["ADMIN"],
      isActive: true,
    },
  });

  await prisma.user.upsert({
    where: { email: "manager@template.local" },
    update: {
      password: managerPassword,
      fullName: "Manager",
      roleId: roleMap["MANAGER"] || roleMap["SAFETY_MANAGER"],
      isActive: true,
    },
    create: {
      email: "manager@template.local",
      password: managerPassword,
      fullName: "Manager",
      roleId: roleMap["MANAGER"] || roleMap["SAFETY_MANAGER"],
      isActive: true,
    },
  });

  await prisma.user.upsert({
    where: { email: "user@template.local" },
    update: {
      password: userPassword,
      fullName: "User",
      roleId: roleMap["USER"],
      isActive: true,
    },
    create: {
      email: "user@template.local",
      password: userPassword,
      fullName: "User",
      roleId: roleMap["USER"],
      isActive: true,
    },
  });

  // 5. Seed Default Maintenance Configuration
  await prisma.maintenanceConfig.upsert({
    where: { key: "DEFAULT" },
    update: {},
    create: {
      key: "DEFAULT",
      enabled: false,
      status: "ONLINE",
      title: "Hệ thống đang bảo trì",
      message:
        "Hệ thống đang được bảo trì để nâng cấp dịch vụ. Vui lòng quay lại sau.",
      bypassPermissions: ["MAINTENANCE_MANAGE", "MAINTENANCE_BYPASS"],
      bypassRoles: ["ADMIN"],
      bypassIps: [],
    },
  });
  console.log("MaintenanceConfig default seeded");

  // 6. Seed Default System Notification Templates
  const DEFAULT_TEMPLATES = [
    {
      code: "VERIFY_EMAIL",
      name: "Xác thực tài khoản",
      description:
        "Email gửi kèm link xác thực khi người dùng đăng ký tài khoản mới",
      channels: ["EMAIL"],
      subject: "Xác thực tài khoản của bạn",
      title: "Xác thực tài khoản",
      content:
        '<p>Chào <strong>{{fullName}}</strong>,</p><p>Cảm ơn bạn đã đăng ký tài khoản. Vui lòng click vào nút bên dưới để xác thực email của bạn:</p><div style="text-align: center; margin: 32px 0;"><a href="{{verificationUrl}}" style="background-color: #4CAF50; color: white; padding: 14px 28px; text-decoration: none; border-radius: 5px; font-weight: bold;">Xác thực tài khoản</a></div><p style="color: #666; font-size: 13px;">Link có hiệu lực trong 24 giờ. Nếu bạn không đăng ký, vui lòng bỏ qua email này.</p>',
      variables: ["fullName", "verificationUrl", "token"],
      isSystem: true,
      isActive: true,
    },
    {
      code: "RESET_PASSWORD",
      name: "Đặt lại mật khẩu",
      description:
        "Email gửi kèm link khôi phục mật khẩu khi người dùng yêu cầu",
      channels: ["EMAIL"],
      subject: "Đặt lại mật khẩu tài khoản",
      title: "Đặt lại mật khẩu",
      content:
        '<p>Chào <strong>{{fullName}}</strong>,</p><p>Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.</p><div style="text-align: center; margin: 32px 0;"><a href="{{resetUrl}}" style="background-color: #FF5722; color: white; padding: 14px 28px; text-decoration: none; border-radius: 5px; font-weight: bold;">Đặt lại mật khẩu</a></div><p style="color: #666; font-size: 13px;">Link có hiệu lực trong 1 giờ. Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này.</p>',
      variables: ["fullName", "resetUrl", "token"],
      isSystem: true,
      isActive: true,
    },
    {
      code: "NEW_DEVICE_ALERT",
      name: "Cảnh báo đăng nhập thiết bị mới",
      description: "Thông báo & Email khi phát hiện đăng nhập từ thiết bị lạ",
      channels: ["WEB", "EMAIL"],
      subject: "⚠️ Cảnh báo: Phát hiện đăng nhập từ thiết bị mới",
      title: "Phát hiện đăng nhập từ thiết bị mới",
      content:
        "Tài khoản của bạn vừa được đăng nhập từ thiết bị: {{deviceName}} (IP: {{ipAddress}}) vào lúc {{loginTime}}.",
      variables: ["fullName", "deviceName", "ipAddress", "loginTime"],
      isSystem: true,
      isActive: true,
    },
    {
      code: "WELCOME",
      name: "Chào mừng thành viên mới",
      description:
        "Thông báo in-app chào mừng sau khi tài khoản được kích hoạt thành công",
      channels: ["WEB"],
      subject: "Chào mừng bạn đến với hệ thống",
      title: "Xác thực tài khoản thành công",
      content:
        "Chào mừng {{fullName}} đến với hệ thống! Tài khoản của bạn đã được kích hoạt thành công.",
      variables: ["fullName"],
      isSystem: true,
      isActive: true,
    },
    {
      code: "PASSWORD_CHANGED",
      name: "Đổi mật khẩu thành công",
      description: "Thông báo cảnh báo bảo mật khi mật khẩu tài khoản thay đổi",
      channels: ["WEB", "EMAIL"],
      subject: "Mật khẩu tài khoản đã được thay đổi",
      title: "Đổi mật khẩu thành công",
      content:
        "Mật khẩu tài khoản của bạn vừa được thay đổi thành công. Nếu không phải bạn thực hiện, vui lòng liên hệ quản trị viên ngay lập tức.",
      variables: ["fullName"],
      isSystem: true,
      isActive: true,
    },
    {
      code: "ROLE_ASSIGNED",
      name: "Cập nhật vai trò tài khoản",
      description: "Thông báo khi người dùng được gán vai trò mới",
      channels: ["WEB"],
      subject: "Cập nhật vai trò tài khoản",
      title: "Cập nhật vai trò tài khoản",
      content:
        "Vai trò tài khoản của bạn đã được cập nhật thành: {{roleName}}.",
      variables: ["fullName", "roleName"],
      isSystem: true,
      isActive: true,
    },
  ];

  for (const tpl of DEFAULT_TEMPLATES) {
    await prisma.notificationTemplate.upsert({
      where: { code: tpl.code },
      update: {
        name: tpl.name,
        description: tpl.description,
        channels: tpl.channels,
        subject: tpl.subject,
        title: tpl.title,
        content: tpl.content,
        variables: tpl.variables,
        isSystem: tpl.isSystem,
        isActive: tpl.isActive,
      },
      create: {
        code: tpl.code,
        name: tpl.name,
        description: tpl.description,
        channels: tpl.channels,
        subject: tpl.subject,
        title: tpl.title,
        content: tpl.content,
        variables: tpl.variables,
        isSystem: tpl.isSystem,
        isActive: tpl.isActive,
      },
    });
  }
  console.log("NotificationTemplates default seeded (6 templates)");

  console.log("Seed completed successfully");
}

main()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
