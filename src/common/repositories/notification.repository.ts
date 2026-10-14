import {
  NOTIFICATION_TYPE,
  NOTIFICATION_PRIORITY,
  EMAIL_STATUS,
} from "../constants/notification.constant";

export interface ClaimedEmailRecord {
  id: string;
  userId: string | null;
  toEmail: string;
  subject: string;
  templateKey: string;
  templateData: unknown;
  status: string;
  attempts: number;
  lastError: string | null;
  sentAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TemplateRecord {
  id: string;
  code: string;
  name: string;
  channel: string;
  subjectTemplate: string | null;
  contentTemplate: string;
  status: string;
}

/**
 * Adapter trung gian cho Notification domain.
 * Các bảng notifications, email_notifications, notification_templates đã được chuyển giao
 * độc quyền sang smart-ppe-notification-service (ppe_notification_db).
 */
export class NotificationRepository {
  async findTemplateByCode(_code: string): Promise<TemplateRecord | null> {
    return null;
  }

  async createSingleNotification(data: {
    userId: string;
    channel?: string;
    severity?: string;
    title: string;
    content: string;
    actionUrl?: string;
    metadata?: Record<string, unknown>;
  }) {
    return this.createWebNotification({
      userId: data.userId,
      title: data.title,
      content: data.content,
      priority: data.severity,
      actionUrl: data.actionUrl,
      metadata: data.metadata,
    });
  }

  async createWebNotification(data: {
    userId: string;
    type?: string;
    priority?: string;
    title: string;
    content: string;
    actionUrl?: string;
    metadata?: Record<string, unknown>;
  }) {
    return {
      id: "delegated-to-notification-service",
      userId: data.userId,
      type: data.type || NOTIFICATION_TYPE.INFO,
      priority: data.priority || NOTIFICATION_PRIORITY.NORMAL,
      title: data.title,
      content: data.content,
      actionUrl: data.actionUrl,
      metadata: data.metadata,
      isRead: false,
      createdAt: new Date(),
    };
  }

  async createEmailNotification(data: {
    userId?: string | null;
    toEmail: string;
    subject: string;
    templateKey: string;
    templateData: unknown;
  }) {
    return {
      id: "delegated-to-notification-service",
      userId: data.userId ?? null,
      toEmail: data.toEmail,
      subject: data.subject,
      templateKey: data.templateKey,
      templateData: data.templateData,
      status: EMAIL_STATUS.PENDING,
      attempts: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  async claimPendingEmails(_batchSize = 20): Promise<ClaimedEmailRecord[]> {
    return [];
  }

  async updateEmailStatus(
    _id: string,
    _data: {
      status: string;
      attempts?: number;
      lastError?: string | null;
      sentAt?: Date | null;
    },
  ) {
    return null;
  }

  async resetEmailForRetry(_id: string) {
    return null;
  }
}

export const notificationRepository = new NotificationRepository();
