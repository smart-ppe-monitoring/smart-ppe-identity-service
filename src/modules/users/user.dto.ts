export interface UserQueryDto {
  search?: string;
  email?: string;
  fullName?: string;
  roleName?: string;
  isActive?: boolean;
  isDeleted?: boolean;
  sortBy?: "createdAt" | "email" | "fullName";
  order?: "asc" | "desc";
  page?: number;
  limit?: number;
}

export interface CreateUserDto {
  email: string;
  password: string;
  roleId: string;
  fullName?: string;
  phoneNumber?: string;
  mustChangePassword?: boolean;
}

export interface UpdateUserDto {
  isActive?: boolean;
  fullName?: string;
  phoneNumber?: string;
}

export interface AdminResetPasswordDto {
  newPassword?: string;
  mustChangePassword?: boolean;
}

export interface UserResponseDto {
  id: string;
  email: string | null;
  fullName?: string | null;
  avatarUrl?: string | null;
  phoneNumber?: string | null;
  roleId: string;
  role?: {
    id: string;
    name: string;
  };
  isActive: boolean;
  twoFactorEnabled?: boolean;
  mustChangePassword?: boolean;
  failedLoginAttempts?: number;
  lockedUntil?: Date | null;
  deletedAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AdminResetPasswordResponseDto extends UserResponseDto {
  temporaryPassword?: string;
}
