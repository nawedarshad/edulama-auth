import { Injectable, UnauthorizedException, Logger, ForbiddenException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import type { Role, User, AcademicYear } from '@prisma/client';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { EmailService } from '../email/email.service';

export type UserRole = 'PRINCIPAL' | 'TEACHER' | 'STUDENT' | 'PARENT' | 'ADMIN';

export interface AuthUserPayload {
  id: number;
  email: string;
  schoolId: number;
  role: UserRole;
  permissions: string[];
  academicYearId?: number;
  academicYearName?: string;
}

type UserWithAllPermissions = User & {
  role: Role;
  userPermissions: {
    permission: {
      name: string;
    };
  }[];
  school: {
    id: number;
    name: string;
    code: string;
    // subdomain: string; // Removed from usage as requested
  };
  academicYear?: {
    id: number;
    name: string;
    isActive: boolean;
  };
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly emailService: EmailService,
  ) { }

  /* -------- EXTRACT PERMISSIONS -------- */
  private async extractPermissions(userId: number, roleId: number): Promise<string[]> {
    const [rolePermissions, userPermissions] = await Promise.all([
      this.prisma.rolePermission.findMany({
        where: { roleId },
        include: {
          permission: true,
        },
      }),
      this.prisma.userPermission.findMany({
        where: { userId },
        include: {
          permission: true,
        },
      }),
    ]);

    const permissions = new Set<string>();

    rolePermissions.forEach((rp) => permissions.add(rp.permission.name));
    userPermissions.forEach((up) => permissions.add(up.permission.name));

    return Array.from(permissions);
  }

  /* -------- GET ACTIVE ACADEMIC YEAR -------- */
  private async getActiveAcademicYear(schoolId: number): Promise<{ id: number; name: string; isActive: boolean } | null> {
    const academicYear = await this.prisma.academicYear.findFirst({
      where: {
        schoolId,
        status: 'ACTIVE',
      },
      select: {
        id: true,
        name: true,
      },
    });

    if (!academicYear) return null;

    return {
      ...academicYear,
      isActive: true,
    };
  }

  /* -------- TO PAYLOAD -------- */
  private async toPayload(user: UserWithAllPermissions): Promise<AuthUserPayload> {
    const permissions = await this.extractPermissions(user.id, user.roleId);
    const academicYear = await this.getActiveAcademicYear(user.schoolId);
    const email = await this.getUserEmail(user.id);

    return {
      id: user.id,
      email,
      schoolId: user.schoolId,
      role: user.role.name as UserRole,
      permissions,
      academicYearId: academicYear?.id,
      academicYearName: academicYear?.name,
    };
  }

  /* -------- GET USER EMAIL -------- */
  private async getUserEmail(userId: number): Promise<string> {
    const authIdentity = await this.prisma.authIdentity.findFirst({
      where: {
        userId,
        type: 'EMAIL',
        verified: true,
      },
    });

    if (!authIdentity) {
      throw new UnauthorizedException('No verified email found for user');
    }

    return authIdentity.value;
  }

  /* -------- VALIDATE USER (ARGON2 + LAZY MIGRATION) -------- */
  async validateUser(
    email: string,
    password: string,
    schoolCode: string,
  ): Promise<UserWithAllPermissions> {
    // First, find the school by code - SUBDOMAIN REMOVED
    const school = await this.prisma.school.findFirst({
      where: {
        code: schoolCode,
        isActive: true,
      },
    });

    if (!school) {
      throw new UnauthorizedException('School not found or inactive');
    }

    // Find auth identity for this school
    const authIdentity = await this.prisma.authIdentity.findFirst({
      where: {
        schoolId: school.id,
        type: 'EMAIL',
        value: email,
        verified: true,
      },
      include: {
        user: true,
      },
    });

    if (!authIdentity) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check Password
    let isPasswordValid = false;

    // 1. Try verifiable hash first (Argon2)
    try {
      if (authIdentity.secret && authIdentity.secret.startsWith('$argon2')) {
        isPasswordValid = await argon2.verify(authIdentity.secret, password);
      }
    } catch (e) {
      // Ignore error, treat as invalid hash
    }

    // 2. If not a generic hash or verification failed, check plain text (Legacy support)
    if (!isPasswordValid && authIdentity.secret === password) {
      isPasswordValid = true;

      // LAZY MIGRATION: Update to Argon2 immediately
      this.logger.log(`Migrating user ${authIdentity.userId} password to Argon2 hash`);
      const hashedPassword = await argon2.hash(password);
      await this.prisma.authIdentity.update({
        where: { id: authIdentity.id },
        data: { secret: hashedPassword },
      });
    }

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Get full user with relations
    const user = await this.prisma.user.findUnique({
      where: {
        id: authIdentity.userId,
        schoolId: school.id,
      },
      include: {
        role: true,
        school: {
          select: {
            id: true,
            name: true,
            code: true,
            // subdomain: true, // Removed from select
          },
        },
        userPermissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account inactive');
    }

    // Get active academic year
    const academicYear = await this.getActiveAcademicYear(school.id);

    this.logger.log(
      `User validated: ${email} (${user.role.name}) | School: ${school.name} | Perms: ${user.userPermissions.length}`,
    );

    return {
      ...user,
      academicYear: academicYear || undefined,
    };
  }

  /* -------- LOGIN -------- */
  async login(
    email: string,
    password: string,
    schoolCode: string,
  ) {
    const user = await this.validateUser(email, password, schoolCode);
    const payload = await this.toPayload(user);

    // Set email from auth identity
    payload.email = email;

    const accessToken = await this.jwt.signAsync(payload);

    // Create audit log
    await this.createAuditLog({
      schoolId: user.schoolId,
      userId: user.id,
      entity: 'User',
      entityId: user.id,
      action: 'LOGIN',
      ipAddress: '', // Will be set by controller
    });

    return {
      user: payload,
      accessToken,
      school: {
        id: user.school.id,
        name: user.school.name,
        code: user.school.code,
        // subdomain: user.school.subdomain, // Removed
      },
      academicYear: user.academicYear,
    };
  }

  /* -------- VERIFY TOKEN -------- */
  async verifyToken(token: string): Promise<AuthUserPayload> {
    try {
      const payload = await this.jwt.verifyAsync<AuthUserPayload>(token);

      // Verify user still exists and is active
      const user = await this.prisma.user.findUnique({
        where: {
          id: payload.id,
          schoolId: payload.schoolId,
          isActive: true,
        },
      });

      if (!user) {
        throw new UnauthorizedException('User no longer exists or is inactive');
      }

      return payload;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  /* -------- FORGOT PASSWORD UTILS -------- */
  async requestPasswordReset(email: string, schoolCode: string) {
    // 1. Find School by CODE only
    const school = await this.prisma.school.findFirst({
      where: {
        code: schoolCode,
        isActive: true,
      },
    });

    if (!school) {
      // Silent fail for security, but return generic message
      return { message: 'School Code Not Found' };
    }

    // 2. Find User Identity
    const authIdentity = await this.prisma.authIdentity.findFirst({
      where: {
        schoolId: school.id,
        type: 'EMAIL',
        value: email,
        verified: true,
      },
      include: { user: { include: { role: true } } },
    });

    if (!authIdentity) {
      return { message: 'Email does not exist' };
    }

    const { user } = authIdentity;
    const roleName = user.role.name;
    const allowedRoles = ['PRINCIPAL', 'TEACHER', 'PARENT', 'ADMIN'];

    if (!allowedRoles.includes(roleName)) {
      // Not allowed for Students/Admins per requirement
      return { message: 'Not allowed for Students' };
    }

    // 3. Generate Secure Token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // 4. Store Token
    await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        schoolId: school.id,
        token: resetToken,
        expiresAt: expiresAt,
      },
    });

    // 5. Send Email (Real)
    const resetLink = `https://edulama.com/reset-password?code=${school.code}&token=${resetToken}`;
    await this.emailService.sendPasswordResetEmail(email, resetLink, school.name);

    return { message: 'If the email exists, a reset link has been sent.' };
  }

  async resetPassword(token: string, newPassword: string) {
    // 1. Validate Token
    const resetRecord = await this.prisma.passwordReset.findUnique({
      where: { token },
    });

    if (!resetRecord) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (resetRecord.usedAt) {
      throw new BadRequestException('Token already used');
    }

    if (resetRecord.expiresAt < new Date()) {
      throw new BadRequestException('Token expired');
    }

    // 2. Hash New Password
    const hashedPassword = await argon2.hash(newPassword);

    // 3. Update AuthIdentity
    // We need to find the auth identity for this user -> email
    const authIdentity = await this.prisma.authIdentity.findFirst({
      where: {
        userId: resetRecord.userId,
        schoolId: resetRecord.schoolId,
        type: 'EMAIL'
      }
    });

    if (!authIdentity) {
      throw new BadRequestException('User authentication record not found');
    }

    await this.prisma.authIdentity.update({
      where: { id: authIdentity.id },
      data: { secret: hashedPassword }
    });

    // 4. Mark Token Used
    await this.prisma.passwordReset.update({
      where: { token },
      data: { usedAt: new Date() }
    });

    // 5. Create audit log
    await this.createAuditLog({
      schoolId: resetRecord.schoolId,
      userId: resetRecord.userId,
      entity: 'User',
      entityId: resetRecord.userId,
      action: 'UPDATE', // Could specific 'PASSWORD_RESET' if enum allows, but UPDATE is safe
      newValue: { action: 'PASSWORD_RESET' }
    });

    return { message: 'Password updated successfully' };
  }


  /* -------- CREATE AUDIT LOG -------- */
  private async createAuditLog(data: {
    schoolId: number;
    userId?: number;
    entity: string;
    entityId?: number;
    action: string;
    oldValue?: any;
    newValue?: any;
    ipAddress?: string;
  }) {
    try {
      await this.prisma.auditLog.create({
        data: {
          schoolId: data.schoolId,
          userId: data.userId,
          entity: data.entity,
          entityId: data.entityId,
          action: data.action as any,
          oldValue: data.oldValue,
          newValue: data.newValue,
          ipAddress: data.ipAddress,
        },
      });
    } catch (error) {
      this.logger.error('Failed to create audit log', error);
    }
  }

  /* -------- SWITCH ACADEMIC YEAR -------- */
  async switchAcademicYear(userId: number, schoolId: number, academicYearId: number): Promise<AuthUserPayload> {
    // Verify user belongs to school
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
        schoolId: schoolId,
        isActive: true,
      },
      include: {
        role: true,
        school: {
          select: {
            id: true,
            name: true,
            code: true,
            // subdomain: true, // Removed
          },
        },
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid user or school');
    }

    // Verify academic year belongs to school
    const academicYear = await this.prisma.academicYear.findFirst({
      where: {
        id: academicYearId,
        schoolId: schoolId,
      },
    });

    if (!academicYear) {
      throw new ForbiddenException('Academic year not found');
    }

    // Get permissions
    const permissions = await this.extractPermissions(user.id, user.roleId);
    const email = await this.getUserEmail(user.id);

    const payload: AuthUserPayload = {
      id: user.id,
      email,
      schoolId: user.schoolId,
      role: user.role.name as UserRole,
      permissions,
      academicYearId: academicYear.id,
      academicYearName: academicYear.name,
    };

    const accessToken = await this.jwt.signAsync(payload);

    return payload;
  }
}