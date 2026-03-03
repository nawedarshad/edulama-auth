import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { OtpService } from './otp.service';
import { AuthType } from '@prisma/client';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';

export interface AuthUserPayload {
  sub: number; // userId
  schoolId?: number;
  roleId?: number;
  role?: string; // Role name
  subdomain?: string;
  email?: string;
  tokenVersion: number;
  permissions: string[];
  type: 'access' | 'refresh';
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  private readonly frontendBaseUrl =
    process.env.FRONTEND_BASE_URL?.trim() || 'http://localhost:3000';

  private maskIdentifier(id: string | number | null | undefined): string {
    if (!id) return 'unknown';
    const s = String(id);
    if (s.includes('@')) {
      const [u, d] = s.split('@');
      return `${u.slice(0, 2)}***@${d}`;
    }
    if (s.length > 5) {
      return `${s.slice(0, 3)}***${s.slice(-2)}`;
    }
    return '***';
  }

  private resolveSubdomainForMembership(membership: any): string {
    const schoolSubdomain = membership?.school?.subdomain?.trim();
    if (schoolSubdomain) return schoolSubdomain;

    const schoolCode = membership?.school?.code?.trim();
    if (schoolCode) return schoolCode.toLowerCase();

    return '';
  }

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly otpService: OtpService,
  ) { }

  private async createAuditLog(
    schoolId: number,
    userId: number | null,
    action: any, // AuditAction
    ipAddress?: string,
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          schoolId,
          userId,
          action,
          entity: 'Authentication',
          ipAddress,
        },
      });
    } catch (err) {
      this.logger.error(`Failed to create audit log: ${err.message}`);
    }
  }

  // ==========================
  // JWT UTILS
  // ==========================

  private async generateTokens(
    userId: number,
    schoolId?: number,
    roleId?: number,
    email?: string,
    role?: string,
    subdomain?: string,
    meta?: { ip?: string; userAgent?: string },
  ) {
    // 1. Fetch user for tokenVersion & validation
    const user = await this.prisma.user.findUnique({
      where: { id: userId, isActive: true },
      select: { tokenVersion: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // 2. Fetch permissions in parallel with minimal fields
    let permissions: string[] = [];
    if (roleId) {
      const [rolePerms, userPerms] = await Promise.all([
        this.prisma.rolePermission.findMany({
          where: { roleId },
          select: { permission: { select: { name: true } } },
        }),
        this.prisma.userPermission.findMany({
          where: { userId },
          select: { permission: { select: { name: true } } },
        }),
      ]);

      permissions = Array.from(
        new Set([
          ...rolePerms.map((rp) => rp.permission.name),
          ...userPerms.map((up) => up.permission.name),
        ]),
      );
    }

    const payload: AuthUserPayload = {
      sub: userId,
      schoolId: schoolId || undefined,
      roleId: roleId || undefined,
      role,
      subdomain,
      email,
      tokenVersion: user.tokenVersion,
      permissions,
      type: 'access',
    };

    const accessToken = await this.jwt.signAsync(payload, {
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '1h',
    });

    // Generate refresh token manually
    const rawRefreshToken = crypto.randomBytes(40).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawRefreshToken)
      .digest('hex');
    const refreshTokenExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN || '30d';
    const expiresAt = new Date(Date.now() + (refreshTokenExpiresIn.endsWith('d') ? parseInt(refreshTokenExpiresIn) * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000));

    await this.prisma.authToken.create({
      data: {
        userId,
        schoolId,
        roleId,
        tokenHash,
        expiresAt,
        ip: meta?.ip,
        userAgent: meta?.userAgent,
      },
    });

    return {
      accessToken,
      refreshToken: rawRefreshToken,
    };
  }

  // ==========================
  // GOOGLE OAUTH
  // ==========================

  async validateGoogleUser(
    profile: any,
    meta?: { ip?: string; userAgent?: string },
  ) {
    const { googleId, displayName, picture, oauthState } = profile;
    const email = profile.email?.toLowerCase().trim();
    this.logger.log(`validateGoogleUser for email: ${this.maskIdentifier(email)}`);

    // CSRF / Multi-tenant Validation
    const schoolIdFromState = oauthState?.schoolId ? parseInt(oauthState.schoolId) : null;

    // 1. Check if identity exists for Google
    const googleIdentity = await this.prisma.authIdentity.findUnique({
      where: { type_value: { type: AuthType.GOOGLE, value: googleId } },
      include: {
        user: {
          include: {
            userSchools: { include: { school: true, role: true } },
            school: true,
            role: true,
          },
        },
      },
    });

    // 2. Check if identity exists for Email (Account Linking)
    const emailIdentity = await this.prisma.authIdentity.findUnique({
      where: { type_value: { type: AuthType.EMAIL, value: email } },
      include: {
        user: {
          include: {
            userSchools: { include: { school: true, role: true } },
            school: true,
            role: true,
          },
        },
      },
    });

    let user;

    if (googleIdentity && emailIdentity) {
      if (googleIdentity.userId === emailIdentity.userId) {
        user = googleIdentity.user;
      } else {
        // Unify
        await this.prisma.authIdentity.update({
          where: { id: googleIdentity.id },
          data: { userId: emailIdentity.userId },
        });
        user = await this.prisma.user.findUnique({
          where: { id: emailIdentity.userId },
          include: {
            userSchools: { include: { school: true, role: true } },
            school: true,
            role: true,
          },
        });
      }
    } else if (googleIdentity) {
      user = googleIdentity.user;
    } else if (emailIdentity) {
      user = emailIdentity.user;
      await this.prisma.authIdentity.create({
        data: {
          userId: user.id,
          type: AuthType.GOOGLE,
          value: googleId,
          verified: true,
        },
      });
    } else {
      // 3. Create new user globally
      user = await this.prisma.user.create({
        data: {
          name: displayName || email,
          photo: picture,
          authIdentities: {
            create: [
              { type: AuthType.GOOGLE, value: googleId, verified: true },
              { type: AuthType.EMAIL, value: email, verified: true },
            ],
          },
        },
        include: {
          userSchools: { include: { school: true, role: true } },
          school: true,
          role: true,
        },
      });
    }

    if (!user.isActive) {
      throw new UnauthorizedException('User account is inactive');
    }

    // Tenant Check: If schoolId was provided in OAuth state, verify user belongs to it
    if (schoolIdFromState) {
      const hasMembership = user.userSchools.some(
        (m: any) => m.schoolId === schoolIdFromState,
      );
      const isGlobalAdmin = user.role?.name === 'SAAS_ADMIN';

      if (!hasMembership && !isGlobalAdmin && user.schoolId !== schoolIdFromState) {
        throw new UnauthorizedException('User does not belong to the requested school');
      }
    }

    this.logger.log(`Google login success for userId: ${user.id}`);
    return this.handlePostLogin(user, email, meta);
  }


  // ==========================
  // OTP AUTHENTICATION
  // ==========================

  async requestOtp(
    identifier: string,
    type: 'EMAIL' | 'PHONE',
    meta?: { ip?: string; userAgent?: string },
  ) {
    return this.otpService.generateAndSendOtp(identifier, AuthType[type], meta);
  }

  async verifyOtpAndLogin(
    identifier: string,
    code: string,
    type: 'EMAIL' | 'PHONE',
    meta?: { ip?: string; userAgent?: string },
  ) {
    const normalizedIdentifier = identifier.toLowerCase().trim();
    this.logger.log(`Verifying OTP for ${this.maskIdentifier(normalizedIdentifier)}`);

    // 1. Verify the OTP
    await this.otpService.verifyOtp(normalizedIdentifier, code, AuthType[type]);

    // 2. Find or Create User
    const identity = await this.prisma.authIdentity.findUnique({
      where: { type_value: { type: AuthType[type], value: normalizedIdentifier } },
      include: {
        user: {
          include: {
            userSchools: { include: { school: true, role: true } },
            school: true,
            role: true,
          },
        },
      },
    });

    let user;
    if (identity) {
      if (!identity.verified) {
        await this.prisma.authIdentity.update({
          where: { id: identity.id },
          data: { verified: true },
        });
      }
      user = identity.user;
    } else {
      // Create new global user securely
      user = await this.prisma.user.create({
        data: {
          name: normalizedIdentifier.split('@')[0],
          authIdentities: {
            create: [
              {
                type: AuthType[type],
                value: normalizedIdentifier,
                verified: true,
              },
            ],
          },
        },
        include: {
          userSchools: { include: { school: true, role: true } },
          school: true,
          role: true,
        },
      });
    }

    return this.handlePostLogin(
      user,
      type === 'EMAIL' ? normalizedIdentifier : undefined,
      meta,
    );
  }

  // ==========================
  // POST-LOGIN HANDLER
  // ==========================

  private async handlePostLogin(
    user: any,
    email?: string,
    meta?: { ip?: string; userAgent?: string },
  ) {
    if (!user.isActive) {
      throw new UnauthorizedException('User account is inactive');
    }

    const memberships = user.userSchools || [];
    this.logger.log(`Post-login for user ${user.id}: ${memberships.length} memberships`);

    // Determine if we can auto-select a school/role:
    // 1. If there's an explicit primary membership
    // 2. OR if there's ONLY one membership
    let primaryMembership = memberships.find((m: any) => m.isPrimary) || (memberships.length === 1 ? memberships[0] : null);

    // Fallback info from the user record directly (for staff on a single school)
    // BUT: If the user has multiple overlapping memberships, we ignore the direct schoolId fallback 
    // to force the "Select School" selector.
    let selectedSchool = primaryMembership?.school;
    let selectedRole = primaryMembership?.role?.name || (memberships.length <= 1 ? user.role?.name : null);
    let selectedSchoolId = primaryMembership?.schoolId || (memberships.length <= 1 ? user.schoolId : null);

    let resolvedSubdomain = '';

    if (!primaryMembership && memberships.length <= 1 && user.schoolId) {
      const school = user.school || await this.prisma.school.findUnique({ where: { id: user.schoolId } });
      if (school) {
        selectedSchool = school;
        resolvedSubdomain = school.subdomain;
      }
    }

    if (primaryMembership) {
      resolvedSubdomain = this.resolveSubdomainForMembership(primaryMembership);
      selectedSchool = primaryMembership.school;
      selectedRole = primaryMembership.role?.name;
      selectedSchoolId = primaryMembership.schoolId;
    }

    if (selectedSchoolId && selectedRole) {

      const tokens = await this.generateTokens(
        user.id,
        selectedSchoolId,
        user.roleId || (primaryMembership?.roleId),
        email,
        selectedRole,
        resolvedSubdomain,
        meta,
      );

      let activeYear: { id: number } | null = null;
      try {
        activeYear = await this.prisma.academicYear.findFirst({
          where: { schoolId: selectedSchoolId, status: 'ACTIVE' },
          select: { id: true },
          orderBy: { startDate: 'desc' },
        });
      } catch (err) {
        this.logger.error(`Failed to fetch active academic year: ${err.message}`);
      }

      if (selectedSchoolId) {
        await this.createAuditLog(selectedSchoolId, user.id, 'LOGIN', meta?.ip);
      }

      return {
        user: { id: user.id, name: user.name, memberships, role: selectedRole },
        school: {
          ...selectedSchool,
          subdomain: resolvedSubdomain || selectedSchool?.subdomain,
        },
        academicYearId: activeYear?.id,
        ...tokens,
      };
    }

    if (memberships.length === 0 && !user.schoolId && user.role) {
      const tokens = await this.generateTokens(
        user.id,
        undefined,
        user.roleId,
        email,
        user.role.name,
        undefined,
        meta,
      );
      return {
        user: { id: user.id, name: user.name, role: user.role.name, memberships: [] },
        message: `Logged in as global ${user.role.name}`,
        ...tokens,
      };
    }

    const tokens = await this.generateTokens(user.id, undefined, undefined, email, undefined, undefined, meta);
    const membershipsWithResolvedSubdomain = memberships.map((m: any) => ({
      ...m,
      school: m.school ? {
        ...m.school,
        subdomain: this.resolveSubdomainForMembership(m) || m.school?.subdomain,
      } : m.school,
    }));

    return {
      message: memberships.length === 0 ? 'No school memberships found.' : 'Multiple schools found. Please select a school.',
      requireSchoolSelection: memberships.length > 0,
      user: { id: user.id, name: user.name, memberships: membershipsWithResolvedSubdomain },
      ...tokens,
    };
  }

  // ==========================
  // PASSWORD AUTHENTICATION
  // ==========================

  async signin(
    email: string,
    password?: string,
    schoolCode?: string,
    meta?: { ip?: string; userAgent?: string },
  ) {
    const normalizedEmail = email.toLowerCase().trim();
    // 1. Find the local identity
    const identity = await this.prisma.authIdentity.findUnique({
      where: { type_value: { type: AuthType.EMAIL, value: normalizedEmail } },
      include: {
        user: {
          include: {
            userSchools: { include: { school: true, role: true } },
            school: true,
            role: true, // Global role
          },
        },
      },
    });

    if (!identity) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 2. Verify password (Require for EMAIL type)
    if (!password) {
      throw new UnauthorizedException('Password is required for email login');
    }

    if (identity.secret) {
      const isHashed = identity.secret.startsWith('$argon2');
      let isPasswordValid = false;

      if (isHashed) {
        isPasswordValid = await argon2.verify(identity.secret, password);
      } else {
        // Migration logic: Handle plain text passwords
        isPasswordValid = identity.secret === password;
        if (isPasswordValid) {
          const newHash = await argon2.hash(password);
          await this.prisma.authIdentity.update({
            where: { id: identity.id },
            data: { secret: newHash },
          });
          this.logger.log(`Migrated plain-text password for identity: ${identity.id}`);
        }
      }

      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid credentials');
      }
    } else {
      throw new UnauthorizedException('Please sign in with Google');
    }

    // 3. Handle school filtering if schoolCode is provided
    if (schoolCode && identity.user.userSchools.length > 0) {
      const targetMembership = identity.user.userSchools.find(
        (m) => m.school.code.toLowerCase() === schoolCode.toLowerCase(),
      );

      if (targetMembership) {
        const resolvedSubdomain = this.resolveSubdomainForMembership(targetMembership);
        const tokens = await this.generateTokens(
          identity.user.id,
          targetMembership.schoolId,
          targetMembership.roleId,
          email,
          targetMembership.role.name,
          resolvedSubdomain,
          meta,
        );
        return {
          ...tokens,
          user: {
            id: identity.user.id,
            name: identity.user.name,
            role: targetMembership.role.name,
          },
          school: {
            ...targetMembership.school,
            subdomain: resolvedSubdomain || targetMembership.school?.subdomain,
          },
        };
      }
    }

    // 4. Fallback to normal post-login
    return this.handlePostLogin(identity.user, email, meta);
  }

  // ==========================
  // SCHOOL SELECTION
  // ==========================

  async selectSchool(
    userId: number,
    schoolId: number,
    meta?: { ip?: string; userAgent?: string },
  ) {
    const membership = await this.prisma.userSchool.findUnique({
      where: { userId_schoolId: { userId, schoolId } },
      include: {
        user: { include: { role: true } },
        school: true,
        role: true,
      },
    });

    if (!membership || !membership.isActive) {
      throw new UnauthorizedException('Invalid or inactive school membership');
    }

    const emailIdentity = await this.prisma.authIdentity.findFirst({
      where: { userId, type: AuthType.EMAIL },
    });

    const resolvedSubdomain = this.resolveSubdomainForMembership(membership);
    const tokens = await this.generateTokens(
      userId,
      membership.schoolId,
      membership.roleId,
      emailIdentity?.value,
      membership.role?.name,
      resolvedSubdomain,
      meta,
    );

    let activeYear: { id: number } | null = null;
    try {
      activeYear = await this.prisma.academicYear.findFirst({
        where: { schoolId, status: 'ACTIVE' },
        select: { id: true },
        orderBy: { startDate: 'desc' },
      });
    } catch (err) {
      this.logger.error(`Failed to fetch active academic year: ${err.message}`);
    }

    return {
      ...tokens,
      academicYearId: activeYear?.id,
      school: {
        ...membership.school,
        subdomain: resolvedSubdomain || membership.school?.subdomain,
      },
      role: membership.role ? { id: membership.role.id, name: membership.role.name } : undefined,
    };
  }

  // ==========================
  // REFRESH TOKENS
  // ==========================

  async refreshToken(
    rawRefreshToken: string,
    meta?: { ip?: string; userAgent?: string },
  ) {
    const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');

    const authToken = await this.prisma.authToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: {
            userSchools: { include: { school: true, role: true } },
            role: true,
          },
        },
      },
    });

    if (!authToken || authToken.expiresAt < new Date()) {
      if (authToken) await this.prisma.authToken.delete({ where: { id: authToken.id } });
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Refresh Token Context Preservation
    const user = authToken.user;
    const schoolId = authToken.schoolId;
    const roleId = authToken.roleId;

    // Device Metadata Check (Optional/Warning)
    if (authToken.ip && meta?.ip && authToken.ip !== meta.ip) {
      this.logger.warn(`Refresh token IP mismatch for user ${user.id}. Original: ${authToken.ip}, Current: ${meta.ip}`);
    }

    // Rotate token
    await this.prisma.authToken.delete({ where: { id: authToken.id } });

    // Find email
    const emailIdentity = await this.prisma.authIdentity.findFirst({
      where: { userId: user.id, type: AuthType.EMAIL },
    });

    // If we had context, use it.
    if (schoolId && roleId) {
      const membership = user.userSchools.find((m: any) => m.schoolId === schoolId && m.roleId === roleId);
      const roleName = membership?.role?.name || (user.roleId === roleId ? user.role?.name : undefined);
      const subdomain = membership ? this.resolveSubdomainForMembership(membership) : undefined;

      return {
        ...(await this.generateTokens(
          user.id,
          schoolId,
          roleId,
          emailIdentity?.value,
          roleName,
          subdomain,
          meta,
        )),
        user: { id: user.id, name: user.name, role: roleName },
      };
    }

    // Fallback to base login flow (auto-select if 1)
    return this.handlePostLogin(user, emailIdentity?.value, meta);
  }

  // ==========================
  // PROFILE HANDLER
  // ==========================

  async getMe(payload: AuthUserPayload) {
    if (payload.roleId) {
      const role = await this.prisma.role.findUnique({
        where: { id: payload.roleId },
        select: { name: true },
      });
      return { ...payload, role: role?.name };
    }
    return payload;
  }

  async revokeTokens(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { tokenVersion: { increment: 1 } },
    });
    this.logger.log(`Tokens revoked for user ${userId}`);
  }
}
