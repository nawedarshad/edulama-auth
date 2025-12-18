import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import type { Role, User } from '@prisma/client';

export type UserRole = 'PRINCIPAL' | 'TEACHER' | 'STUDENT' | 'PARENT' | 'ADMIN';

export interface AuthUserPayload {
  id: number;
  email: string;
  role: UserRole;
  permissions: string[];
}

type UserWithAllPermissions = User & {
  role: Role & {
    Role: {
      permission: {
        name: string;
      };
    }[];
  };
  userPermissions: {
    permission: {
      name: string;
    };
  }[];
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  /* -------- MERGE ROLE + USER PERMISSIONS -------- */

  private extractPermissions(user: UserWithAllPermissions): string[] {
    const rolePermissions =
      user.role?.Role?.map((rp) => rp.permission.name) ?? [];

    const userPermissions =
      user.userPermissions?.map((up) => up.permission.name) ?? [];

    return Array.from(new Set([...rolePermissions, ...userPermissions]));
  }

  private toPayload(user: UserWithAllPermissions): AuthUserPayload {
    return {
      id: user.id,
      email: user.email,
      role: user.role.name as UserRole,
      permissions: this.extractPermissions(user),
    };
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserWithAllPermissions> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        role: {
          include: {
            Role: {
              include: {
                permission: true,
              },
            },
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
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.password !== password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account inactive');
    }

    this.logger.log(
      `User validated: ${email} (${user.role.name}) | perms=${user.userPermissions.length}`,
    );

    return user;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    const payload = this.toPayload(user);
    const accessToken = await this.jwt.signAsync(payload);

    return {
      user: payload,
      accessToken,
    };
  }

  async verifyToken(token: string): Promise<AuthUserPayload> {
    try {
      return await this.jwt.verifyAsync<AuthUserPayload>(token);
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
