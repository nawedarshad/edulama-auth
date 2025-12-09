import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import type { Role, User } from '@prisma/client';

export type UserRole = 'PRINCIPAL' | 'TEACHER' | 'STUDENT' | 'PARENT' | 'ADMIN';

export interface AuthUserPayload {
  id: number;
  email: string;
  role: UserRole;
  staffProfile?: { id: number } | null; // keep for future if needed
}

type UserWithRole = User & { role: Role };

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  private toPayload(user: UserWithRole): AuthUserPayload {
    return {
      id: user.id,
      email: user.email,
      role: user.role.name as UserRole,
    };
  }
  private readonly logger = new Logger(AuthService.name);

  async validateUser(email: string, password: string): Promise<UserWithRole> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { role: true },
    });

    if (!user) {
      this.logger.warn(`Login failed: User not found (${email})`);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.password !== password) {
      this.logger.warn(`Login failed: Wrong password (${email})`);
      throw new UnauthorizedException('Invalid credentials');
    }

    this.logger.log(`Login validated: ${email} (${user.role.name})`);
    return user;
  }

  async login(email: string, password: string) {
    this.logger.log(`Login attempt: ${email}`);

    const user = await this.validateUser(email, password);
    const payload = this.toPayload(user);

    const accessToken = await this.jwt.signAsync(payload);

    this.logger.log(`Login success: ${email} (${user.role.name})`);

    return {
      user: payload,
      accessToken,
    };
  }

  async verifyToken(token: string): Promise<AuthUserPayload> {
    try {
      const decoded = await this.jwt.verifyAsync<AuthUserPayload>(token);
      this.logger.log(`Token verification success: ${decoded.email}`);
      return decoded;
    } catch {
      this.logger.warn(`Token verification failed`);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
