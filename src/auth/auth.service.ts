import { Injectable, UnauthorizedException } from '@nestjs/common';
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

  async validateUser(email: string, password: string): Promise<UserWithRole> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { role: true },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // ⚠️ DEV ONLY – later replace with bcrypt
    if (user.password !== password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return user;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    const payload = this.toPayload(user);

    const accessToken = await this.jwt.signAsync(payload);
    console.log('Login endpoint hit!');

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
