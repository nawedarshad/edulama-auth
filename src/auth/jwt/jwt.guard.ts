import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import type { AuthUserPayload } from '../auth.service';

export const SCHOOL_ID_HEADER = 'x-school-id';
export const ACADEMIC_YEAR_HEADER = 'x-academic-year-id';

interface RequestWithUser extends Request {
  user?: AuthUserPayload;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
    private readonly reflector: Reflector,
    private readonly config: ConfigService,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithUser>();

    let token: string | undefined;
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    if (!token && (req as any).cookies) {
      token = (req as any).cookies['accessToken'];
    }

    if (!token) {
      throw new UnauthorizedException('Missing authentication token');
    }

    try {
      const decoded = await this.jwt.verifyAsync<AuthUserPayload>(token, {
        secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'),
        algorithms: ['HS256'],
        issuer: this.config.get<string>('JWT_ISSUER'),
        audience: this.config.get<string>('JWT_AUDIENCE'),
        clockTolerance: 5,
      });

      if (!decoded.sub || !decoded.tokenVersion) {
        throw new UnauthorizedException('Invalid token payload');
      }

      // Verify tenant context if header is present
      const schoolIdHeader = req.headers[SCHOOL_ID_HEADER];
      if (schoolIdHeader) {
        const schoolId = parseInt(schoolIdHeader as string);
        if (decoded.schoolId && decoded.schoolId !== schoolId) {
          throw new ForbiddenException('Invalid tenant context');
        }
      }

      // Verify token version against DB (Revocation check)
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.sub, isActive: true },
        select: { tokenVersion: true },
      });

      if (!user) {
        throw new UnauthorizedException('User not found or inactive');
      }

      if (user.tokenVersion !== decoded.tokenVersion) {
        throw new UnauthorizedException('Token revoked');
      }

      req.user = decoded;
      return true;
    } catch (error) {
      if (error instanceof ForbiddenException || error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

/* -------- PERMISSION GUARD -------- */
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<string[]>(
      'permissions',
      context.getHandler(),
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<RequestWithUser>();
    const userPayload = req.user;

    if (!userPayload || !userPayload.sub || !userPayload.roleId) {
      throw new UnauthorizedException(
        'User not authenticated or no active role selected',
      );
    }

    const activePermissions = new Set(userPayload.permissions || []);

    const hasPermission = requiredPermissions.some((permission) =>
      activePermissions.has(permission),
    );

    if (!hasPermission) {
      throw new ForbiddenException(
        `Insufficient permissions. Required: ${requiredPermissions.join(', ')}`,
      );
    }

    return true;
  }
}

/* -------- ROLE GUARD -------- */
@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      context.getHandler(),
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<RequestWithUser>();
    const userPayload = req.user;

    if (!userPayload || !userPayload.sub || !userPayload.roleId) {
      throw new UnauthorizedException(
        'User not authenticated or no role selected',
      );
    }

    const hasRole = requiredRoles.includes(userPayload.role || '');

    if (!hasRole) {
      throw new ForbiddenException(
        `Insufficient role. Required: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
