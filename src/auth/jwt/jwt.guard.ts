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
import type { AuthUserPayload, UserRole } from '../auth.service';

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
      const decoded = await this.jwt.verifyAsync<AuthUserPayload>(token);

      // Verify user still exists and is active
      const user = await this.prisma.user.findUnique({
        where: {
          id: decoded.id,
          schoolId: decoded.schoolId,
          isActive: true,
        },
        include: {
          school: {
            select: {
              isActive: true,
            },
          },
        },
      });

      if (!user) {
        throw new UnauthorizedException('User not found or inactive');
      }

      if (!user.school.isActive) {
        throw new ForbiddenException('School is inactive');
      }

      // Validate school ID from header matches token
      const schoolIdHeader = req.headers[SCHOOL_ID_HEADER] as string;
      if (schoolIdHeader && parseInt(schoolIdHeader) !== decoded.schoolId) {
        throw new ForbiddenException('School ID mismatch');
      }

      // Validate academic year if provided
      const academicYearHeader = req.headers[ACADEMIC_YEAR_HEADER] as string;
      if (academicYearHeader) {
        const academicYearId = parseInt(academicYearHeader);

        // Verify academic year belongs to user's school
        const academicYear = await this.prisma.academicYear.findFirst({
          where: {
            id: academicYearId,
            schoolId: decoded.schoolId,
          },
        });

        if (!academicYear) {
          throw new ForbiddenException('Invalid academic year');
        }

        // Add to decoded user for easy access
        decoded.academicYearId = academicYear.id;
        decoded.academicYearName = academicYear.name;
      }

      req.user = decoded;
      return true;
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

/* -------- PERMISSION GUARD -------- */
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.get<string[]>(
      'permissions',
      context.getHandler(),
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<RequestWithUser>();
    const user = req.user;

    if (!user) {
      throw new UnauthorizedException('User not authenticated');
    }

    const hasPermission = requiredPermissions.some(permission =>
      user.permissions.includes(permission),
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
  constructor(private readonly reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<UserRole[]>(
      'roles',
      context.getHandler(),
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<RequestWithUser>();
    const user = req.user;

    if (!user) {
      throw new UnauthorizedException('User not authenticated');
    }

    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      throw new ForbiddenException(
        `Insufficient role. Required: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}