import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  Patch,
  UnauthorizedException,
  Ip,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  schoolCode: string;
}

class SwitchAcademicYearDto {
  @IsNotEmpty()
  academicYearId: number;
}

class ForgotPasswordDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  schoolCode: string;
}

class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  newPassword: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) { }

  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
  ) {
    if (!body.schoolCode) {
      throw new UnauthorizedException('School code is required');
    }

    const result = await this.auth.login(body.email, body.password, body.schoolCode);

    // Add IP address to audit log (handled in service)
    return result;
  }

  @Post('forgot-password')
  async forgotPassword(@Body() body: ForgotPasswordDto) {
    if (!body.schoolCode) {
      throw new UnauthorizedException('School code is required');
    }
    return this.auth.requestPasswordReset(body.email, body.schoolCode);
  }

  @Post('reset-password')
  async resetPassword(@Body() body: ResetPasswordDto) {
    return this.auth.resetPassword(body.token, body.newPassword);
  }

  @Post('verify')
  async verify(@Headers('authorization') authHeader?: string) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];
    return this.auth.verifyToken(token);
  }

  @Patch('switch-academic-year')
  async switchAcademicYear(
    @Headers('authorization') authHeader: string,
    @Body() body: SwitchAcademicYearDto,
  ) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];
    const currentUser = await this.auth.verifyToken(token);

    if (!currentUser) {
      throw new UnauthorizedException('Invalid token');
    }

    const newPayload = await this.auth.switchAcademicYear(
      currentUser.id,
      currentUser.schoolId,
      body.academicYearId,
    );

    const newToken = await this.auth['jwt'].signAsync(newPayload);

    return {
      user: newPayload,
      accessToken: newToken,
    };
  }

  @Get('me')
  async getCurrentUser(@Headers('authorization') authHeader: string) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];
    const user = await this.auth.verifyToken(token);

    // Get fresh school info
    const school = await this.auth['prisma'].school.findUnique({
      where: { id: user.schoolId },
      select: {
        id: true,
        name: true,
        code: true,
        // subdomain: true, // Removed
      },
    });

    // Get available academic years for this school
    const academicYears = await this.auth['prisma'].academicYear.findMany({
      where: { schoolId: user.schoolId },
      select: {
        id: true,
        name: true,
        status: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return {
      user,
      school,
      academicYears: academicYears.map(ay => ({
        id: ay.id,
        name: ay.name,
        isActive: ay.status === 'ACTIVE',
      })),
      currentAcademicYear: academicYears
        .filter(ay => ay.id === user.academicYearId)
        .map(ay => ({
          id: ay.id,
          name: ay.name,
          isActive: ay.status === 'ACTIVE',
        }))[0],
    };
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }
}