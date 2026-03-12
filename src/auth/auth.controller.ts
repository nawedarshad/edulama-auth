import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  UnauthorizedException,
  Headers,
  Query,
  Ip,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { GoogleAuthGuard } from './google-auth.guard';
import { JwtAuthGuard } from './jwt/jwt.guard';
import { IsNotEmpty, IsString, IsEnum, IsOptional } from 'class-validator';
import { AuthType } from '@prisma/client';

class SigninDto {
  @IsString()
  @IsNotEmpty()
  email: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsString()
  schoolCode?: string;
}



class OtpRequestDto {
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @IsEnum(AuthType)
  @IsNotEmpty()
  type: 'EMAIL' | 'PHONE';
}

class OtpVerifyDto {
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @IsString()
  @IsNotEmpty()
  code: string;

  @IsEnum(AuthType)
  @IsNotEmpty()
  type: 'EMAIL' | 'PHONE';
}

class SelectSchoolDto {
  @IsNotEmpty()
  schoolId: number;
}

class RefreshDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

class ChangePasswordDto {
  @IsOptional()
  @IsString()
  oldPassword?: string;

  @IsString()
  @IsNotEmpty()
  newPassword: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  // ==========================
  // HEALTH CHECK
  // ==========================

  @Get('health')
  checkHealth() {
    return { status: 'ok', service: 'auth-ms', timestamp: new Date().toISOString() };
  }

  // ==========================
  // GOOGLE OAUTH
  // ==========================

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req) {
    // Passport redirects to Google
  }

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(@Req() req, @Res() res, @Ip() ip: string, @Headers('user-agent') ua: string) {
    if (!req.user) {
      throw new UnauthorizedException('Google authentication failed');
    }

    const result = await this.authService.validateGoogleUser(req.user, { ip, userAgent: ua }) as any;

    // Detect if this came from the mobile app via the state param
    let oauthState: any = {};
    try {
      const rawState = req.query.state || req.user?.oauthState;
      if (rawState && typeof rawState === 'string') {
        oauthState = JSON.parse(rawState);
      } else if (req.user?.oauthState) {
        oauthState = req.user.oauthState;
      }
    } catch { }

    const isMobile = oauthState?.platform === 'mobile';
    const mobileRedirect = oauthState?.mobileRedirect || 'edulama://auth/callback';

    if (isMobile) {
      // Build the mobile deep-link with tokens as query params
      const params = new URLSearchParams();
      params.set('accessToken', result.accessToken || '');
      params.set('refreshToken', result.refreshToken || '');
      if (result.user?.id) params.set('userId', String(result.user.id));
      if (result.user?.name) params.set('name', result.user.name);
      if (result.user?.role) params.set('role', result.user.role);
      if (result.school?.id) params.set('schoolId', String(result.school.id));
      if (result.school?.subdomain) params.set('subdomain', result.school.subdomain);
      if (result.academicYearId) params.set('academicYearId', String(result.academicYearId));
      if (result.requireSchoolSelection) params.set('requireSchoolSelection', 'true');
      if (result.user?.memberships) {
        params.set('memberships', encodeURIComponent(JSON.stringify(result.user.memberships)));
      }
      if (result.modules) {
        params.set('modules', encodeURIComponent(JSON.stringify(result.modules)));
      }

      return res.redirect(`${mobileRedirect}?${params.toString()}`);
    }

    // Web: return JSON as before
    return res.json(result);
  }


  @Post('signin')
  async signin(@Body() body: SigninDto, @Ip() ip: string, @Headers('user-agent') ua: string) {
    return this.authService.signin(body.email, body.password, body.schoolCode, {
      ip,
      userAgent: ua,
    });
  }

  // ==========================
  // OTP AUTHENTICATION
  // ==========================

  @Post('otp/request')
  async requestOtp(@Body() body: OtpRequestDto, @Ip() ip: string, @Headers('user-agent') ua: string) {
    return this.authService.requestOtp(body.identifier, body.type, { ip, userAgent: ua });
  }

  @Post('otp/verify')
  async verifyOtp(@Body() body: OtpVerifyDto, @Ip() ip: string, @Headers('user-agent') ua: string) {
    return this.authService.verifyOtpAndLogin(
      body.identifier,
      body.code,
      body.type,
      { ip, userAgent: ua },
    );
  }

  // ==========================
  // POST-LOGIN FLOWS
  // ==========================

  @Post('select-school')
  @UseGuards(JwtAuthGuard)
  async selectSchool(@Req() req, @Body() body: SelectSchoolDto) {
    // Current user context is from JWT (Base token with no school selection yet, or changing school)
    if (!req.user?.sub) {
      throw new UnauthorizedException('Invalid token structure');
    }

    const tokens = await this.authService.selectSchool(
      req.user.sub,
      body.schoolId,
      { ip: req.ip, userAgent: req.headers['user-agent'] },
    );

    return {
      message: 'School selected successfully',
      ...tokens,
    };
  }

  // ==========================
  // TOKEN MANAGEMENT
  // ==========================

  @Post('refresh')
  async refreshTokens(@Body() body: RefreshDto, @Ip() ip: string, @Headers('user-agent') ua: string) {
    return this.authService.refreshToken(body.refreshToken, {
      ip,
      userAgent: ua,
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Req() req) {
    return { user: await this.authService.getMe(req.user) };
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  async changePassword(@Req() req, @Body() body: ChangePasswordDto) {
    return this.authService.changePassword(
      req.user.sub,
      body.newPassword,
      body.oldPassword,
    );
  }
}
