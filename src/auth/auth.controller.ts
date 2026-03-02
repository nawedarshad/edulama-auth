import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
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

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

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
  async googleAuthRedirect(@Req() req, @Ip() ip: string, @Headers('user-agent') ua: string) {
    if (!req.user) {
      throw new UnauthorizedException('Google authentication failed');
    }

    return this.authService.validateGoogleUser(req.user, { ip, userAgent: ua });
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
}
