import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly jwt: JwtService,
  ) {
    console.log('RUNNING JWT SECRET:', process.env.JWT_ACCESS_SECRET);
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    console.log(
      'JWT SECRET USED:',
      // internal field but handy for debugging
      (this.jwt as any)['jwtOptionsProvider'] ?? 'NO JWT OPTIONS FOUND',
    );

    return this.auth.login(body.email, body.password);
  }

  @Post('verify')
  async verify(@Headers('authorization') authHeader?: string) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];
    const user = await this.auth.verifyToken(token);

    return user;
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }
}
