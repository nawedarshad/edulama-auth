import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt/jwt.guard';

@Controller('test')
export class TestController {
  @UseGuards(JwtAuthGuard)
  @Get('secure')
  secure(@Req() req) {
    return {
      message: 'You are authorized!',
      user: req.user,
    };
  }
}
