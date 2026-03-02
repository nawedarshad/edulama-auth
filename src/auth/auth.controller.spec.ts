import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { GoogleAuthGuard } from './google-auth.guard';
import { JwtAuthGuard } from './jwt/jwt.guard';

describe('AuthController', () => {
  let controller: AuthController;

  const mockAuthService = {
    signin: jest.fn(),
    requestOtp: jest.fn(),
    verifyOtpAndLogin: jest.fn(),
    selectSchool: jest.fn(),
    refreshToken: jest.fn(),
    getMe: jest.fn(),
    validateGoogleUser: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
      ],
    })
      .overrideGuard(GoogleAuthGuard).useValue({ canActivate: () => true })
      .overrideGuard(JwtAuthGuard).useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
