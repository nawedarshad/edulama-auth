import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { OtpService } from './otp.service';
import { EmailService } from '../email/email.service';
import { AuthType } from '@prisma/client';
import { UnauthorizedException } from '@nestjs/common';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';

jest.mock('argon2');

describe('AuthService', () => {
  let service: AuthService;
  let prisma: PrismaService;
  let jwt: JwtService;

  const mockPrisma = {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
      create: jest.fn(),
    },
    authIdentity: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
    },
    authToken: {
      create: jest.fn(),
      findUnique: jest.fn(),
      delete: jest.fn(),
    },
    userSchool: {
      findUnique: jest.fn(),
    },
    academicYear: {
      findFirst: jest.fn(),
    },
    role: {
      findUnique: jest.fn(),
    },
    school: {
      findUnique: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
    },
    rolePermission: {
      findMany: jest.fn().mockResolvedValue([]),
    },
    userPermission: {
      findMany: jest.fn().mockResolvedValue([]),
    },
  };

  const mockJwt = {
    signAsync: jest.fn(),
  };

  const mockConfig = {
    get: jest.fn((key: string, defaultValue?: any) => defaultValue || null),
    getOrThrow: jest.fn((key: string) => {
      if (key === 'JWT_ACCESS_EXPIRES') return '15m';
      if (key === 'JWT_REFRESH_EXPIRES_DAYS') return '7d';
      return 'mocked_secret';
    }),
  };

  const mockOtpService = {
    generateAndSendOtp: jest.fn(),
    verifyOtp: jest.fn(),
  };

  const mockEmailService = {
    sendPasswordResetEmail: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: mockJwt },
        { provide: ConfigService, useValue: mockConfig },
        { provide: OtpService, useValue: mockOtpService },
        { provide: EmailService, useValue: mockEmailService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prisma = module.get<PrismaService>(PrismaService);
    jwt = module.get<JwtService>(JwtService);

    // Default mocks for generateTokens
    mockPrisma.user.findUnique.mockResolvedValue({ id: 10, tokenVersion: 1 });
    mockPrisma.rolePermission.findMany.mockResolvedValue([]);
    mockPrisma.userPermission.findMany.mockResolvedValue([]);

    jest.clearAllMocks();
  });

  describe('signin', () => {
    it('should successfully sign in with argon2 hashed password', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      const identity = {
        id: 1,
        secret: '$argon2id$v=19$m=65536,t=3,p=4$mockhash',
        user: {
          id: 10,
          isActive: true,
          userSchools: [],
          role: { name: 'USER' },
        },
      };

      mockPrisma.authIdentity.findUnique.mockResolvedValue(identity);
      (argon2.verify as jest.Mock).mockResolvedValue(true);
      mockJwt.signAsync.mockResolvedValue('mock_token');
      mockPrisma.authToken.create.mockResolvedValue({ id: 100 });

      const result = await service.signin(email, password);

      expect(result).toBeDefined();
      expect(argon2.verify).toHaveBeenCalled();
      expect(mockPrisma.authIdentity.update).not.toHaveBeenCalled();
    });

    it('should migrate plain-text password on successful sign in', async () => {
      const email = 'migrate@example.com';
      const password = 'plaintext_pwd';
      const identity = {
        id: 2,
        secret: 'plaintext_pwd', // Not hashed
        user: {
          id: 20,
          isActive: true,
          userSchools: [],
          role: { name: 'USER' },
        },
      };

      mockPrisma.authIdentity.findUnique.mockResolvedValue(identity);
      (argon2.hash as jest.Mock).mockResolvedValue('$argon2_new_hash');
      mockJwt.signAsync.mockResolvedValue('mock_token');
      mockPrisma.authToken.create.mockResolvedValue({ id: 101 });

      const result = await service.signin(email, password);

      expect(result).toBeDefined();
      expect(mockPrisma.authIdentity.update).toHaveBeenCalledWith({
        where: { id: 2 },
        data: { secret: '$argon2_new_hash' },
      });
    });

    it('should throw UnauthorizedException for wrong password', async () => {
      const email = 'test@example.com';
      const identity = {
        secret: '$argon2id$...',
        user: { isActive: true },
      };
      mockPrisma.authIdentity.findUnique.mockResolvedValue(identity);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(service.signin(email, 'wrong')).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('refreshToken', () => {
    it('should rotate tokens and preserve context', async () => {
      const oldRawToken = 'old_refresh_token';
      const oldTokenHash = crypto.createHash('sha256').update(oldRawToken).digest('hex');
      const authToken = {
        id: 100,
        userId: 1,
        schoolId: 10,
        roleId: 5,
        expiresAt: new Date(Date.now() + 10000),
        user: {
          id: 1,
          isActive: true,
          userSchools: [{ schoolId: 10, roleId: 5, role: { name: 'TEACHER' }, school: { subdomain: 'test' } }],
          role: { name: 'USER' },
        },
      };

      mockPrisma.authToken.findUnique.mockResolvedValue(authToken);
      mockJwt.signAsync.mockResolvedValue('new_access_token');
      mockPrisma.authToken.create.mockResolvedValue({ id: 101 });
      mockPrisma.authIdentity.findFirst.mockResolvedValue({ value: 'test@example.com' });
      mockPrisma.user.findUnique.mockResolvedValue({ id: 1, tokenVersion: 1 });

      const result = await service.refreshToken(oldRawToken);

      expect(result.accessToken).toBe('new_access_token');
      expect(mockPrisma.authToken.delete).toHaveBeenCalledWith({ where: { id: 100 } });
      expect(mockPrisma.authToken.create).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ schoolId: 10, roleId: 5 }),
      }));
    });

    it('should throw UnauthorizedException if token expired', async () => {
      const oldRawToken = 'expired_token';
      const authToken = {
        id: 100,
        expiresAt: new Date(Date.now() - 10000), // Expired
      };

      mockPrisma.authToken.findUnique.mockResolvedValue(authToken);

      await expect(service.refreshToken(oldRawToken)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('handlePostLogin', () => {
    it('should prompt for school selection if multiple exist and no primary', async () => {
      const user = {
        id: 1,
        isActive: true,
        userSchools: [
          { schoolId: 101, roleId: 1, school: { name: 'School A', subdomain: 'a' }, role: { name: 'TEACHER' } },
          { schoolId: 102, roleId: 2, school: { name: 'School B', subdomain: 'b' }, role: { name: 'PRINCIPAL' } },
        ],
      };
      mockJwt.signAsync.mockResolvedValue('mock_token');
      mockPrisma.authToken.create.mockResolvedValue({ id: 100 });
      mockPrisma.user.findUnique.mockResolvedValue({ id: 1, tokenVersion: 1 });

      const result = await (service as any).handlePostLogin(user, 'test@example.com');

      expect(result.requireSchoolSelection).toBe(true);
      expect(result.user.memberships.length).toBe(2);
    });

    it('should auto-select the primary school if it exists', async () => {
      const user = {
        id: 1,
        isActive: true,
        userSchools: [
          { id: 1, schoolId: 101, roleId: 1, isPrimary: true, school: { id: 101, name: 'School A', subdomain: 'a' }, role: { name: 'TEACHER' } },
        ],
        role: { name: 'USER' },
      };
      mockJwt.signAsync.mockResolvedValue('mock_token');
      mockPrisma.authToken.create.mockResolvedValue({ id: 100 });
      mockPrisma.academicYear.findFirst.mockResolvedValue({ id: 2024 });
      mockPrisma.user.findUnique.mockResolvedValue({ id: 1, tokenVersion: 1 });

      const result = await (service as any).handlePostLogin(user, 'test@example.com');

      expect(result.school.id).toBe(101);
      expect(result.accessToken).toBeDefined();
    });
  });
});
