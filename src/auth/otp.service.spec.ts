import { Test, TestingModule } from '@nestjs/testing';
import { OtpService } from './otp.service';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { REDIS_CLIENT } from '../redis/redis.module';
import { AuthType } from '@prisma/client';
import { BadRequestException } from '@nestjs/common';
import * as argon2 from 'argon2';

jest.mock('argon2');

describe('OtpService', () => {
    let service: OtpService;
    let prisma: PrismaService;
    let emailService: EmailService;
    let redis: any;

    const mockPrisma = {
        otpVerification: {
            upsert: jest.fn(),
            findUnique: jest.fn(),
            update: jest.fn(),
            delete: jest.fn(),
        },
    };

    const mockEmailService = {
        sendOtp: jest.fn(),
    };

    const mockRedis = {
        get: jest.fn(),
        set: jest.fn(),
        incr: jest.fn(),
        expire: jest.fn(),
        del: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                OtpService,
                { provide: PrismaService, useValue: mockPrisma },
                { provide: EmailService, useValue: mockEmailService },
                { provide: REDIS_CLIENT, useValue: mockRedis },
            ],
        }).compile();

        service = module.get<OtpService>(OtpService);
        prisma = module.get<PrismaService>(PrismaService);
        emailService = module.get<EmailService>(EmailService);
        redis = module.get(REDIS_CLIENT);

        jest.clearAllMocks();
    });

    describe('generateAndSendOtp', () => {
        it('should generate and send OTP successfully', async () => {
            const identifier = 'test@example.com';
            const type = AuthType.EMAIL;
            const meta = { ip: '127.0.0.1', userAgent: 'test-agent' };

            redis.get.mockResolvedValue(null);
            redis.incr.mockResolvedValue(1);
            (argon2.hash as jest.Mock).mockResolvedValue('hashed_otp');

            const result = await service.generateAndSendOtp(identifier, type, meta);

            expect(result).toEqual({ message: 'OTP sent successfully' });
            expect(redis.get).toHaveBeenCalledWith(`lockout:otp:email:test@example.com`);
            expect(redis.incr).toHaveBeenCalledWith(`rate:otp:ip:127.0.0.1`);
            expect(prisma.otpVerification.upsert).toHaveBeenCalledWith(expect.objectContaining({
                where: { type_value: { type, value: 'test@example.com' } },
                create: expect.objectContaining({ value: 'test@example.com', otpHash: 'hashed_otp' }),
            }));
            expect(emailService.sendOtp).toHaveBeenCalledWith('test@example.com', expect.any(String));
        });

        it('should throw BadRequestException if identifier is locked out', async () => {
            redis.get.mockResolvedValue('true');

            await expect(service.generateAndSendOtp('test@example.com')).rejects.toThrow(BadRequestException);
            expect(prisma.otpVerification.upsert).not.toHaveBeenCalled();
        });

        it('should throw BadRequestException if IP is throttled', async () => {
            redis.get.mockResolvedValue(null);
            redis.incr.mockResolvedValue(11);

            await expect(service.generateAndSendOtp('test@example.com', AuthType.EMAIL, { ip: '127.0.0.1' }))
                .rejects.toThrow(BadRequestException);
        });
    });

    describe('verifyOtp', () => {
        it('should verify OTP successfully and cleanup', async () => {
            const identifier = 'test@example.com';
            const code = '123456';
            const record = {
                id: 1,
                otpHash: 'hashed_otp',
                expiresAt: new Date(Date.now() + 10000),
                attempts: 0,
            };

            redis.get.mockResolvedValue(null);
            mockPrisma.otpVerification.findUnique.mockResolvedValue(record);
            (argon2.verify as jest.Mock).mockResolvedValue(true);

            const result = await service.verifyOtp(identifier, code);

            expect(result).toBe(true);
            expect(prisma.otpVerification.delete).toHaveBeenCalledWith({ where: { id: 1 } });
            expect(redis.del).toHaveBeenCalledWith(`failed:otp:email:test@example.com`);
        });

        it('should throw if identifier is locked out', async () => {
            redis.get.mockResolvedValue('true');
            await expect(service.verifyOtp('test@example.com', '123456')).rejects.toThrow(BadRequestException);
        });

        it('should throw if record not found', async () => {
            redis.get.mockResolvedValue(null);
            mockPrisma.otpVerification.findUnique.mockResolvedValue(null);

            await expect(service.verifyOtp('test@example.com', '123456')).rejects.toThrow(BadRequestException);
        });

        it('should throw and increment attempts on invalid code', async () => {
            const identifier = 'test@example.com';
            const record = {
                id: 1,
                otpHash: 'hashed_otp',
                expiresAt: new Date(Date.now() + 10000),
                attempts: 0,
            };

            redis.get.mockResolvedValue(null);
            mockPrisma.otpVerification.findUnique.mockResolvedValue(record);
            (argon2.verify as jest.Mock).mockResolvedValue(false);
            redis.incr.mockResolvedValue(1);

            await expect(service.verifyOtp(identifier, 'wrong')).rejects.toThrow(BadRequestException);
            expect(prisma.otpVerification.update).toHaveBeenCalledWith({
                where: { id: 1 },
                data: { attempts: { increment: 1 } },
            });
            expect(redis.incr).toHaveBeenCalledWith(`failed:otp:email:test@example.com`);
        });

        it('should trigger lockout after too many failures', async () => {
            const identifier = 'test@example.com';
            const record = {
                id: 1,
                otpHash: 'hashed_otp',
                expiresAt: new Date(Date.now() + 10000),
                attempts: 4,
            };

            redis.get.mockResolvedValue(null);
            mockPrisma.otpVerification.findUnique.mockResolvedValue(record);
            (argon2.verify as jest.Mock).mockResolvedValue(false);
            redis.incr.mockResolvedValue(10); // 10th failure total

            await expect(service.verifyOtp(identifier, 'wrong')).rejects.toThrow(BadRequestException);
            expect(redis.set).toHaveBeenCalledWith(expect.stringContaining('lockout:otp'), 'true', 'EX', 300);
        });
    });
});
