import { Test, TestingModule } from '@nestjs/testing';
import { JwtAuthGuard, SCHOOL_ID_HEADER } from './jwt.guard';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';

describe('JwtAuthGuard', () => {
    let guard: JwtAuthGuard;
    let jwt: JwtService;
    let prisma: PrismaService;

    const mockJwt = {
        verifyAsync: jest.fn(),
    };

    const mockPrisma = {
        user: {
            findUnique: jest.fn(),
        },
    };

    const mockConfig = {
        getOrThrow: jest.fn().mockReturnValue('secret'),
        get: jest.fn(),
    };

    const mockReflector = {
        get: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                JwtAuthGuard,
                { provide: JwtService, useValue: mockJwt },
                { provide: PrismaService, useValue: mockPrisma },
                { provide: ConfigService, useValue: mockConfig },
                { provide: Reflector, useValue: mockReflector },
            ],
        }).compile();

        guard = module.get<JwtAuthGuard>(JwtAuthGuard);
        jwt = module.get<JwtService>(JwtService);
        prisma = module.get<PrismaService>(PrismaService);

        jest.clearAllMocks();
    });

    const createMockContext = (headers: any = {}, cookies: any = {}) => {
        const req = {
            headers,
            cookies,
            user: null,
        };
        return {
            switchToHttp: () => ({
                getRequest: () => req,
            }),
        } as unknown as ExecutionContext;
    };

    it('should be defined', () => {
        expect(guard).toBeDefined();
    });

    describe('canActivate', () => {
        it('should throw UnauthorizedException if no token provided', async () => {
            const context = createMockContext();
            await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
        });

        it('should successfully validate a valid token and attach user to req', async () => {
            const payload = { sub: 1, tokenVersion: 1, schoolId: 101 };
            const context = createMockContext({ authorization: 'Bearer valid_token' });

            mockJwt.verifyAsync.mockResolvedValue(payload);
            mockPrisma.user.findUnique.mockResolvedValue({ tokenVersion: 1 });

            const result = await guard.canActivate(context);

            expect(result).toBe(true);
            const req = context.switchToHttp().getRequest();
            expect(req.user).toEqual(payload);
        });

        it('should fail if token version does not match (revocation check)', async () => {
            const payload = { sub: 1, tokenVersion: 1 };
            const context = createMockContext({ authorization: 'Bearer valid_token' });

            mockJwt.verifyAsync.mockResolvedValue(payload);
            mockPrisma.user.findUnique.mockResolvedValue({ tokenVersion: 2 }); // version mismatch in DB

            await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
        });

        it('should throw ForbiddenException if school context mismatch', async () => {
            const payload = { sub: 1, tokenVersion: 1, schoolId: 101 };
            const context = createMockContext({
                authorization: 'Bearer valid_token',
                [SCHOOL_ID_HEADER]: '102', // Request says 102, token says 101
            });

            mockJwt.verifyAsync.mockResolvedValue(payload);

            await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
        });

        it('should accept school context if it matches', async () => {
            const payload = { sub: 1, tokenVersion: 1, schoolId: 101 };
            const context = createMockContext({
                authorization: 'Bearer valid_token',
                [SCHOOL_ID_HEADER]: '101',
            });

            mockJwt.verifyAsync.mockResolvedValue(payload);
            mockPrisma.user.findUnique.mockResolvedValue({ tokenVersion: 1 });

            const result = await guard.canActivate(context);
            expect(result).toBe(true);
        });

        it('should fail if user is inactive or not found', async () => {
            const payload = { sub: 1, tokenVersion: 1 };
            const context = createMockContext({ authorization: 'Bearer valid_token' });

            mockJwt.verifyAsync.mockResolvedValue(payload);
            mockPrisma.user.findUnique.mockResolvedValue(null);

            await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
        });
    });
});
