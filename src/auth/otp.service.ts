import { Injectable, BadRequestException, Logger, Inject } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { AuthType } from '@prisma/client';
import { REDIS_CLIENT } from '../redis/redis.module';
import Redis from 'ioredis';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) { }

  /**
   * Generates a 6-digit OTP, hashes it, and stores it in OtpVerification
   */
  async generateAndSendOtp(
    identifier: string,
    type: AuthType = AuthType.EMAIL,
    meta?: { ip?: string; userAgent?: string },
  ) {
    const normalized = identifier.trim().toLowerCase();
    const typeLower = type.toLowerCase();

    // 1. Check for identifier lockout (Brute Force Protection)
    const lockoutKey = `lockout:otp:${typeLower}:${normalized}`;
    if (await this.redis.get(lockoutKey)) {
      throw new BadRequestException('Invalid or expired OTP'); // Generic message
    }

    // 2. IP-Based Throttling (Spam Protection)
    if (meta?.ip) {
      const ipKey = `rate:otp:ip:${meta.ip}`;
      const count = await this.redis.incr(ipKey);
      if (count === 1) await this.redis.expire(ipKey, 3600); // 1 hour window
      if (count > 10) {
        this.logger.warn(`Potential OTP spam from IP: ${meta.ip}`);
        throw new BadRequestException('Too many requests. Please try later.');
      }
    }

    // 3. Cryptographically secure 6-digit OTP
    const otp = crypto.randomInt(100000, 1000000).toString();
    const otpHash = await argon2.hash(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // 4. Atomic Upsert (Prevents Race Condition)
    await this.prisma.otpVerification.upsert({
      where: { type_value: { type, value: normalized } },
      update: {
        otpHash,
        expiresAt,
        attempts: 0,
        ip: meta?.ip,
        userAgent: meta?.userAgent,
      },
      create: {
        type,
        value: normalized,
        otpHash,
        expiresAt,
        ip: meta?.ip,
        userAgent: meta?.userAgent,
      },
    });

    if (type === 'EMAIL') {
      await this.emailService.sendOtp(normalized, otp);
    } else if (type === 'PHONE') {
      this.logger.warn(`SMS OTP requested for ${normalized} but provider not configured`);
    }

    return { message: 'OTP sent successfully' };
  }

  /**
   * Verifies the OTP. Returns true if valid, throws if invalid or expired.
   */
  async verifyOtp(
    identifier: string,
    code: string,
    type: AuthType = AuthType.EMAIL,
  ): Promise<boolean> {
    const normalized = identifier.trim().toLowerCase();
    const typeLower = type.toLowerCase();

    // 1. Check for identifier lockout
    const lockoutKey = `lockout:otp:${typeLower}:${normalized}`;
    if (await this.redis.get(lockoutKey)) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    const record = await this.prisma.otpVerification.findUnique({
      where: { type_value: { type, value: normalized } },
    });

    const genericError = new BadRequestException('Invalid or expired OTP');

    if (!record || record.expiresAt < new Date() || record.attempts >= 5) {
      if (record && record.attempts >= 5) {
        // Trigger lockout if they hit the limit
        await this.redis.set(lockoutKey, 'true', 'EX', 300);
      }
      throw genericError;
    }

    const isValid = await argon2.verify(record.otpHash, code);

    if (!isValid) {
      await this.prisma.otpVerification.update({
        where: { id: record.id },
        data: { attempts: { increment: 1 } },
      });

      // Brute Force Tracking
      const failedKey = `failed:otp:${typeLower}:${normalized}`;
      const failedCount = await this.redis.incr(failedKey);
      if (failedCount === 1) await this.redis.expire(failedKey, 300);

      if (failedCount >= 10) {
        await this.redis.set(lockoutKey, 'true', 'EX', 300);
        await this.redis.del(failedKey);
        this.logger.warn(`Identifier locked out: ${normalized}`);
        throw genericError;
      }

      throw genericError;
    }

    // Success: Clean up
    await Promise.all([
      this.prisma.otpVerification.delete({ where: { id: record.id } }),
      this.redis.del(`failed:otp:${typeLower}:${normalized}`),
    ]);

    return true;
  }
}
