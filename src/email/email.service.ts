import { Injectable, Logger, OnModuleInit, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(
    private readonly config: ConfigService,
    @InjectQueue('email') private emailQueue: Queue,
  ) {
    const host = this.config.getOrThrow<string>('MAIL_HOST');
    const port = this.config.getOrThrow<number>('MAIL_PORT');
    const user = this.config.getOrThrow<string>('MAIL_USER');
    const pass = this.config.getOrThrow<string>('MAIL_PASSWORD');
    const secure = Number(port) === 465;

    this.transporter = nodemailer.createTransport({
      host: host,
      port: Number(port),
      secure: secure,
      auth: {
        user: user,
        pass: pass,
      },
    });
  }

  async onModuleInit() {
    try {
      await this.transporter.verify();
      this.logger.log('SMTP connection verified successfully');
    } catch (error) {
      this.logger.error(`SMTP verification failed: ${error.message}`);
    }
  }

  async sendPasswordResetEmail(
    to: string,
    resetLink: string,
    schoolName: string,
  ): Promise<void> {
    this.validateEmail(to);
    await this.emailQueue.add(
      'sendPasswordReset',
      { to, resetLink, schoolName },
      {
        attempts: 5,
        backoff: { type: 'exponential', delay: 3000 },
        removeOnComplete: true,
      },
    );
    this.logger.log(`Queued password reset email for ${to}`);
  }

  async sendOtp(to: string, otp: string): Promise<void> {
    this.validateEmail(to);
    await this.emailQueue.add(
      'sendOtp',
      { to, otp },
      {
        attempts: 5,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: true,
      },
    );
    this.logger.log(`Queued OTP email for ${to}`);
  }

  private validateEmail(email: string) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || email.length > 255 || !emailRegex.test(email)) {
      throw new BadRequestException('Invalid email address');
    }
  }

  // Actual sending execution (called by EmailProcessor)
  async sendPasswordResetEmailNow(
    to: string,
    resetLink: string,
    schoolName: string,
  ): Promise<void> {
    const from = this.config.get<string>('MAIL_FROM') || 'no-reply@edulama.com';

    try {
      await this.transporter.sendMail({
        from: `"${schoolName}" <${from}>`,
        to,
        subject: 'Reset your password',
        html: buildPasswordResetTemplate(resetLink, schoolName),
      });
    } catch (error) {
      this.logger.error(`Failed to send password reset email to ${to}: ${error.message}`);
      throw error;
    }
  }

  async sendOtpNow(to: string, otp: string): Promise<void> {
    const from = this.config.get<string>('MAIL_FROM') || 'no-reply@edulama.com';

    try {
      await this.transporter.sendMail({
        from: `"EduLama" <${from}>`,
        to,
        subject: `${otp} is your EduLama code`,
        html: buildOtpTemplate(otp),
      });
    } catch (error) {
      this.logger.error(`Failed to send OTP email to ${to}: ${error.message}`);
      throw error;
    }
  }
}


// ─────────────────────────────────────────────
//  OTP EMAIL TEMPLATE
// ─────────────────────────────────────────────
function buildOtpTemplate(otp: string): string {
  const digits = otp.split('');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="color-scheme" content="light dark" />
  <meta name="supported-color-schemes" content="light dark" />
  <title>Your EduLama Code</title>
  <style>
    :root { color-scheme: light dark; }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      background-color: #f0f0f0;
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }

    @media (prefers-color-scheme: dark) {
      body { background-color: #0a0a0a !important; }
      .email-wrapper { background-color: #0a0a0a !important; }
      .card { background-color: #111111 !important; border-color: rgba(255,255,255,0.07) !important; }
      .logo-bg { background-color: #1a1a1a !important; border-color: rgba(255,255,255,0.08) !important; }
      .logo-text { color: #ffffff !important; }
      .brand-name { color: rgba(255,255,255,0.45) !important; }
      .headline { color: #ffffff !important; }
      .subtext { color: rgba(255,255,255,0.38) !important; }
      .digit-box { background-color: #1c1c1c !important; border-color: rgba(255,255,255,0.09) !important; color: #ffffff !important; }
      .divider { border-color: rgba(255,255,255,0.05) !important; }
      .warning-box { background-color: rgba(255,255,255,0.03) !important; border-color: rgba(255,255,255,0.06) !important; }
      .warning-text { color: rgba(255,255,255,0.28) !important; }
      .footer-text { color: rgba(255,255,255,0.18) !important; }
      .expiry-badge { background-color: rgba(255,255,255,0.04) !important; border-color: rgba(255,255,255,0.07) !important; color: rgba(255,255,255,0.35) !important; }
    }
  </style>
</head>
<body>
<table class="email-wrapper" width="100%" cellpadding="0" cellspacing="0" role="presentation"
  style="background-color:#f0f0f0; padding: 48px 16px;">
  <tr>
    <td align="center">

      <!-- Card -->
      <table class="card" width="100%" cellpadding="0" cellspacing="0" role="presentation"
        style="max-width:480px; background-color:#ffffff; border-radius:20px; border:1px solid rgba(0,0,0,0.07); overflow:hidden;">

        <!-- Top accent bar -->
        <tr>
          <td style="height:3px; background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 40%, #a855f7 70%, #6366f1 100%);"></td>
        </tr>

        <!-- Header -->
        <tr>
          <td style="padding: 36px 40px 0 40px; text-align:center;">

            <!-- Logo mark -->
            <table cellpadding="0" cellspacing="0" role="presentation" style="margin: 0 auto 20px auto;">
              <tr>
                <td class="logo-bg" align="center"
                  style="width:44px; height:44px; border-radius:11px; background-color:#f5f5f7; border:1px solid rgba(0,0,0,0.06); vertical-align:middle;">
                  <span class="logo-text" style="font-size:18px; font-weight:700; color:#0a0a0a; letter-spacing:-0.5px; line-height:44px; display:block;">E</span>
                </td>
              </tr>
            </table>

            <p class="brand-name" style="font-size:11px; font-weight:600; letter-spacing:0.18em; text-transform:uppercase; color:rgba(0,0,0,0.35); margin-bottom:16px;">
              EduLama
            </p>

            <h1 class="headline" style="font-size:26px; font-weight:600; letter-spacing:-0.035em; color:#0a0a0a; line-height:1.15; margin-bottom:10px;">
              Your sign-in code
            </h1>
            <p class="subtext" style="font-size:14px; color:rgba(0,0,0,0.42); line-height:1.55; letter-spacing:-0.01em;">
              Use the code below to complete<br/>your sign in to EduLama.
            </p>

          </td>
        </tr>

        <!-- OTP Digits -->
        <tr>
          <td style="padding: 32px 40px 28px 40px; text-align:center;">
            <table cellpadding="0" cellspacing="0" role="presentation" style="margin: 0 auto;">
              <tr>
                ${digits.map((digit, i) => `
                <td style="padding: 0 ${i === 2 ? '10px' : '4px'} 0 ${i === 3 ? '10px' : '4px'};">
                  <table class="digit-box" cellpadding="0" cellspacing="0" role="presentation"
                    style="background-color:#f7f7f8; border:1px solid rgba(0,0,0,0.08); border-radius:10px; width:52px; height:60px;">
                    <tr>
                      <td align="center" valign="middle"
                        style="font-size:28px; font-weight:600; letter-spacing:-0.02em; color:#0a0a0a; font-variant-numeric:tabular-nums;">
                        ${digit}
                      </td>
                    </tr>
                  </table>
                </td>
                `).join('')}
              </tr>
            </table>

            <!-- Expiry badge -->
            <div style="margin-top: 18px; display: inline-block;">
              <table cellpadding="0" cellspacing="0" role="presentation" style="margin: 0 auto;">
                <tr>
                  <td class="expiry-badge"
                    style="padding: 5px 14px; border-radius:20px; background-color:rgba(0,0,0,0.04); border:1px solid rgba(0,0,0,0.07);">
                    <p class="warning-text" style="font-size:11px; font-weight:600; letter-spacing:0.04em; color:rgba(0,0,0,0.32); white-space:nowrap;">
                      Expires in 5 minutes
                    </p>
                  </td>
                </tr>
              </table>
            </div>
          </td>
        </tr>

        <!-- Divider -->
        <tr>
          <td style="padding: 0 40px;">
            <hr class="divider" style="border:none; border-top:1px solid rgba(0,0,0,0.06); margin:0;" />
          </td>
        </tr>

        <!-- Warning -->
        <tr>
          <td style="padding: 22px 40px 30px 40px;">
            <table class="warning-box" cellpadding="0" cellspacing="0" role="presentation" width="100%"
              style="background-color:rgba(0,0,0,0.025); border:1px solid rgba(0,0,0,0.055); border-radius:10px;">
              <tr>
                <td style="padding: 14px 18px;">
                  <p class="warning-text" style="font-size:12px; line-height:1.6; color:rgba(0,0,0,0.38); letter-spacing:-0.005em;">
                    <strong style="font-weight:600;">Didn't request this?</strong> Your account is safe. Someone may have entered your email by mistake. You can safely ignore this message — the code will expire shortly.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding: 0 40px 32px 40px; text-align:center;">
            <p class="footer-text" style="font-size:11px; color:rgba(0,0,0,0.22); letter-spacing:0.01em; line-height:1.7;">
              EduLama OS · School management, reimagined<br/>
              <a href="https://edulama.com" style="color:inherit; text-decoration:none;">edulama.com</a>
            </p>
          </td>
        </tr>

      </table>
      <!-- /Card -->

    </td>
  </tr>
</table>
</body>
</html>
  `.trim();
}


// ─────────────────────────────────────────────
//  PASSWORD RESET EMAIL TEMPLATE
// ─────────────────────────────────────────────
function buildPasswordResetTemplate(resetLink: string, schoolName: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="color-scheme" content="light dark" />
  <meta name="supported-color-schemes" content="light dark" />
  <title>Reset your password</title>
  <style>
    :root { color-scheme: light dark; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background-color: #f0f0f0;
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    @media (prefers-color-scheme: dark) {
      body { background-color: #0a0a0a !important; }
      .email-wrapper { background-color: #0a0a0a !important; }
      .card { background-color: #111111 !important; border-color: rgba(255,255,255,0.07) !important; }
      .logo-bg { background-color: #1a1a1a !important; border-color: rgba(255,255,255,0.08) !important; }
      .logo-text { color: #ffffff !important; }
      .brand-name { color: rgba(255,255,255,0.45) !important; }
      .headline { color: #ffffff !important; }
      .subtext { color: rgba(255,255,255,0.38) !important; }
      .cta-btn { background-color: #ffffff !important; color: #000000 !important; }
      .divider { border-color: rgba(255,255,255,0.05) !important; }
      .warning-box { background-color: rgba(255,255,255,0.03) !important; border-color: rgba(255,255,255,0.06) !important; }
      .warning-text { color: rgba(255,255,255,0.28) !important; }
      .footer-text { color: rgba(255,255,255,0.18) !important; }
    }
  </style>
</head>
<body>
<table class="email-wrapper" width="100%" cellpadding="0" cellspacing="0" role="presentation"
  style="background-color:#f0f0f0; padding: 48px 16px;">
  <tr>
    <td align="center">

      <table class="card" width="100%" cellpadding="0" cellspacing="0" role="presentation"
        style="max-width:480px; background-color:#ffffff; border-radius:20px; border:1px solid rgba(0,0,0,0.07); overflow:hidden;">

        <tr>
          <td style="height:3px; background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 40%, #a855f7 70%, #6366f1 100%);"></td>
        </tr>

        <tr>
          <td style="padding: 36px 40px 0 40px; text-align:center;">
            <table cellpadding="0" cellspacing="0" role="presentation" style="margin: 0 auto 20px auto;">
              <tr>
                <td class="logo-bg" align="center"
                  style="width:44px; height:44px; border-radius:11px; background-color:#f5f5f7; border:1px solid rgba(0,0,0,0.06); vertical-align:middle;">
                  <span class="logo-text" style="font-size:18px; font-weight:700; color:#0a0a0a; letter-spacing:-0.5px; line-height:44px; display:block;">E</span>
                </td>
              </tr>
            </table>

            <p class="brand-name" style="font-size:11px; font-weight:600; letter-spacing:0.18em; text-transform:uppercase; color:rgba(0,0,0,0.35); margin-bottom:16px;">
              ${schoolName}
            </p>

            <h1 class="headline" style="font-size:26px; font-weight:600; letter-spacing:-0.035em; color:#0a0a0a; line-height:1.15; margin-bottom:10px;">
              Reset your password
            </h1>
            <p class="subtext" style="font-size:14px; color:rgba(0,0,0,0.42); line-height:1.55; letter-spacing:-0.01em;">
              We received a request to reset the password<br/>for your EduLama account.
            </p>
          </td>
        </tr>

        <!-- CTA -->
        <tr>
          <td style="padding: 32px 40px 28px 40px; text-align:center;">
            <table cellpadding="0" cellspacing="0" role="presentation" style="margin: 0 auto;">
              <tr>
                <td>
                  <a href="${resetLink}" class="cta-btn"
                    style="display:inline-block; background-color:#0a0a0a; color:#ffffff; text-decoration:none; font-size:14px; font-weight:600; letter-spacing:-0.01em; padding:13px 32px; border-radius:10px;">
                    Reset Password →
                  </a>
                </td>
              </tr>
            </table>
            <p class="subtext" style="font-size:11.5px; color:rgba(0,0,0,0.28); margin-top:14px; letter-spacing:0.01em;">
              Link expires in 15 minutes
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding: 0 40px;">
            <hr class="divider" style="border:none; border-top:1px solid rgba(0,0,0,0.06); margin:0;" />
          </td>
        </tr>

        <tr>
          <td style="padding: 22px 40px 30px 40px;">
            <table class="warning-box" cellpadding="0" cellspacing="0" role="presentation" width="100%"
              style="background-color:rgba(0,0,0,0.025); border:1px solid rgba(0,0,0,0.055); border-radius:10px;">
              <tr>
                <td style="padding: 14px 18px;">
                  <p class="warning-text" style="font-size:12px; line-height:1.6; color:rgba(0,0,0,0.38); letter-spacing:-0.005em;">
                    <strong style="font-weight:600;">Didn't request this?</strong> Your account remains secure. Simply ignore this email and your password will not be changed.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="padding: 0 40px 32px 40px; text-align:center;">
            <p class="footer-text" style="font-size:11px; color:rgba(0,0,0,0.22); letter-spacing:0.01em; line-height:1.7;">
              EduLama OS · School management, reimagined<br/>
              <a href="https://edulama.com" style="color:inherit; text-decoration:none;">edulama.com</a>
            </p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>
  `.trim();
}