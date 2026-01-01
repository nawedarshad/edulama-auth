import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);
    private transporter: nodemailer.Transporter;

    constructor(private readonly config: ConfigService) {
        const host = this.config.get<string>('MAIL_HOST');
        const port = this.config.get<number>('MAIL_PORT');
        const user = this.config.get<string>('MAIL_USER');

        this.logger.log(`Initializing EmailService with: Host=${host}, Port=${port}, User=${user}`);

        const pass = this.config.get<string>('MAIL_PASSWORD');
        if (!pass) {
            this.logger.error('CRITICAL: MAIL_PASSWORD is empty or undefined!');
        } else {
            this.logger.log(`MAIL_PASSWORD loaded. Length: ${pass.length} characters.`);
        }

        if (!host || !user) {
            this.logger.error('Missing MAIL_HOST or MAIL_USER in environment variables');
        }

        this.transporter = nodemailer.createTransport({
            host: host,
            port: Number(port) || 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: user,
                pass: this.config.get<string>('MAIL_PASSWORD'),
            },
        });
    }

    async sendPasswordResetEmail(to: string, resetLink: string, schoolName: string): Promise<void> {
        const from = this.config.get<string>('MAIL_FROM') || 'no-reply@edulama.com';
        this.logger.log(`Attempting to send email to [${to}] from [${from}]`);

        try {
            const info = await this.transporter.sendMail({
                from: `"${schoolName}" <${from}>`,
                to,
                subject: 'Password Reset Request',
                html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Password Reset Request</h2>
            <p>You requested to reset your password for <strong>${schoolName}</strong>.</p>
            <p>Click the link below to reset your password:</p>
            <p>
              <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                Reset Password
              </a>
            </p>
            <p><small>If you did not request this, please ignore this email.</small></p>
            <p><small>Link expires in 15 minutes.</small></p>
          </div>
        `,
            });
            this.logger.log(`Password reset email sent successfully to ${to}. MessageId: ${info.messageId}`);
        } catch (error) {
            this.logger.error(`Failed to send email to ${to}`, error);
            // We log the detailed error object to see SMTP responses
            console.error('SMTP Error Details:', error);
        }
    }
}
