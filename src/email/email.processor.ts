import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { EmailService } from './email.service';
import { Logger } from '@nestjs/common';

@Processor('email')
export class EmailProcessor extends WorkerHost {
    private readonly logger = new Logger(EmailProcessor.name);

    constructor(private readonly emailService: EmailService) {
        super();
    }

    async process(job: Job<any, any, string>): Promise<any> {
        this.logger.log(`Processing email job ${job.id} of type ${job.name}`);

        try {
            switch (job.name) {
                case 'sendOtp':
                    await this.emailService.sendOtpNow(job.data.to, job.data.otp);
                    break;
                case 'sendPasswordReset':
                    await this.emailService.sendPasswordResetEmailNow(
                        job.data.to,
                        job.data.resetLink,
                        job.data.schoolName,
                    );
                    break;
                default:
                    this.logger.warn(`Unknown job type: ${job.name}`);
            }
        } catch (error) {
            this.logger.error(`Failed to process email job ${job.id}: ${error.message}`);
            throw error; // BullMQ will handle retries if configured
        }
    }
}
