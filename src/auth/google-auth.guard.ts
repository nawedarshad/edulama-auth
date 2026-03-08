import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
    getAuthenticateOptions(context: ExecutionContext) {
        const req = context.switchToHttp().getRequest();
        const schoolId = req.headers['x-school-id'] || req.query['schoolId'];
        // Allow the frontend/mobile to tag the platform so the callback can handle it
        const platform = req.query['platform'] || 'web';
        const mobileRedirect = req.query['mobileRedirect'] || '';

        return {
            state: JSON.stringify({
                schoolId,
                ts: Date.now(),
                platform,
                mobileRedirect,
            }),
            session: false,
            accessType: 'offline',
            prompt: 'consent',
        };
    }
}
