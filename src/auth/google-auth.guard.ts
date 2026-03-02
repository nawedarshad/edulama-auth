import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
    getAuthenticateOptions(context: ExecutionContext) {
        const req = context.switchToHttp().getRequest();
        const schoolId = req.headers['x-school-id'] || req.query['schoolId'];

        return {
            state: JSON.stringify({
                schoolId,
                ts: Date.now(),
            }),
            session: false,
            accessType: 'offline',
            prompt: 'consent',
        };
    }
}
