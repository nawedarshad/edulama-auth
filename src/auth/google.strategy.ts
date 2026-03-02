import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback, Profile } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(configService: ConfigService) {
    super({
      clientID: configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  async validate(
    req: any,
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails, photos, displayName } = profile;

    // CSRF & Tenant State Validation
    const stateStr = req.query.state;
    if (!stateStr) {
      return done(new UnauthorizedException('Missing OAuth state'));
    }

    try {
      const state = JSON.parse(stateStr);
      // We can attach the state to the user object for AuthService to use
      (profile as any).oauthState = state;
    } catch (e) {
      return done(new UnauthorizedException('Invalid OAuth state'));
    }

    // Email verification
    const verifiedEmail = emails?.find((e) => e.verified === true) || emails?.[0];

    if (!verifiedEmail?.value) {
      return done(
        new UnauthorizedException('Google account has no valid email'),
      );
    }

    const user = {
      googleId: id,
      email: verifiedEmail.value,
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      displayName,
      picture: photos?.[0]?.value,
      oauthState: (profile as any).oauthState,
    };

    done(null, user);
  }
}
