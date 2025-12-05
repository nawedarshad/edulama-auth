import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CORS FIX FOR WEB + MOBILE
  app.enableCors({
    origin: (origin, callback) => {
      // Allow mobile apps (origin = null)
      if (!origin) return callback(null, true);

      // Allow all local and production domains
      const allowed = [
        'http://localhost:3000',
        'http://192.168.1.5:3000',
        'http://167.71.229.252:3000',
      ];

      if (allowed.includes(origin)) {
        return callback(null, true);
      }

      return callback(null, false);
    },
    credentials: true,
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: '*',
  });

  // MOST IMPORTANT FOR VPS !! 🔥
  await app.listen(process.env.PORT || 4000, '0.0.0.0');
}
bootstrap();
