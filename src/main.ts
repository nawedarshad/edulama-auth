import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import morgan from 'morgan';
import { AppLogger } from './logger/logger';
import helmet from 'helmet';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: AppLogger, // <-- THIS ENABLES WINSTON
  });

  // SECURITY HEADERS
  app.use(helmet());

  // INPUT VALIDATION configuration
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true, // properties not in DTO are stripped
    forbidNonWhitelisted: true, // throw error if unknown properties
    transform: true, // auto-transform payloads to DTO instances
  }));

  app.enableCors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      const allowed = [
        'http://localhost:3000',
        'http://192.168.1.5:3000',
        'http://167.71.229.252:3000',
        'http://localhost:5002',
        'http://localhost:5002',
        'http://school.edulama.com:3000',
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

  // HTTP REQUEST LOGGER
  app.use(morgan(':method :url :status - :response-time ms'));

  await app.listen(process.env.PORT || 4000, '0.0.0.0');
}
bootstrap();
