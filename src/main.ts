import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import morgan from 'morgan';
import { AppLogger } from './logger/logger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: AppLogger, // <-- THIS ENABLES WINSTON
  });

  app.enableCors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      const allowed = [
        'http://localhost:3000',
        'http://192.168.1.5:3000',
        'http://167.71.229.252:3000',
        'http://localhost:5002',
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
