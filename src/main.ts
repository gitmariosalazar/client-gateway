import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as morgan from 'morgan';
import { Logger } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { environments } from './settings/environments/environments';
import { RcpCustomExceptionFilter } from './shared/errors/exception/GlobalExceptionHandler';

async function bootstrap() {
  const logger: Logger = new Logger('Main');
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.use(morgan('dev'));
  const config = new DocumentBuilder()
    .setTitle('API Gateway Microservices')
    .setBasePath('api')
    .setDescription('API - Clean Architecture with NestJS & TypeScript')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();

  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory, {
    customSiteTitle: 'API Documentation',
    customCssUrl:
      'https://mariosalazar-styles-swagger-ui.vercel.app/css/swagger-ui.css',
  });
  app.useGlobalFilters(new RcpCustomExceptionFilter());
  await app.startAllMicroservices();
  await app.init();
  await app.listen(environments.serverPort);
  console.log(`Hello World`);
  logger.log(
    `🚀🎉 This API Gateway is running on: http://127.0.0.1:${environments.serverPort}`,
  );
}
void bootstrap();
