import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from '../src/app.module';
import * as fs from 'fs';

async function generate() {
  const app = await NestFactory.create(AppModule, { logger: false });

  const config = new DocumentBuilder()
    .setTitle('UICP Internal / Public API')
    .setDescription('Unified Identity Control Plane API Documentation')
    .setVersion(process.env.VERSION || '1.0.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);

  fs.writeFileSync('./swagger-spec.json', JSON.stringify(document, null, 2));
  console.log('OpenAPI spec generated at ./swagger-spec.json');

  await app.close();
  process.exit(0);
}

generate().catch(err => {
  console.error('Failed to generate OpenAPI spec', err);
  process.exit(1);
});
