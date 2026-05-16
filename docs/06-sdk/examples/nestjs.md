# NestJS Example

## Metadata
```yaml
title: NestJS SDK Example
domain: sdk/examples
owner: platform-team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - backend-sdk.md
  - initialization.md
  - middleware.md
related-docs:
  - examples/express.md
  - middleware.md
related-queues:
  - notification-queue
related-services:
  - user-service
  - auth-service
```

---

## Overview

This guide demonstrates integrating the UICP backend SDK into a NestJS application. NestJS's modular architecture aligns well with the SDK's service-oriented design.

## Installation

```bash
npm install @uicp/server
```

## SDK Module

Create a reusable SDK module:

```typescript
// uicp/uicp.module.ts
import { Module, Global } from '@nestjs/common';
import { UICPBackendClient } from '@uicp/server';

export const UICP_CLIENT = 'UICP_CLIENT';

@Global()
@Module({
  providers: [
    {
      provide: UICP_CLIENT,
      useFactory: () => {
        return new UICPBackendClient({
          secretKey: process.env.UICP_SECRET_KEY!,
          tenantId: process.env.UICP_TENANT_ID!,
          baseUrl: process.env.UICP_BASE_URL
        });
      }
    }
  ],
  exports: [UICP_CLIENT]
})
export class UICPModule {}
```

## Authentication Guard

Implement a JWT authentication guard:

```typescript
// auth/jwt-auth.guard.ts
import { Injectable, CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UICP_CLIENT } from '../uicp/uicp.module';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(UICP_CLIENT) private client: UICPBackendClient
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) return false;

    try {
      const token = authHeader.replace('Bearer ', '');
      const user = await this.client.auth.verify(token);
      request.user = user;
      return true;
    } catch {
      return false;
    }
  }
}
```

## User Service Integration

Use the SDK in NestJS services:

```typescript
// users/users.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { UICP_CLIENT } from '../uicp/uicp.module';

@Injectable()
export class UsersService {
  constructor(@Inject(UICP_CLIENT) private client: UICPBackendClient) {}

  async findAll() {
    return this.client.users.list();
  }

  async findOne(id: string) {
    return this.client.users.get(id);
  }

  async create(userData: CreateUserDto) {
    return this.client.users.create(userData);
  }

  async update(id: string, userData: UpdateUserDto) {
    return this.client.users.update(id, userData);
  }

  async delete(id: string) {
    return this.client.users.delete(id);
  }
}
```

## Queue Consumer

Process messages from UICP queues:

```typescript
// notifications/notifications.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { UICP_CLIENT } from '../uicp/uicp.module';

@Injectable()
export class NotificationsService {
  constructor(@Inject(UICP_CLIENT) private client: UICPBackendClient) {}

  async onModuleInit() {
    // Subscribe to notification queue
    await this.client.queues.subscribe('notification-email', async (message) => {
      await this.sendEmail(message);
    });
  }

  private async sendEmail(message: EmailMessage) {
    // Email sending logic
    console.log('Sending email to:', message.to);
  }
}
```

## Controller Example

A complete controller with authentication:

```typescript
// users/users.controller.ts
import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  async findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }
}
```

## Module Configuration

Wire everything together in the application module:

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { UICPModule } from './uicp/uicp.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    UICPModule,
    UsersModule,
    AuthModule
  ]
})
export class AppModule {}
```

## Error Handling

Add exception filters for UICP errors:

```typescript
// filters/uicp-exception.filter.ts
import { ExceptionFilter, Catch } from '@nestjs/common';
import { UICPError } from '@uicp/server';

@Catch(UICPError)
export class UICPExceptionFilter implements ExceptionFilter {
  catch(exception: UICPError) {
    return {
      statusCode: exception.status,
      message: exception.message,
      code: exception.code
    };
  }
}
```

---

## Related Documents

- `examples/express.md` - Express.js example
- `backend-sdk.md` - Full backend SDK documentation