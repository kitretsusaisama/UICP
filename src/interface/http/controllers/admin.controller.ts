import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Admin')
@Controller('v1/admin')
export class AdminController {
  @Get('health')
  health() {
    return {
      data: {
        ok: true,
        surface: 'admin',
      },
    };
  }
}
