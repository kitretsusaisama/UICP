import { Controller, Get } from '@nestjs/common';
import { VersionService } from '../../../../src/application/services/platform-ops/version.service';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('Operations')
@Controller('v1/version')
export class VersionController {
  constructor(private readonly versionService: VersionService) {}

  @Get()
  @ApiOperation({ summary: 'MNC-grade version traceability and drift detection' })
  getVersion() {
    return this.versionService.getVersion();
  }
}
