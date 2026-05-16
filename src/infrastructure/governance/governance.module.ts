import { Module } from '@nestjs/common';
import { GovernanceGuard } from './guards/governance.guard';

@Module({
  providers: [GovernanceGuard],
  exports: [GovernanceGuard],
})
export class GovernanceModule {}
