import { Injectable } from '@nestjs/common';

@Injectable()
export class MetricsService {
  increment(_name: string, _labels?: Record<string, string>): void {}
  histogram(_name: string, _value: number, _labels?: Record<string, string>): void {}
}
