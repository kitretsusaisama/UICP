import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class PaginationDto {
  @ApiPropertyOptional({
    description: 'Number of items to return (1-100)',
    default: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;

  @ApiPropertyOptional({
    description: 'Cursor for pagination (base64 encoded)',
  })
  @IsOptional()
  cursor?: string;
}

export class PaginatedResponse<T> {
  data!: T[];
  pagination!: {
    nextCursor?: string;
    hasMore: boolean;
    total?: number;
  };
}

export interface CursorPaginationOptions {
  limit: number;
  cursor?: string;
  encodeCursor: (item: any) => string;
  decodeCursor: (cursor: string) => any;
}