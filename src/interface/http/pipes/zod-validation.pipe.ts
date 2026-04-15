import { ArgumentMetadata, Injectable, PipeTransform } from '@nestjs/common';
import { ZodSchema, ZodError } from 'zod';
import { SchemaValidationException } from '../../../domain/exceptions/schema-validation.exception';

/**
 * ZodValidationPipe — validates and transforms incoming data using a Zod schema.
 *
 * Implements: Req 1.6
 *
 * Usage:
 * ```ts
 * @Body(new ZodValidationPipe(mySchema))
 * body: MyDto
 * ```
 *
 * On validation failure throws `SchemaValidationException` (HTTP 400) with
 * structured field-path errors.
 */
@Injectable()
export class ZodValidationPipe implements PipeTransform {
  constructor(private readonly schema: ZodSchema) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  transform(value: unknown, _metadata: ArgumentMetadata): unknown {
    const result = this.schema.safeParse(value);

    if (!result.success) {
      const errors = this.formatErrors(result.error);
      throw new SchemaValidationException(errors);
    }

    return result.data;
  }

  private formatErrors(error: ZodError): Array<{ path: string; message: string }> {
    return error.errors.map((issue) => ({
      path: issue.path.join('.') || '(root)',
      message: issue.message,
    }));
  }
}
