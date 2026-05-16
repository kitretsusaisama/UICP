import { ExtensionExecutorService, ExtensionExecutionRequest } from './extension.executor';
import { randomUUID } from 'crypto';

/**
 * Unit tests for ExtensionExecutorService.
 *
 * Covers:
 *   - execute with valid request
 *   - execute with missing optional actorId
 */

const makeExecutionRequest = (overrides: Partial<ExtensionExecutionRequest> = {}): ExtensionExecutionRequest => ({
  tenantId: randomUUID(),
  extensionKey: 'test-extension',
  commandKey: 'test-command',
  payload: { key: 'value' },
  actorId: randomUUID(),
  ...overrides,
});

describe('ExtensionExecutorService', () => {
  let service: ExtensionExecutorService;

  beforeEach(() => {
    service = new ExtensionExecutorService();
  });

  describe('execute', () => {
    it('should execute a valid extension request', async () => {
      const request = makeExecutionRequest();

      const result = await service.execute(request);

      expect(result.accepted).toBe(true);
      expect(result.tenantId).toBe(request.tenantId);
      expect(result.extensionKey).toBe(request.extensionKey);
      expect(result.commandKey).toBe(request.commandKey);
    });

    it('should return null result for successful execution', async () => {
      const request = makeExecutionRequest();

      const result = await service.execute(request);

      expect(result.result).toBeNull();
    });

    it('should handle request without actorId', async () => {
      const request = makeExecutionRequest({ actorId: undefined });

      const result = await service.execute(request);

      expect(result.accepted).toBe(true);
      expect(result.tenantId).toBe(request.tenantId);
    });

    it('should handle complex payload', async () => {
      const complexPayload = {
        user: { id: '123', name: 'Test User' },
        items: [{ id: 1 }, { id: 2 }],
        metadata: { timestamp: new Date().toISOString() },
      };
      const request = makeExecutionRequest({ payload: complexPayload });

      const result = await service.execute(request);

      expect(result.accepted).toBe(true);
    });

    it('should preserve all request properties in response', async () => {
      const request = makeExecutionRequest({
        extensionKey: 'custom-ext',
        commandKey: 'custom-cmd',
      });

      const result = await service.execute(request);

      expect(result.extensionKey).toBe('custom-ext');
      expect(result.commandKey).toBe('custom-cmd');
    });
  });
});