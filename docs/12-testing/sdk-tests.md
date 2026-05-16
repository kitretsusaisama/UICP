# SDK Tests

## Metadata
```yaml
title: SDK Tests
domain: sdk
owner: Developer Experience Team
criticality: MEDIUM
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: NONE
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: per-release
last-reviewed: 2026-05-16
depends-on:
  - src/sdk/typescript/uicp-client.ts
  - src/sdk/python/uicp_client.py
  - src/sdk/go/client.go
related-docs:
  - docs/08-api/sdk-documentation.md
  - docs/02-architecture/client-libraries.md
related-queues: NONE
related-services:
  - TypeScriptSDK
  - PythonSDK
  - GoSDK
```

---

## Overview

SDK tests validate that client libraries provide correct functionality, proper error handling, and seamless integration with the UICP platform. These tests ensure developers can successfully integrate using any supported language.

---

## Test Coverage

### TypeScript SDK

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Client initialization | Create client with valid config | Client ready for requests |
| Authentication | Set API key on client | Requests authenticated |
| Provider listing | Call listProviders() | Returns provider array |
| Error handling | Call with invalid credentials | Typed error thrown |

### Python SDK

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Context manager | Use client in with statement | Connection managed |
| Async operations | Call async methods | Proper await behavior |
| Type hints | Use with mypy | No type errors |
| Exception mapping | Catch SDK exceptions | Correct exception type |

### Go SDK

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Client options | Configure with custom options | Options applied |
| Retry configuration | Set retry count and backoff | Retries execute correctly |
| Context cancellation | Cancel request mid-flight | Request stops |
| Connection pooling | Make concurrent requests | Pool functions properly |

### Cross-Language Consistency

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Same operation | Create provider in TS/Python/Go | Same API call |
| Error parity | Invalid request in all SDKs | Consistent error format |
| Timeout behavior | Request timeout in all SDKs | Consistent timeout |

---

## Test Implementation

```typescript
// TypeScript SDK Tests
describe('TypeScript SDK', () => {
  const client = new UICPClient({ apiKey: 'test-key' });

  it('should initialize with configuration', () => {
    expect(client.config.apiKey).toBe('test-key');
    expect(client.config.baseUrl).toBeDefined();
  });

  it('should list providers', async () => {
    const providers = await client.providers.list();

    expect(providers).toBeInstanceOf(Array);
    expect(providers[0]).toHaveProperty('id');
    expect(providers[0]).toHaveProperty('name');
  });

  it('should throw typed errors', async () => {
    const client = new UICPClient({ apiKey: 'invalid-key' });

    await expect(client.providers.list())
      .rejects.toThrow(AuthenticationError);
  });
});

# Python SDK Tests
def test_client_initialization():
    client = UICPClient(api_key="test-key")
    assert client.api_key == "test-key"

@pytest.mark.asyncio
async def test_async_provider_creation():
    client = UICPClient(api_key="test-key")
    provider = await client.providers.create({
        "name": "test-provider",
        "type": "aws"
    })
    assert provider.id is not None

// Go SDK Tests
func TestClientOptions(t *testing.T) {
    client := NewClient(
        WithRetryCount(5),
        WithTimeout(30 * time.Second),
    )

    assert.Equal(t, 5, client.retryCount)
}

func TestContextCancellation(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel()

    err := client.Providers.List(ctx)
    assert.ErrorIs(t, err, context.Canceled)
}
```

---

## Test Environment

- Real API backend (test environment)
- Mock provider responses
- Isolated test API keys
- Network condition simulation

---

## Coverage Targets

- Unit tests: > 90% code coverage
- Integration tests: All public methods
- Sample applications: Run without modification
- Documentation examples: All tested