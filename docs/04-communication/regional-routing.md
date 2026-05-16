# Regional Routing

## Metadata
```yaml
title: Regional Routing
domain: communication
owner: Platform Team
criticality: MEDIUM
runtime-impact: HIGH
security-impact: LOW
queue-impact: LOW
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-selection.md
  - provider-runtime.md
related-docs:
  - communication-overview.md
  - provider-health.md
related-queues:
  - regional-sync
related-services:
  - RegionalRouter
  - GeoLocator
  - ProviderRegionMapper
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - region_detected
  - region_routing
  - region_matched
  - region_fallback
related-threat-models:
  - Region spoofing
  - GDPR compliance
```

---

## Overview

Regional Routing optimizes message delivery by selecting providers and routes based on recipient geographic location. This ensures lower latency, better deliverability, and compliance with regional regulations.

---

## Region Detection

### Detection Methods

```typescript
interface RegionDetection {
  // Priority order
  method: 'explicit' | 'domain_tld' | 'geoip' | 'tenant_config';

  // Detected region
  region: string;
  confidence: number;
  detectedAt: Date;
}

function detectRegion(message: OutboundMessage): RegionDetection {
  // 1. Explicit region in message
  if (message.region) {
    return { method: 'explicit', region: message.region, confidence: 1.0 };
  }

  // 2. Domain TLD detection
  const tld = extractTLD(message.recipients[0]);
  const region = tldToRegionMap[tld];
  if (region) {
    return { method: 'domain_tld', region, confidence: 0.9 };
  }

  // 3. GeoIP lookup
  const geo = geoip.lookup(getRecipientIP(message));
  return { method: 'geoip', region: geo?.region, confidence: 0.7 };

  // 4. Default to tenant config
  return { method: 'tenant_config', region: message.tenant.defaultRegion };
}
```

### TLD to Region Mapping

| TLD | Region | Provider Preference |
|-----|--------|---------------------|
| .in | India | Msg91 |
| .uk | EU-West | SES |
| .de | EU-Central | SES |
| .fr | EU-West | SES |
| .jp | APAC | Resend |
| .au | APAC | SES |
| .com | Global | Default chain |

---

## Provider Region Coverage

### Email Provider Regions

| Provider | Regions | Notes |
|----------|---------|-------|
| SES | Global | Primary, best coverage |
| Resend | Global | Secondary |
| Maileroo | EU, US | Limited |

### SMS Provider Regions

| Provider | Coverage | Notes |
|----------|----------|-------|
| Msg91 | India | Primary |

---

## Routing Logic

### Region-Based Selection

```typescript
async function selectProviderForRegion(
  message: OutboundMessage
): Promise<string> {
  const region = detectRegion(message);

  // Get providers available in region
  const available = await getRegionProviders(region);

  // Score and rank
  const scored = await Promise.all(
    available.map(async provider => ({
      provider,
      score: await calculateRegionalScore(provider, region)
    }))
  );

  // Select highest scoring
  scored.sort((a, b) => b.score - a.score);
  return scored[0].provider;
}

function calculateRegionalScore(provider: string, region: string): number {
  let score = provider.baseScore;

  // Regional bonus
  if (provider.regions.includes(region)) {
    score += 20;
  }

  // Latency penalty
  const avgLatency = provider.getAverageLatency(region);
  score -= Math.floor(avgLatency / 100);

  // Cost adjustment
  score -= provider.getRegionalCost(region);

  return score;
}
```

---

## Compliance Routing

### Data Residency

```typescript
interface ComplianceConfig {
  tenantId: string;
  allowedRegions: string[];
  prohibitedRegions: string[];
  data ResidencyRequirement: 'local' | 'any' | 'explicit';
}

function validateRegionalCompliance(
  message: OutboundMessage,
  config: ComplianceConfig
): boolean {
  // Check prohibited
  if (config.prohibitedRegions.includes(message.region)) {
    return false;
  }

  // Check allowed
  if (config.allowedRegions.length > 0) {
    return config.allowedRegions.includes(message.region);
  }

  return true;
}
```

### GDPR Compliance

- EU data stays in EU region
- Cross-border transfers logged
- Data processing agreements required

---

## Latency Optimization

### Latency by Region

| Route | Avg Latency | Target |
|-------|-------------|--------|
| US → US | 50ms | < 100ms |
| EU → EU | 80ms | < 150ms |
| IN → IN | 150ms | < 300ms |
| US → IN | 400ms | < 600ms |

### Optimization Strategies

1. Regional provider selection
2. Connection pool per region
3. DNS-based routing
4. CDN for template delivery

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-selection.md`
- `04-communication/provider-health.md`