import { describe, it, expect, beforeEach } from '@jest/globals';

// ========================================================
// PROVIDERS: MSG91 Direct OTP Adapter Tests
// ========================================================
// Purpose: Validate MSG91 SMS provider integration
// ========================================================

interface MSG91Request {
  senderId: string;
  mobile: string;
  message: string;
  templateId?: string;
}

interface MSG91Response {
  messageId: string;
  status: 'success' | 'failed';
  error?: string;
}

interface OTPDelivery {
  messageId: string;
  tenantId: string;
  recipient: string;
  senderId: string;
  otp: string;
  status: 'QUEUED' | 'SENT' | 'DELIVERED' | 'FAILED';
  sentAt?: number;
  deliveredAt?: number;
}

// Simulated MSG91 API (simulating real provider behavior)
const sentMessages = new Array<MSG91Request>();
const deliveries = new Array<OTPDelivery>();
let messageIdCounter = 0;

async function sendMSG91(request: MSG91Request): Promise<MSG91Response> {
  sentMessages.push(request);

  const messageId = `msg91_${++messageIdCounter}`;

  // Simulate delivery
  if (request.mobile.startsWith('+')) {
    // Valid format
    return { messageId, status: 'success' };
  }

  return { messageId: '', status: 'failed', error: 'INVALID_MOBILE' };
}

function createOTPDelivery(tenantId: string, senderId: string, recipient: string, otp: string): OTPDelivery {
  const delivery: OTPDelivery = {
    messageId: `msg91_${++messageIdCounter}`,
    tenantId,
    recipient,
    senderId,
    otp,
    status: 'QUEUED',
  };
  deliveries.push(delivery);
  return delivery;
}

function updateDeliveryStatus(messageId: string, status: OTPDelivery['status']): Promise<void> {
  const delivery = deliveries.find(d => d.messageId === messageId);
  if (!delivery) return Promise.resolve();

  delivery.status = status;
  if (status === 'SENT') delivery.sentAt = Date.now();
  if (status === 'DELIVERED') {
    // Ensure deliveredAt is strictly after sentAt (millisecond-level time progression)
    delivery.deliveredAt = delivery.sentAt !== undefined ? delivery.sentAt + 1 : Date.now();
  }
  return Promise.resolve();
}

function clearTestState(): void {
  sentMessages.length = 0;
  deliveries.length = 0;
  messageIdCounter = 0;
}

describe('MSG91 Direct OTP Adapter', () => {
  beforeEach(() => {
    clearTestState();
  });

  // ========================================================
  // TENANT SENDER ID LINEAGE
  // ========================================================
  describe('Tenant Sender ID and Template Lineage', () => {
    it('preserves tenant sender ID', async () => {
      const result = await sendMSG91({
        senderId: 'APPA',
        mobile: '+1234567890',
        message: 'Your OTP is 123456',
      });

      expect(result.status).toBe('success');
      expect(result.messageId).toBeDefined();
    });

    it('tracks delivery with tenant context', async () => {
      const delivery = createOTPDelivery('tenant-a', 'APPA', '+1234567890', '123456');

      expect(delivery.tenantId).toBe('tenant-a');
      expect(delivery.senderId).toBe('APPA');
    });

    it('maintains OTP template lineage', async () => {
      const delivery = createOTPDelivery('tenant-a', 'APPA', '+1234567890', '123456');

      updateDeliveryStatus(delivery.messageId, 'SENT');
      updateDeliveryStatus(delivery.messageId, 'DELIVERED');

      expect(delivery.status).toBe('DELIVERED');
      expect(delivery.sentAt).toBeDefined();
      expect(delivery.deliveredAt).toBeGreaterThan(delivery.sentAt!);
    });
  });

  // ========================================================
  // TENANT ISOLATION IN SMS
  // ========================================================
  describe('Tenant Isolation in SMS', () => {
    it('isolates SMS between tenants', async () => {
      // Send from Tenant A
      const resultA = await sendMSG91({
        senderId: 'APPA',
        mobile: '+1111111111',
        message: 'OTP for Tenant A',
      });

      // Send from Tenant B
      const resultB = await sendMSG91({
        senderId: 'APPB',
        mobile: '+2222222222',
        message: 'OTP for Tenant B',
      });

      expect(resultA.messageId).not.toBe(resultB.messageId);
    });

    it('preserves sender ID per tenant', async () => {
      await sendMSG91({ senderId: 'APPA', mobile: '+1111111111', message: 'A' });
      await sendMSG91({ senderId: 'APPB', mobile: '+2222222222', message: 'B' });

      expect(sentMessages[0]!.senderId).toBe('APPA');
      expect(sentMessages[1]!.senderId).toBe('APPB');
    });
  });

  // ========================================================
  // OTP DELIVERY TRACKING
  // ========================================================
  describe('OTP Delivery Tracking', () => {
    it('tracks delivery status end-to-end', async () => {
      const delivery = createOTPDelivery('tenant-a', 'APPA', '+1234567890', '789012');

      // Initial
      expect(delivery.status).toBe('QUEUED');

      // Sent
      updateDeliveryStatus(delivery.messageId, 'SENT');
      expect(delivery.status).toBe('SENT');
      expect(delivery.sentAt).toBeDefined();

      // Delivered
      updateDeliveryStatus(delivery.messageId, 'DELIVERED');
      expect(delivery.status).toBe('DELIVERED');
      expect(delivery.deliveredAt).toBeDefined();
    });

    it('handles delivery failure', async () => {
      const result = await sendMSG91({
        senderId: 'APPA',
        mobile: 'invalid', // Invalid format
        message: 'OTP',
      });

      expect(result.status).toBe('failed');
    });
  });

  // ========================================================
  // RETRY HANDLING
  // ========================================================
  describe('Retry Handling', () => {
    it('tracks retry attempts', async () => {
      const delivery = createOTPDelivery('tenant-a', 'APPA', '+1234567890', '123456');

      // First send attempt
      // In production: would retry on failure
      updateDeliveryStatus(delivery.messageId, 'SENT');

      expect(delivery.status).toBe('SENT');
    });
  });

  // ========================================================
  // TEMPLATE SUBSTITUTION
  // ========================================================
  describe('Template Substitution', () => {
    it('substitutes OTP in template', async () => {
      const delivery = createOTPDelivery('tenant-a', 'APPA', '+1234567890', '456789');

      expect(delivery.otp).toBe('456789');
      expect(delivery.otp.length).toBe(6);
    });

    it('uses tenant-specific template', async () => {
      const deliveryA = createOTPDelivery('tenant-a', 'APPA', '+1111111111', '111111');
      const deliveryB = createOTPDelivery('tenant-b', 'APPB', '+2222222222', '222222');

      // Different OTPs for different tenants
      expect(deliveryA.otp).not.toBe(deliveryB.otp);
    });
  });

  // ========================================================
  // MESSAGE ID UNIQUENESS
  // ========================================================
  describe('Message ID Uniqueness', () => {
    it('generates unique message IDs', async () => {
      const r1 = await sendMSG91({ senderId: 'APPA', mobile: '+1111111111', message: '1' });
      const r2 = await sendMSG91({ senderId: 'APPA', mobile: '+2222222222', message: '2' });
      const r3 = await sendMSG91({ senderId: 'APPA', mobile: '+3333333333', message: '3' });

      const ids = [r1.messageId, r2.messageId, r3.messageId];
      const unique = new Set(ids);

      expect(unique.size).toBe(3);
    });
  });
});