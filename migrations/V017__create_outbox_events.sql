-- V017: Create outbox_events table
CREATE TABLE outbox_events (
  id                      BINARY(16)    NOT NULL,
  event_type              VARCHAR(128)  NOT NULL,
  payload_json            JSON          NOT NULL,
  status                  ENUM('PENDING','PUBLISHED','FAILED','DLQ') NOT NULL DEFAULT 'PENDING',
  attempts                TINYINT UNSIGNED NOT NULL DEFAULT 0,
  last_error              TEXT,
  published_at            DATETIME(3),
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_status_created (status, created_at)
);
