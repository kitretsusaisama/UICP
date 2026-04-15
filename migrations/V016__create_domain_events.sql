-- V016: Create domain_events table
-- Note: global_seq is AUTO_INCREMENT but id is the PRIMARY KEY.
-- MySQL requires AUTO_INCREMENT columns to be a key; UNIQUE KEY satisfies this.
CREATE TABLE domain_events (
  id                      BINARY(16)    NOT NULL,
  aggregate_id            VARCHAR(36)   NOT NULL,
  aggregate_type          VARCHAR(64)   NOT NULL,
  event_type              VARCHAR(128)  NOT NULL,
  global_seq              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  aggregate_seq           INT UNSIGNED  NOT NULL,
  payload_enc             MEDIUMBLOB    NOT NULL,
  payload_enc_kid         VARCHAR(36)   NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_global_seq (global_seq),
  UNIQUE KEY uq_aggregate_seq (aggregate_id, aggregate_seq),
  KEY idx_global_seq (global_seq),
  KEY idx_aggregate_id (aggregate_id, aggregate_seq ASC)
);
