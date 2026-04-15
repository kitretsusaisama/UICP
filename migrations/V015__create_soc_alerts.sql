-- V015: Create soc_alerts table
CREATE TABLE soc_alerts (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16),
  ip_hash                 BINARY(32),
  threat_score            DECIMAL(4,3)  NOT NULL,
  kill_chain_stage        ENUM('RECONNAISSANCE','INITIAL_ACCESS','CREDENTIAL_ACCESS','LATERAL_MOVEMENT','ACCOUNT_TAKEOVER'),
  signals_json            JSON          NOT NULL,
  response_actions_json   JSON          NOT NULL,
  workflow                ENUM('open','acknowledged','resolved','false_positive') NOT NULL DEFAULT 'open',
  acknowledged_by         BINARY(16),
  acknowledged_at         DATETIME(3),
  resolved_by             BINARY(16),
  resolved_at             DATETIME(3),
  checksum                BINARY(32)    NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tenant_workflow (tenant_id, workflow, created_at),
  KEY idx_tenant_user (tenant_id, user_id, created_at),
  KEY idx_threat_score (tenant_id, threat_score DESC)
);
