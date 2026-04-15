-- V001: Create schema_versions table (migration tracking)
CREATE TABLE IF NOT EXISTS schema_versions (
  version                 INT UNSIGNED  NOT NULL,
  description             VARCHAR(255)  NOT NULL,
  checksum                CHAR(64)      NOT NULL,
  applied_at              DATETIME(3)   NOT NULL,
  applied_by              VARCHAR(128)  NOT NULL,
  duration_ms             INT UNSIGNED  NOT NULL,
  PRIMARY KEY (version)
);
