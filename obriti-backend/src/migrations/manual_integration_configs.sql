-- Manual SQL command to create integration_configs table
-- Run this in your MySQL database

CREATE TABLE IF NOT EXISTS integration_configs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    integration_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    config_data TEXT NULL,
    status VARCHAR(50) DEFAULT 'not_configured',
    last_tested DATETIME NULL,
    last_sync DATETIME NULL,
    metadata TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by INT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_integration_type (integration_type)
);

-- Verify table creation
DESCRIBE integration_configs;
