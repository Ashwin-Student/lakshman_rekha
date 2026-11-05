CREATE DATABASE IF NOT EXISTS lakshman_rekha_db;
USE lakshman_rekha_db;

CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    payload TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    reason VARCHAR(255),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
