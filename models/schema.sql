-- Threat Intelligence Cache Database Schema
-- This schema demonstrates proper database design with indexes and constraints

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS threat_intel_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE threat_intel_db;

-- Drop table if exists (for development/testing)
DROP TABLE IF EXISTS threat_intel_cache;

-- Create threat intelligence cache table
CREATE TABLE threat_intel_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL COMMENT 'IPv4 or IPv6 address',
    threat_data JSON NOT NULL COMMENT 'Aggregated threat intelligence data',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'When the cache entry was created',
    expires_at DATETIME NOT NULL COMMENT 'When the cache entry expires',

    -- Indexes for performance
    INDEX idx_ip_address (ip_address),
    INDEX idx_expires_at (expires_at),
    INDEX idx_ip_expires (ip_address, expires_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Caches threat intelligence data to reduce API calls';

-- Create index for cleanup queries
CREATE INDEX idx_cleanup ON threat_intel_cache(expires_at);
