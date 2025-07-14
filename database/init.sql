-- Enterprise Security Platform Database Schema
-- PostgreSQL initialization script

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS security_platform;
USE security_platform;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    permissions JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security incidents table
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    source_ip INET,
    target_ip INET,
    threat_type VARCHAR(100),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    assigned_to UUID REFERENCES users(id),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Threat alerts table
CREATE TABLE threat_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    signature VARCHAR(500),
    description TEXT,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    incident_id UUID REFERENCES security_incidents(id),
    raw_data JSONB,
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Incident timeline table
CREATE TABLE incident_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN ('user', 'system', 'automation')),
    actor_id UUID REFERENCES users(id),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Network assets table
CREATE TABLE network_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255),
    ip_address INET UNIQUE NOT NULL,
    mac_address MACADDR,
    asset_type VARCHAR(50) NOT NULL,
    operating_system VARCHAR(100),
    criticality VARCHAR(20) DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    location VARCHAR(100),
    owner VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'quarantined')),
    last_seen TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Blocked IPs table
CREATE TABLE blocked_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL,
    reason TEXT NOT NULL,
    blocked_by UUID REFERENCES users(id),
    block_type VARCHAR(20) DEFAULT 'manual' CHECK (block_type IN ('manual', 'automatic', 'temporary')),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance assessments table
CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework VARCHAR(50) NOT NULL,
    assessment_date DATE NOT NULL,
    overall_score DECIMAL(5,4) CHECK (overall_score >= 0 AND overall_score <= 1),
    total_controls INTEGER NOT NULL,
    passed_controls INTEGER NOT NULL,
    failed_controls INTEGER NOT NULL,
    pending_controls INTEGER NOT NULL,
    assessor UUID REFERENCES users(id),
    report_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compliance controls table
CREATE TABLE compliance_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    framework VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('compliant', 'non_compliant', 'partial', 'not_applicable')),
    score DECIMAL(5,4) CHECK (score >= 0 AND score <= 1),
    evidence TEXT[],
    recommendations TEXT[],
    last_tested TIMESTAMP WITH TIME ZONE,
    next_test_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id),
    resource_type VARCHAR(100),
    resource_id UUID,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat intelligence table
CREATE TABLE threat_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_type VARCHAR(50) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),
    indicator_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(100),
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    source VARCHAR(100) NOT NULL,
    description TEXT,
    tags TEXT[],
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(indicator_type, indicator_value, source)
);

-- System configurations table
CREATE TABLE system_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_security_incidents_status ON security_incidents(status);
CREATE INDEX idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX idx_security_incidents_created_at ON security_incidents(created_at);
CREATE INDEX idx_threat_alerts_severity ON threat_alerts(severity);
CREATE INDEX idx_threat_alerts_source_ip ON threat_alerts(source_ip);
CREATE INDEX idx_threat_alerts_created_at ON threat_alerts(created_at);
CREATE INDEX idx_incident_timeline_incident_id ON incident_timeline(incident_id);
CREATE INDEX idx_network_assets_ip_address ON network_assets(ip_address);
CREATE INDEX idx_blocked_ips_ip_address ON blocked_ips(ip_address);
CREATE INDEX idx_blocked_ips_is_active ON blocked_ips(is_active);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_threat_intelligence_indicator ON threat_intelligence(indicator_type, indicator_value);
CREATE INDEX idx_threat_intelligence_is_active ON threat_intelligence(is_active);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_security_incidents_updated_at BEFORE UPDATE ON security_incidents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_threat_alerts_updated_at BEFORE UPDATE ON threat_alerts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_network_assets_updated_at BEFORE UPDATE ON network_assets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_blocked_ips_updated_at BEFORE UPDATE ON blocked_ips FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_threat_intelligence_updated_at BEFORE UPDATE ON threat_intelligence FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_system_configurations_updated_at BEFORE UPDATE ON system_configurations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user
INSERT INTO users (username, email, password_hash, role, permissions) VALUES 
('admin', 'admin@enterprise.com', crypt('admin', gen_salt('bf')), 'admin', '["read", "write", "admin"]');

-- Insert default system configurations
INSERT INTO system_configurations (config_key, config_value, description) VALUES
('platform_version', '"1.0.0"', 'Current platform version'),
('max_failed_logins', '5', 'Maximum failed login attempts before account lockout'),
('session_timeout_minutes', '60', 'Session timeout in minutes'),
('enable_mfa', 'true', 'Enable multi-factor authentication'),
('threat_score_threshold', '70', 'Minimum threat score for automatic blocking'),
('compliance_frameworks', '["SOC2", "ISO27001"]', 'Enabled compliance frameworks');

-- Create views for common queries
CREATE VIEW active_incidents AS
SELECT 
    i.*,
    u.username as assigned_to_username,
    COUNT(a.id) as alert_count
FROM security_incidents i
LEFT JOIN users u ON i.assigned_to = u.id
LEFT JOIN threat_alerts a ON i.id = a.incident_id
WHERE i.status IN ('open', 'investigating', 'contained')
GROUP BY i.id, u.username;

CREATE VIEW recent_threats AS
SELECT 
    alert_type,
    severity,
    source_ip,
    destination_ip,
    COUNT(*) as count,
    MAX(created_at) as last_seen
FROM threat_alerts
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY alert_type, severity, source_ip, destination_ip
ORDER BY count DESC, last_seen DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
