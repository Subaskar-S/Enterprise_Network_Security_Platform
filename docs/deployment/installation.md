# Enterprise Network Security Platform - Installation Guide

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 8 cores (Intel Xeon or AMD EPYC recommended)
- **Memory**: 32GB RAM
- **Storage**: 500GB SSD (NVMe recommended)
- **Network**: 1Gbps network interface
- **OS**: Ubuntu 20.04 LTS, CentOS 8, or RHEL 8

#### Recommended Requirements
- **CPU**: 16+ cores with hyperthreading
- **Memory**: 64GB+ RAM
- **Storage**: 2TB+ NVMe SSD with RAID 10
- **Network**: 10Gbps network interface
- **OS**: Ubuntu 22.04 LTS (latest)

#### Production Requirements
- **CPU**: 32+ cores across multiple nodes
- **Memory**: 128GB+ RAM per node
- **Storage**: 10TB+ distributed storage
- **Network**: 25Gbps+ with redundancy
- **High Availability**: 3+ node cluster

### Software Dependencies

#### Required Software
```bash
# Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Kubernetes (for Istio deployment)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm

# Istio (optional, for service mesh)
curl -L https://istio.io/downloadIstio | sh -
sudo mv istio-*/bin/istioctl /usr/local/bin/
```

#### Optional Tools
```bash
# Monitoring and debugging tools
sudo apt-get install htop iotop nethogs tcpdump wireshark-common
```

## Quick Start Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/enterprise-network-security-platform.git
cd enterprise-network-security-platform
```

### 2. Configure Environment
```bash
# Copy and edit environment configuration
cp .env.example .env
nano .env

# Update the following critical settings:
# - ELASTIC_PASSWORD: Strong password for Elasticsearch
# - POSTGRES_PASSWORD: Strong password for PostgreSQL
# - REDIS_PASSWORD: Strong password for Redis
# - SLACK_BOT_TOKEN: Your Slack bot token
# - PFSENSE_URL: Your pfSense firewall URL
```

### 3. Run Automated Deployment
```bash
# Make deployment script executable
chmod +x scripts/deployment/deploy.sh

# Run deployment
./scripts/deployment/deploy.sh
```

### 4. Verify Installation
```bash
# Check service status
docker-compose ps

# Run health checks
./scripts/monitoring/health-check.sh

# Access dashboards
# Kibana: http://localhost:5601
# Grafana: http://localhost:3000 (admin/changeme)
# Security Dashboard: http://localhost:3001
```

## Manual Installation

### Step 1: Infrastructure Setup

#### 1.1 Create Directory Structure
```bash
mkdir -p {logs,data,ssl,backups}
mkdir -p data/{elasticsearch,redis,postgres,grafana,prometheus}
chmod -R 755 logs data ssl backups
```

#### 1.2 Generate SSL Certificates
```bash
# Self-signed certificates for development
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/server.key \
    -out ssl/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=security.enterprise.com"

# For production, use certificates from a trusted CA
```

#### 1.3 Configure System Limits
```bash
# Increase system limits for Elasticsearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure Docker daemon
sudo mkdir -p /etc/docker
cat << EOF | sudo tee /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
sudo systemctl restart docker
```

### Step 2: Core Services Deployment

#### 2.1 Start Elasticsearch and Redis
```bash
# Start core data services
docker-compose up -d elasticsearch redis

# Wait for Elasticsearch to be ready
timeout=300
while [ $timeout -gt 0 ]; do
    if curl -s -f http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        echo "Elasticsearch is ready"
        break
    fi
    sleep 5
    timeout=$((timeout - 5))
done
```

#### 2.2 Configure Elasticsearch
```bash
# Set up index templates
curl -X PUT "localhost:9200/_index_template/security-logs" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["security-*"],
    "template": {
      "settings": {
        "number_of_shards": 3,
        "number_of_replicas": 1,
        "refresh_interval": "5s"
      },
      "mappings": {
        "properties": {
          "@timestamp": {"type": "date"},
          "source_ip": {"type": "ip"},
          "dest_ip": {"type": "ip"},
          "threat_type": {"type": "keyword"},
          "risk_score": {"type": "integer"}
        }
      }
    }
  }'

# Create initial indices
curl -X PUT "localhost:9200/security-alerts-$(date +%Y.%m.%d)"
curl -X PUT "localhost:9200/security-incidents-$(date +%Y.%m)"
```

### Step 3: ELK Stack Deployment

#### 3.1 Start Logstash and Kibana
```bash
# Start log processing and visualization
docker-compose up -d logstash kibana

# Wait for Kibana to be ready
timeout=300
while [ $timeout -gt 0 ]; do
    if curl -s -f http://localhost:5601/api/status > /dev/null 2>&1; then
        echo "Kibana is ready"
        break
    fi
    sleep 5
    timeout=$((timeout - 5))
done
```

#### 3.2 Import Kibana Dashboards
```bash
# Import security dashboards
for dashboard in elk/kibana/dashboards/*.ndjson; do
    if [ -f "$dashboard" ]; then
        curl -X POST "localhost:5601/api/saved_objects/_import" \
            -H "kbn-xsrf: true" \
            -H "Content-Type: application/json" \
            --form file=@"$dashboard"
    fi
done
```

### Step 4: Security Services

#### 4.1 Deploy Suricata IDS/IPS
```bash
# Start Suricata with custom rules
docker-compose up -d suricata

# Verify Suricata is processing traffic
docker logs suricata | grep "Suricata-Main"
```

#### 4.2 Start AI Threat Detection
```bash
# Build and start AI services
docker-compose build ai-threat-detection
docker-compose up -d ai-threat-detection

# Check AI service logs
docker logs ai-threat-detection
```

#### 4.3 Deploy Incident Response
```bash
# Start incident response engine
docker-compose up -d incident-response

# Verify incident response service
curl -f http://localhost:8001/health
```

### Step 5: Monitoring and Visualization

#### 5.1 Start Monitoring Stack
```bash
# Deploy Prometheus and Grafana
docker-compose up -d prometheus grafana

# Start log shippers
docker-compose up -d filebeat metricbeat
```

#### 5.2 Configure Grafana
```bash
# Wait for Grafana to start
sleep 30

# Import dashboards
for dashboard in monitoring/grafana/dashboards/*.json; do
    if [ -f "$dashboard" ]; then
        curl -X POST "http://admin:changeme@localhost:3000/api/dashboards/db" \
            -H "Content-Type: application/json" \
            -d @"$dashboard"
    fi
done
```

### Step 6: Web Services

#### 6.1 Deploy API and Dashboard
```bash
# Start web services
docker-compose up -d api-gateway security-dashboard nginx

# Verify web services
curl -f http://localhost:8000/health
curl -f http://localhost:3001
```

## Istio Service Mesh Installation (Optional)

### Prerequisites
- Kubernetes cluster (minikube, kind, or cloud provider)
- kubectl configured to access the cluster
- Istio CLI (istioctl) installed

### Installation Steps

#### 1. Install Istio
```bash
# Install Istio with default configuration
istioctl install --set values.defaultRevision=default -y

# Enable Istio injection for default namespace
kubectl label namespace default istio-injection=enabled
```

#### 2. Deploy Istio Configurations
```bash
# Apply security policies
kubectl apply -f istio/policies/

# Deploy gateways
kubectl apply -f istio/gateways/

# Configure virtual services
kubectl apply -f istio/virtualservices/
```

#### 3. Verify Istio Installation
```bash
# Check Istio components
kubectl get pods -n istio-system

# Verify mTLS is working
istioctl authn tls-check
```

## Configuration

### Environment Variables
```bash
# Core configuration
DEPLOYMENT_ENV=production
PLATFORM_VERSION=1.0.0

# Security settings
ELASTIC_PASSWORD=your_secure_password
KIBANA_PASSWORD=your_secure_password
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_password

# External integrations
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
PFSENSE_URL=https://firewall.enterprise.com
PFSENSE_USERNAME=admin
PFSENSE_PASSWORD=your_pfsense_password

# Threat intelligence
THREAT_INTEL_API_KEY=your_threat_intel_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Monitoring
GRAFANA_ADMIN_PASSWORD=your_grafana_password
PROMETHEUS_RETENTION=30d
```

### Network Configuration
```bash
# Configure firewall rules
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 5601/tcp    # Kibana
sudo ufw allow 3000/tcp    # Grafana
sudo ufw allow 9200/tcp    # Elasticsearch (internal only)
sudo ufw enable
```

### SSL/TLS Configuration
```bash
# For production, configure proper SSL certificates
# Update nginx configuration with your certificates
cp your-certificate.crt ssl/certs/
cp your-private-key.key ssl/certs/
```

## Post-Installation Tasks

### 1. Security Hardening
```bash
# Change default passwords
./scripts/security/change-passwords.sh

# Configure SSL certificates
./scripts/security/setup-ssl.sh

# Enable authentication
./scripts/security/enable-auth.sh
```

### 2. Data Initialization
```bash
# Load threat intelligence data
python3 scripts/data/load-threat-intel.py

# Create default users and roles
python3 scripts/setup/create-users.py

# Import sample dashboards
./scripts/setup/import-dashboards.sh
```

### 3. Integration Setup
```bash
# Configure Slack integration
./scripts/integrations/setup-slack.sh

# Setup JIRA integration
./scripts/integrations/setup-jira.sh

# Configure pfSense API
./scripts/integrations/setup-pfsense.sh
```

### 4. Monitoring Setup
```bash
# Configure alerting rules
./scripts/monitoring/setup-alerts.sh

# Setup backup procedures
./scripts/backup/setup-backup.sh

# Configure log rotation
./scripts/maintenance/setup-logrotate.sh
```

## Troubleshooting

### Common Issues

#### Elasticsearch Won't Start
```bash
# Check system limits
sysctl vm.max_map_count

# Check disk space
df -h

# Check logs
docker logs elasticsearch
```

#### Kibana Connection Issues
```bash
# Verify Elasticsearch is running
curl http://localhost:9200/_cluster/health

# Check Kibana configuration
docker exec kibana cat /usr/share/kibana/config/kibana.yml

# Check logs
docker logs kibana
```

#### Suricata Not Detecting Traffic
```bash
# Check network interface
docker exec suricata ip addr show

# Verify rules are loaded
docker exec suricata suricata-update list-sources

# Check logs
docker logs suricata
```

### Performance Tuning

#### Elasticsearch Optimization
```bash
# Increase heap size (50% of available RAM)
echo "ES_JAVA_OPTS=-Xms16g -Xmx16g" >> .env

# Optimize for SSDs
curl -X PUT "localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent": {"indices.store.throttle.type": "none"}}'
```

#### System Optimization
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Backup and Recovery

### Backup Procedures
```bash
# Automated backup script
./scripts/backup/backup-all.sh

# Manual backup
docker exec elasticsearch curl -X PUT "localhost:9200/_snapshot/backup_repo" \
  -H "Content-Type: application/json" \
  -d '{"type": "fs", "settings": {"location": "/usr/share/elasticsearch/backups"}}'
```

### Recovery Procedures
```bash
# Restore from backup
./scripts/backup/restore-all.sh

# Verify data integrity
./scripts/monitoring/verify-data.sh
```

## Support and Maintenance

### Regular Maintenance Tasks
- Update threat intelligence feeds (daily)
- Review and tune detection rules (weekly)
- Update system patches (monthly)
- Review and rotate logs (monthly)
- Test backup and recovery procedures (quarterly)

### Getting Help
- Documentation: `docs/` directory
- Logs: `logs/` directory
- Health checks: `./scripts/monitoring/health-check.sh`
- Support: Create an issue in the GitHub repository
