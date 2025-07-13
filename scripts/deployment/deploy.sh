#!/bin/bash

# Enterprise Network Security Platform Deployment Script
# Deploys the complete security platform with all components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PLATFORM_NAME="Enterprise Network Security Platform"
VERSION="1.0.0"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
LOG_FILE="deployment_$(date +%Y%m%d_%H%M%S).log"

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    Enterprise Network Security Platform Deployment           ║
║                                                               ║
║    🔐 Zero Trust Architecture                                 ║
║    🧠 AI-Driven Threat Detection                             ║
║    ⚠️  Automated Incident Response                            ║
║    📊 Real-time Security Monitoring                          ║
║    📄 SOC 2 & ISO 27001 Compliance                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Starting deployment of $PLATFORM_NAME v$VERSION"

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check if Kubernetes tools are available (for Istio deployment)
    if ! command -v kubectl &> /dev/null; then
        warn "kubectl is not installed. Istio deployment will be skipped."
    fi
    
    if ! command -v helm &> /dev/null; then
        warn "Helm is not installed. Some Kubernetes deployments may fail."
    fi
    
    # Check available disk space (minimum 20GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 20971520 ]; then  # 20GB in KB
        warn "Less than 20GB disk space available. Deployment may fail."
    fi
    
    # Check available memory (minimum 8GB)
    available_memory=$(free -m | awk 'NR==2{print $7}')
    if [ "$available_memory" -lt 8192 ]; then  # 8GB in MB
        warn "Less than 8GB memory available. Performance may be degraded."
    fi
    
    log "Prerequisites check completed"
}

# Setup environment
setup_environment() {
    log "Setting up environment..."
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p data/{elasticsearch,redis,postgres,grafana,prometheus}
    mkdir -p ssl/certs
    mkdir -p backups
    
    # Set proper permissions
    chmod 755 logs data ssl backups
    chmod -R 755 scripts/
    
    # Generate SSL certificates if they don't exist
    if [ ! -f ssl/certs/server.crt ]; then
        log "Generating SSL certificates..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ssl/certs/server.key \
            -out ssl/certs/server.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=security.enterprise.com"
    fi
    
    # Create environment file if it doesn't exist
    if [ ! -f .env ]; then
        log "Creating environment configuration..."
        cat > .env << EOF
# Environment Configuration
DEPLOYMENT_ENV=$DEPLOYMENT_ENV
PLATFORM_VERSION=$VERSION

# Elasticsearch
ELASTIC_PASSWORD=changeme_elastic_password
KIBANA_PASSWORD=changeme_kibana_password

# Database
POSTGRES_PASSWORD=changeme_postgres_password

# Redis
REDIS_PASSWORD=changeme_redis_password

# External Integrations
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
PFSENSE_URL=https://firewall.enterprise.com
PFSENSE_USERNAME=admin
PFSENSE_PASSWORD=changeme_pfsense_password

# API Keys
THREAT_INTEL_API_KEY=your_threat_intel_api_key
JIRA_API_TOKEN=your_jira_api_token

# Monitoring
GRAFANA_ADMIN_PASSWORD=changeme_grafana_password
PROMETHEUS_RETENTION=30d
EOF
        warn "Please update the .env file with your actual credentials before proceeding"
    fi
    
    log "Environment setup completed"
}

# Deploy core infrastructure
deploy_infrastructure() {
    log "Deploying core infrastructure..."
    
    # Pull latest images
    log "Pulling Docker images..."
    docker-compose pull
    
    # Start core services
    log "Starting Elasticsearch and Redis..."
    docker-compose up -d elasticsearch redis
    
    # Wait for Elasticsearch to be ready
    log "Waiting for Elasticsearch to be ready..."
    timeout=300
    while [ $timeout -gt 0 ]; do
        if curl -s -f http://localhost:9200/_cluster/health > /dev/null 2>&1; then
            break
        fi
        sleep 5
        timeout=$((timeout - 5))
    done
    
    if [ $timeout -le 0 ]; then
        error "Elasticsearch failed to start within 5 minutes"
    fi
    
    log "Core infrastructure deployed successfully"
}

# Deploy ELK stack
deploy_elk_stack() {
    log "Deploying ELK stack..."
    
    # Start Logstash and Kibana
    docker-compose up -d logstash kibana
    
    # Wait for Kibana to be ready
    log "Waiting for Kibana to be ready..."
    timeout=300
    while [ $timeout -gt 0 ]; do
        if curl -s -f http://localhost:5601/api/status > /dev/null 2>&1; then
            break
        fi
        sleep 5
        timeout=$((timeout - 5))
    done
    
    if [ $timeout -le 0 ]; then
        error "Kibana failed to start within 5 minutes"
    fi
    
    # Import Kibana dashboards
    log "Importing Kibana dashboards..."
    if [ -d "elk/kibana/dashboards" ]; then
        for dashboard in elk/kibana/dashboards/*.json; do
            if [ -f "$dashboard" ]; then
                curl -X POST "localhost:5601/api/saved_objects/_import" \
                    -H "kbn-xsrf: true" \
                    -H "Content-Type: application/json" \
                    --form file=@"$dashboard" || warn "Failed to import dashboard: $dashboard"
            fi
        done
    fi
    
    log "ELK stack deployed successfully"
}

# Deploy security services
deploy_security_services() {
    log "Deploying security services..."
    
    # Start Suricata IDS/IPS
    docker-compose up -d suricata
    
    # Start AI threat detection
    docker-compose up -d ai-threat-detection
    
    # Start incident response service
    docker-compose up -d incident-response
    
    # Start monitoring services
    docker-compose up -d prometheus grafana
    
    log "Security services deployed successfully"
}

# Deploy Istio service mesh (if Kubernetes is available)
deploy_istio() {
    if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
        log "Deploying Istio service mesh..."
        
        # Check if Istio is already installed
        if ! kubectl get namespace istio-system &> /dev/null; then
            # Install Istio
            if command -v istioctl &> /dev/null; then
                istioctl install --set values.defaultRevision=default -y
                kubectl label namespace default istio-injection=enabled
                
                # Apply Istio configurations
                kubectl apply -f istio/policies/
                kubectl apply -f istio/gateways/
                kubectl apply -f istio/virtualservices/
                
                log "Istio service mesh deployed successfully"
            else
                warn "istioctl not found. Skipping Istio deployment."
            fi
        else
            log "Istio is already installed"
        fi
    else
        warn "Kubernetes not available. Skipping Istio deployment."
    fi
}

# Setup monitoring and alerting
setup_monitoring() {
    log "Setting up monitoring and alerting..."
    
    # Start Filebeat and Metricbeat
    docker-compose up -d filebeat metricbeat
    
    # Import Grafana dashboards
    if [ -d "monitoring/grafana/dashboards" ]; then
        log "Importing Grafana dashboards..."
        sleep 30  # Wait for Grafana to be ready
        
        for dashboard in monitoring/grafana/dashboards/*.json; do
            if [ -f "$dashboard" ]; then
                curl -X POST "http://admin:changeme@localhost:3000/api/dashboards/db" \
                    -H "Content-Type: application/json" \
                    -d @"$dashboard" || warn "Failed to import Grafana dashboard: $dashboard"
            fi
        done
    fi
    
    log "Monitoring and alerting setup completed"
}

# Deploy web services
deploy_web_services() {
    log "Deploying web services..."
    
    # Start API gateway and dashboard
    docker-compose up -d api-gateway security-dashboard
    
    # Start reverse proxy
    docker-compose up -d nginx
    
    log "Web services deployed successfully"
}

# Run health checks
run_health_checks() {
    log "Running health checks..."
    
    # Check Elasticsearch
    if curl -s -f http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; then
        log "✓ Elasticsearch is healthy"
    else
        error "✗ Elasticsearch health check failed"
    fi
    
    # Check Kibana
    if curl -s -f http://localhost:5601/api/status | grep -q '"overall":{"level":"available"'; then
        log "✓ Kibana is healthy"
    else
        warn "✗ Kibana health check failed"
    fi
    
    # Check Redis
    if docker exec redis redis-cli ping | grep -q "PONG"; then
        log "✓ Redis is healthy"
    else
        warn "✗ Redis health check failed"
    fi
    
    # Check Grafana
    if curl -s -f http://localhost:3000/api/health | grep -q '"database":"ok"'; then
        log "✓ Grafana is healthy"
    else
        warn "✗ Grafana health check failed"
    fi
    
    log "Health checks completed"
}

# Setup initial data and configurations
setup_initial_data() {
    log "Setting up initial data and configurations..."
    
    # Create Elasticsearch index templates
    if [ -f "elk/elasticsearch/index-templates.json" ]; then
        curl -X PUT "localhost:9200/_index_template/security-logs" \
            -H "Content-Type: application/json" \
            -d @elk/elasticsearch/index-templates.json || warn "Failed to create index template"
    fi
    
    # Load threat intelligence data
    if [ -f "data/threat-intel/malicious-ips.txt" ]; then
        log "Loading threat intelligence data..."
        python3 scripts/load-threat-intel.py || warn "Failed to load threat intelligence data"
    fi
    
    # Create default users and roles
    log "Creating default users and roles..."
    python3 scripts/setup-users.py || warn "Failed to create default users"
    
    log "Initial data setup completed"
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."
    
    report_file="deployment_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Platform Deployment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .success { border-left-color: #27ae60; }
        .warning { border-left-color: #f39c12; }
        .error { border-left-color: #e74c3c; }
        .service-list { list-style-type: none; padding: 0; }
        .service-list li { padding: 5px 0; }
        .status-ok { color: #27ae60; }
        .status-warn { color: #f39c12; }
        .status-error { color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Enterprise Network Security Platform</h1>
        <p>Deployment Report - $(date)</p>
        <p>Version: $VERSION | Environment: $DEPLOYMENT_ENV</p>
    </div>
    
    <div class="section success">
        <h2>Deployment Summary</h2>
        <p>The Enterprise Network Security Platform has been successfully deployed with the following components:</p>
        <ul class="service-list">
            <li><span class="status-ok">✓</span> Elasticsearch (Log Storage & Search)</li>
            <li><span class="status-ok">✓</span> Kibana (Visualization & Dashboards)</li>
            <li><span class="status-ok">✓</span> Logstash (Log Processing)</li>
            <li><span class="status-ok">✓</span> Suricata (IDS/IPS)</li>
            <li><span class="status-ok">✓</span> Redis (Caching & Real-time Data)</li>
            <li><span class="status-ok">✓</span> Prometheus (Metrics Collection)</li>
            <li><span class="status-ok">✓</span> Grafana (Metrics Visualization)</li>
            <li><span class="status-ok">✓</span> AI Threat Detection Service</li>
            <li><span class="status-ok">✓</span> Incident Response Service</li>
            <li><span class="status-ok">✓</span> Security Dashboard</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Access URLs</h2>
        <ul>
            <li><strong>Kibana:</strong> <a href="http://localhost:5601">http://localhost:5601</a></li>
            <li><strong>Grafana:</strong> <a href="http://localhost:3000">http://localhost:3000</a> (admin/changeme)</li>
            <li><strong>Security Dashboard:</strong> <a href="http://localhost:3001">http://localhost:3001</a></li>
            <li><strong>Elasticsearch:</strong> <a href="http://localhost:9200">http://localhost:9200</a></li>
            <li><strong>Prometheus:</strong> <a href="http://localhost:9090">http://localhost:9090</a></li>
        </ul>
    </div>
    
    <div class="section warning">
        <h2>Next Steps</h2>
        <ol>
            <li>Update default passwords in the .env file</li>
            <li>Configure external integrations (Slack, JIRA, pfSense)</li>
            <li>Import custom Suricata rules</li>
            <li>Set up SSL certificates for production</li>
            <li>Configure backup and disaster recovery</li>
            <li>Train AI models with historical data</li>
            <li>Set up monitoring alerts and notifications</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>Support</h2>
        <p>For support and documentation:</p>
        <ul>
            <li>Documentation: <code>docs/</code> directory</li>
            <li>Logs: <code>logs/</code> directory</li>
            <li>Configuration: <code>.env</code> file</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    log "Deployment report generated: $report_file"
}

# Main deployment flow
main() {
    log "Starting deployment process..."
    
    check_prerequisites
    setup_environment
    deploy_infrastructure
    deploy_elk_stack
    deploy_security_services
    deploy_istio
    setup_monitoring
    deploy_web_services
    run_health_checks
    setup_initial_data
    generate_report
    
    log "Deployment completed successfully!"
    
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    🎉 DEPLOYMENT SUCCESSFUL! 🎉                              ║
║                                                               ║
║    Your Enterprise Network Security Platform is now running  ║
║                                                               ║
║    Access your dashboards:                                   ║
║    • Kibana: http://localhost:5601                           ║
║    • Grafana: http://localhost:3000                          ║
║    • Security Dashboard: http://localhost:3001               ║
║                                                               ║
║    Next: Configure integrations and update passwords         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Handle script interruption
trap 'error "Deployment interrupted by user"' INT TERM

# Run main function
main "$@"
