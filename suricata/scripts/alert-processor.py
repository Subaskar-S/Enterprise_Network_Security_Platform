#!/usr/bin/env python3
"""
Suricata Alert Processor for Enterprise Security Platform
Processes Suricata alerts and forwards them to SIEM systems
"""

import json
import time
import logging
import asyncio
import aiofiles
import aiohttp
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from elasticsearch import AsyncElasticsearch
import redis.asyncio as redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    timestamp: str
    alert_id: str
    severity: str
    signature: str
    category: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    payload: Optional[str] = None
    http_hostname: Optional[str] = None
    http_url: Optional[str] = None
    http_user_agent: Optional[str] = None
    tls_sni: Optional[str] = None
    dns_query: Optional[str] = None
    file_hash: Optional[str] = None
    threat_score: int = 0
    mitre_tactics: List[str] = None
    iocs: List[str] = None

class ThreatIntelligence:
    """Threat intelligence integration"""
    
    def __init__(self):
        self.known_bad_ips = set()
        self.known_bad_domains = set()
        self.malware_hashes = set()
        self.redis_client = None
        
    async def initialize(self):
        """Initialize threat intelligence feeds"""
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        await self.load_threat_feeds()
        
    async def load_threat_feeds(self):
        """Load threat intelligence from various sources"""
        try:
            # Load from Redis cache
            bad_ips = await self.redis_client.smembers('threat:bad_ips')
            self.known_bad_ips.update(ip.decode() for ip in bad_ips)
            
            bad_domains = await self.redis_client.smembers('threat:bad_domains')
            self.known_bad_domains.update(domain.decode() for domain in bad_domains)
            
            malware_hashes = await self.redis_client.smembers('threat:malware_hashes')
            self.malware_hashes.update(hash_val.decode() for hash_val in malware_hashes)
            
            logger.info(f"Loaded {len(self.known_bad_ips)} bad IPs, "
                       f"{len(self.known_bad_domains)} bad domains, "
                       f"{len(self.malware_hashes)} malware hashes")
                       
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")
    
    def enrich_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """Enrich alert with threat intelligence"""
        iocs = []
        threat_score = alert.threat_score
        
        # Check source IP against threat feeds
        if alert.source_ip in self.known_bad_ips:
            iocs.append(f"malicious_ip:{alert.source_ip}")
            threat_score += 50
            
        # Check destination IP
        if alert.dest_ip in self.known_bad_ips:
            iocs.append(f"malicious_dest_ip:{alert.dest_ip}")
            threat_score += 30
            
        # Check domains
        if alert.http_hostname and alert.http_hostname in self.known_bad_domains:
            iocs.append(f"malicious_domain:{alert.http_hostname}")
            threat_score += 40
            
        if alert.tls_sni and alert.tls_sni in self.known_bad_domains:
            iocs.append(f"malicious_tls_sni:{alert.tls_sni}")
            threat_score += 40
            
        if alert.dns_query and alert.dns_query in self.known_bad_domains:
            iocs.append(f"malicious_dns_query:{alert.dns_query}")
            threat_score += 35
            
        # Check file hashes
        if alert.file_hash and alert.file_hash in self.malware_hashes:
            iocs.append(f"malware_hash:{alert.file_hash}")
            threat_score += 80
            
        alert.iocs = iocs
        alert.threat_score = min(threat_score, 100)  # Cap at 100
        
        return alert

class MITREMapper:
    """Map alerts to MITRE ATT&CK framework"""
    
    def __init__(self):
        self.signature_mappings = {
            'SQL Injection': ['T1190'],  # Exploit Public-Facing Application
            'XSS': ['T1190'],
            'Command Injection': ['T1059'],  # Command and Scripting Interpreter
            'Brute Force': ['T1110'],  # Brute Force
            'Lateral Movement': ['T1021'],  # Remote Services
            'Privilege Escalation': ['T1068'],  # Exploitation for Privilege Escalation
            'Data Exfiltration': ['T1041'],  # Exfiltration Over C2 Channel
            'Malware C2': ['T1071'],  # Application Layer Protocol
            'DNS Tunneling': ['T1071.004'],  # DNS
            'Cryptocurrency Mining': ['T1496'],  # Resource Hijacking
        }
    
    def map_alert(self, alert: SecurityAlert) -> List[str]:
        """Map alert to MITRE ATT&CK tactics"""
        tactics = []
        
        for pattern, mitre_ids in self.signature_mappings.items():
            if pattern.lower() in alert.signature.lower():
                tactics.extend(mitre_ids)
                
        return list(set(tactics))  # Remove duplicates

class AlertProcessor:
    """Main alert processing engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.threat_intel = ThreatIntelligence()
        self.mitre_mapper = MITREMapper()
        self.es_client = None
        self.processed_alerts = set()
        
    async def initialize(self):
        """Initialize the alert processor"""
        await self.threat_intel.initialize()
        
        # Initialize Elasticsearch client
        self.es_client = AsyncElasticsearch(
            [self.config['elasticsearch']['host']],
            http_auth=(
                self.config['elasticsearch']['username'],
                self.config['elasticsearch']['password']
            )
        )
        
        logger.info("Alert processor initialized")
    
    async def process_eve_log(self, log_file: str):
        """Process Suricata EVE JSON log file"""
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line.strip())
                            if event.get('event_type') == 'alert':
                                await self.process_alert(event)
                        except json.JSONDecodeError as e:
                            logger.error(f"Error parsing JSON: {e}")
                            
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
    
    async def process_alert(self, raw_alert: Dict):
        """Process a single alert"""
        try:
            # Create alert ID to prevent duplicates
            alert_id = self.generate_alert_id(raw_alert)
            if alert_id in self.processed_alerts:
                return
                
            self.processed_alerts.add(alert_id)
            
            # Parse raw alert into structured format
            alert = self.parse_raw_alert(raw_alert, alert_id)
            
            # Enrich with threat intelligence
            alert = self.threat_intel.enrich_alert(alert)
            
            # Map to MITRE ATT&CK
            alert.mitre_tactics = self.mitre_mapper.map_alert(alert)
            
            # Determine severity based on threat score
            alert.severity = self.calculate_severity(alert.threat_score)
            
            # Send to various outputs
            await asyncio.gather(
                self.send_to_elasticsearch(alert),
                self.send_to_splunk(alert),
                self.send_to_slack(alert) if alert.threat_score >= 70 else asyncio.sleep(0),
                self.trigger_automated_response(alert) if alert.threat_score >= 80 else asyncio.sleep(0)
            )
            
            logger.info(f"Processed alert {alert_id} with threat score {alert.threat_score}")
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def parse_raw_alert(self, raw_alert: Dict, alert_id: str) -> SecurityAlert:
        """Parse raw Suricata alert into structured format"""
        alert_data = raw_alert.get('alert', {})
        flow = raw_alert.get('flow', {})
        http = raw_alert.get('http', {})
        tls = raw_alert.get('tls', {})
        dns = raw_alert.get('dns', {})
        fileinfo = raw_alert.get('fileinfo', {})
        
        return SecurityAlert(
            timestamp=raw_alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
            alert_id=alert_id,
            severity='medium',  # Will be recalculated
            signature=alert_data.get('signature', 'Unknown'),
            category=alert_data.get('category', 'Unknown'),
            source_ip=raw_alert.get('src_ip', ''),
            dest_ip=raw_alert.get('dest_ip', ''),
            source_port=raw_alert.get('src_port', 0),
            dest_port=raw_alert.get('dest_port', 0),
            protocol=raw_alert.get('proto', ''),
            payload=raw_alert.get('payload'),
            http_hostname=http.get('hostname'),
            http_url=http.get('url'),
            http_user_agent=http.get('http_user_agent'),
            tls_sni=tls.get('sni'),
            dns_query=dns.get('query', {}).get('rrname') if dns.get('query') else None,
            file_hash=fileinfo.get('sha256'),
            threat_score=self.calculate_base_threat_score(alert_data)
        )
    
    def generate_alert_id(self, raw_alert: Dict) -> str:
        """Generate unique alert ID"""
        content = f"{raw_alert.get('timestamp')}{raw_alert.get('src_ip')}{raw_alert.get('dest_ip')}{raw_alert.get('alert', {}).get('signature')}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def calculate_base_threat_score(self, alert_data: Dict) -> int:
        """Calculate base threat score from alert data"""
        severity_map = {
            1: 20,  # Low
            2: 40,  # Medium
            3: 60,  # High
            4: 80   # Critical
        }
        return severity_map.get(alert_data.get('severity', 2), 40)
    
    def calculate_severity(self, threat_score: int) -> str:
        """Calculate severity based on threat score"""
        if threat_score >= 80:
            return 'critical'
        elif threat_score >= 60:
            return 'high'
        elif threat_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    async def send_to_elasticsearch(self, alert: SecurityAlert):
        """Send alert to Elasticsearch"""
        try:
            index_name = f"security-alerts-{datetime.now().strftime('%Y.%m.%d')}"
            await self.es_client.index(
                index=index_name,
                id=alert.alert_id,
                body=asdict(alert)
            )
        except Exception as e:
            logger.error(f"Error sending to Elasticsearch: {e}")
    
    async def send_to_splunk(self, alert: SecurityAlert):
        """Send alert to Splunk"""
        try:
            splunk_config = self.config.get('splunk', {})
            if not splunk_config.get('enabled', False):
                return
                
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f"Splunk {splunk_config['token']}",
                    'Content-Type': 'application/json'
                }
                
                payload = {
                    'event': asdict(alert),
                    'sourcetype': 'suricata:alert',
                    'index': 'security'
                }
                
                async with session.post(
                    f"{splunk_config['url']}/services/collector/event",
                    headers=headers,
                    json=payload
                ) as response:
                    if response.status != 200:
                        logger.error(f"Splunk error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error sending to Splunk: {e}")
    
    async def send_to_slack(self, alert: SecurityAlert):
        """Send high-priority alerts to Slack"""
        try:
            slack_config = self.config.get('slack', {})
            if not slack_config.get('enabled', False):
                return
                
            message = {
                'text': f"🚨 High Priority Security Alert",
                'attachments': [{
                    'color': 'danger' if alert.severity == 'critical' else 'warning',
                    'fields': [
                        {'title': 'Signature', 'value': alert.signature, 'short': False},
                        {'title': 'Source IP', 'value': alert.source_ip, 'short': True},
                        {'title': 'Destination IP', 'value': alert.dest_ip, 'short': True},
                        {'title': 'Threat Score', 'value': str(alert.threat_score), 'short': True},
                        {'title': 'Severity', 'value': alert.severity.upper(), 'short': True}
                    ],
                    'ts': int(time.time())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(slack_config['webhook_url'], json=message) as response:
                    if response.status != 200:
                        logger.error(f"Slack error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error sending to Slack: {e}")
    
    async def trigger_automated_response(self, alert: SecurityAlert):
        """Trigger automated response for critical alerts"""
        try:
            if alert.threat_score >= 90:
                # Block IP at firewall level
                await self.block_ip_at_firewall(alert.source_ip)
                
            if alert.threat_score >= 80:
                # Create incident ticket
                await self.create_incident_ticket(alert)
                
        except Exception as e:
            logger.error(f"Error in automated response: {e}")
    
    async def block_ip_at_firewall(self, ip_address: str):
        """Block IP address at pfSense firewall"""
        try:
            pfsense_config = self.config.get('pfsense', {})
            if not pfsense_config.get('enabled', False):
                return
                
            # Call pfSense API to block IP
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    pfsense_config['username'],
                    pfsense_config['password']
                )
                
                payload = {
                    'type': 'block',
                    'interface': 'wan',
                    'source': {'address': ip_address},
                    'destination': {'any': True},
                    'descr': f'Auto-blocked by security platform - Alert ID: {alert.alert_id}'
                }
                
                async with session.post(
                    f"{pfsense_config['url']}/api/v1/firewall/rule",
                    auth=auth,
                    json=payload
                ) as response:
                    if response.status == 200:
                        logger.info(f"Successfully blocked IP {ip_address}")
                    else:
                        logger.error(f"Failed to block IP {ip_address}: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
    
    async def create_incident_ticket(self, alert: SecurityAlert):
        """Create incident ticket in ITSM system"""
        try:
            # Implementation would integrate with ServiceNow, Jira, etc.
            logger.info(f"Creating incident ticket for alert {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error creating incident ticket: {e}")

async def main():
    """Main function"""
    config = {
        'elasticsearch': {
            'host': 'localhost:9200',
            'username': 'elastic',
            'password': 'changeme'
        },
        'splunk': {
            'enabled': True,
            'url': 'https://splunk.enterprise.com:8088',
            'token': 'your-splunk-token'
        },
        'slack': {
            'enabled': True,
            'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        },
        'pfsense': {
            'enabled': True,
            'url': 'https://firewall.enterprise.com',
            'username': 'admin',
            'password': 'your-password'
        }
    }
    
    processor = AlertProcessor(config)
    await processor.initialize()
    
    # Monitor EVE log file
    log_file = '/var/log/suricata/eve.json'
    
    while True:
        try:
            await processor.process_eve_log(log_file)
            await asyncio.sleep(1)  # Check for new alerts every second
        except KeyboardInterrupt:
            logger.info("Shutting down alert processor")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(main())
