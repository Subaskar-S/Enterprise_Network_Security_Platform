#!/usr/bin/env python3
"""
Automated Incident Response System for Enterprise Security Platform
Handles threat detection, escalation, and automated remediation
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import uuid

# Third-party imports
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
import slack_sdk.web.async_client as slack

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

@dataclass
class SecurityIncident:
    """Security incident data structure"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    source_ip: str
    target_ip: str
    threat_type: str
    detection_time: str
    last_updated: str
    assigned_to: Optional[str] = None
    artifacts: List[Dict] = None
    timeline: List[Dict] = None
    mitigation_actions: List[str] = None
    risk_score: int = 0
    
    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = []
        if self.timeline is None:
            self.timeline = []
        if self.mitigation_actions is None:
            self.mitigation_actions = []

class AutomatedResponseEngine:
    """Main engine for automated incident response"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.redis_client = None
        self.es_client = None
        self.slack_client = None
        self.active_incidents = {}
        
        # Response thresholds
        self.auto_block_threshold = config.get('auto_block_threshold', 80)
        self.escalation_threshold = config.get('escalation_threshold', 70)
        self.notification_threshold = config.get('notification_threshold', 60)
        
    async def initialize(self):
        """Initialize the response engine"""
        # Initialize Redis for caching
        self.redis_client = redis.Redis(
            host=self.config['redis']['host'],
            port=self.config['redis']['port'],
            db=0
        )
        
        # Initialize Elasticsearch
        self.es_client = AsyncElasticsearch([self.config['elasticsearch']['host']])
        
        # Initialize Slack client
        if self.config.get('slack', {}).get('enabled'):
            self.slack_client = slack.AsyncWebClient(
                token=self.config['slack']['bot_token']
            )
        
        logger.info("Automated response engine initialized")
    
    async def process_threat_alert(self, alert: Dict) -> Optional[SecurityIncident]:
        """Process incoming threat alert and determine response"""
        try:
            # Create incident from alert
            incident = await self.create_incident_from_alert(alert)
            
            # Determine response actions based on severity and risk score
            response_actions = await self.determine_response_actions(incident)
            
            # Execute automated responses
            for action in response_actions:
                await self.execute_response_action(incident, action)
            
            # Store incident
            await self.store_incident(incident)
            
            # Send notifications
            await self.send_notifications(incident)
            
            logger.info(f"Processed threat alert and created incident {incident.incident_id}")
            return incident
            
        except Exception as e:
            logger.error(f"Error processing threat alert: {e}")
            return None
    
    async def create_incident_from_alert(self, alert: Dict) -> SecurityIncident:
        """Create security incident from threat alert"""
        incident_id = str(uuid.uuid4())
        
        # Determine severity based on risk score
        risk_score = alert.get('risk_score', 0)
        if risk_score >= 90:
            severity = IncidentSeverity.CRITICAL
        elif risk_score >= 70:
            severity = IncidentSeverity.HIGH
        elif risk_score >= 50:
            severity = IncidentSeverity.MEDIUM
        else:
            severity = IncidentSeverity.LOW
        
        # Create incident
        incident = SecurityIncident(
            incident_id=incident_id,
            title=f"Security Alert: {alert.get('threat_type', 'Unknown Threat')}",
            description=self.generate_incident_description(alert),
            severity=severity,
            status=IncidentStatus.OPEN,
            source_ip=alert.get('source_ip', ''),
            target_ip=alert.get('target_ip', ''),
            threat_type=alert.get('threat_type', 'unknown'),
            detection_time=alert.get('timestamp', datetime.now().isoformat()),
            last_updated=datetime.now().isoformat(),
            risk_score=risk_score
        )
        
        # Add initial timeline entry
        incident.timeline.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'incident_created',
            'description': 'Incident created from automated threat detection',
            'actor': 'system'
        })
        
        # Add artifacts
        incident.artifacts.extend([
            {
                'type': 'ip_address',
                'value': incident.source_ip,
                'description': 'Source IP address'
            },
            {
                'type': 'threat_signature',
                'value': alert.get('signature', ''),
                'description': 'Detection signature'
            }
        ])
        
        return incident
    
    def generate_incident_description(self, alert: Dict) -> str:
        """Generate detailed incident description"""
        description_parts = [
            f"Threat Type: {alert.get('threat_type', 'Unknown')}",
            f"Source IP: {alert.get('source_ip', 'Unknown')}",
            f"Target IP: {alert.get('target_ip', 'Unknown')}",
            f"Risk Score: {alert.get('risk_score', 0)}/100",
            f"Detection Time: {alert.get('timestamp', 'Unknown')}"
        ]
        
        if alert.get('signature'):
            description_parts.append(f"Signature: {alert['signature']}")
        
        if alert.get('mitre_tactics'):
            description_parts.append(f"MITRE ATT&CK Tactics: {', '.join(alert['mitre_tactics'])}")
        
        return "\n".join(description_parts)
    
    async def determine_response_actions(self, incident: SecurityIncident) -> List[str]:
        """Determine appropriate response actions based on incident characteristics"""
        actions = []
        
        # Always collect additional information
        actions.append('collect_forensics')
        
        # Risk-based automated responses
        if incident.risk_score >= self.auto_block_threshold:
            actions.extend([
                'block_source_ip',
                'isolate_affected_systems',
                'escalate_to_soc',
                'create_jira_ticket'
            ])
        elif incident.risk_score >= self.escalation_threshold:
            actions.extend([
                'escalate_to_soc',
                'create_jira_ticket',
                'monitor_source_ip'
            ])
        elif incident.risk_score >= self.notification_threshold:
            actions.extend([
                'notify_security_team',
                'monitor_source_ip'
            ])
        
        # Threat-specific responses
        if incident.threat_type in ['malware', 'ransomware']:
            actions.extend([
                'isolate_affected_systems',
                'backup_critical_data',
                'scan_network_for_indicators'
            ])
        elif incident.threat_type == 'data_exfiltration':
            actions.extend([
                'block_data_channels',
                'audit_data_access',
                'notify_compliance_team'
            ])
        elif incident.threat_type == 'brute_force':
            actions.extend([
                'implement_rate_limiting',
                'force_password_reset',
                'enable_mfa'
            ])
        
        # Time-based responses
        current_hour = datetime.now().hour
        if current_hour < 8 or current_hour > 18:  # Outside business hours
            if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
                actions.append('page_on_call_engineer')
        
        return list(set(actions))  # Remove duplicates
    
    async def execute_response_action(self, incident: SecurityIncident, action: str):
        """Execute a specific response action"""
        try:
            action_map = {
                'block_source_ip': self.block_source_ip,
                'isolate_affected_systems': self.isolate_affected_systems,
                'collect_forensics': self.collect_forensics,
                'escalate_to_soc': self.escalate_to_soc,
                'create_jira_ticket': self.create_jira_ticket,
                'notify_security_team': self.notify_security_team,
                'monitor_source_ip': self.monitor_source_ip,
                'backup_critical_data': self.backup_critical_data,
                'scan_network_for_indicators': self.scan_network_for_indicators,
                'block_data_channels': self.block_data_channels,
                'audit_data_access': self.audit_data_access,
                'notify_compliance_team': self.notify_compliance_team,
                'implement_rate_limiting': self.implement_rate_limiting,
                'force_password_reset': self.force_password_reset,
                'enable_mfa': self.enable_mfa,
                'page_on_call_engineer': self.page_on_call_engineer
            }
            
            if action in action_map:
                await action_map[action](incident)
                
                # Add to timeline
                incident.timeline.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': action,
                    'description': f'Executed automated response: {action}',
                    'actor': 'system'
                })
                
                # Add to mitigation actions
                incident.mitigation_actions.append(action)
                
                logger.info(f"Executed response action '{action}' for incident {incident.incident_id}")
            else:
                logger.warning(f"Unknown response action: {action}")
                
        except Exception as e:
            logger.error(f"Error executing response action '{action}': {e}")
    
    async def block_source_ip(self, incident: SecurityIncident):
        """Block source IP at firewall level"""
        try:
            pfsense_config = self.config.get('pfsense', {})
            if not pfsense_config.get('enabled'):
                logger.info(f"pfSense integration disabled, would block IP: {incident.source_ip}")
                return
            
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    pfsense_config['username'],
                    pfsense_config['password']
                )
                
                payload = {
                    'type': 'block',
                    'interface': 'wan',
                    'source': {'address': incident.source_ip},
                    'destination': {'any': True},
                    'descr': f'Auto-blocked by security platform - Incident: {incident.incident_id}'
                }
                
                async with session.post(
                    f"{pfsense_config['url']}/api/v1/firewall/rule",
                    auth=auth,
                    json=payload
                ) as response:
                    if response.status == 200:
                        logger.info(f"Successfully blocked IP {incident.source_ip}")
                    else:
                        logger.error(f"Failed to block IP {incident.source_ip}: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error blocking IP {incident.source_ip}: {e}")
    
    async def isolate_affected_systems(self, incident: SecurityIncident):
        """Isolate affected systems from network"""
        # This would integrate with network management systems
        logger.info(f"Isolating systems affected by incident {incident.incident_id}")
        
        # Example: Update network ACLs, VLAN assignments, etc.
        isolation_actions = [
            f"Isolate host {incident.target_ip}",
            f"Block lateral movement from {incident.source_ip}",
            "Enable enhanced monitoring on affected subnet"
        ]
        
        for action in isolation_actions:
            logger.info(f"Isolation action: {action}")
    
    async def collect_forensics(self, incident: SecurityIncident):
        """Collect forensic evidence"""
        logger.info(f"Collecting forensics for incident {incident.incident_id}")
        
        # Collect network packet captures
        forensic_data = {
            'packet_capture': f"pcap_{incident.incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
            'memory_dump': f"memory_{incident.target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mem",
            'disk_image': f"disk_{incident.target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.img",
            'log_collection': f"logs_{incident.incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
        }
        
        # Add forensic artifacts to incident
        for artifact_type, filename in forensic_data.items():
            incident.artifacts.append({
                'type': artifact_type,
                'value': filename,
                'description': f'Forensic evidence: {artifact_type}'
            })
    
    async def escalate_to_soc(self, incident: SecurityIncident):
        """Escalate incident to Security Operations Center"""
        logger.info(f"Escalating incident {incident.incident_id} to SOC")
        
        # Update incident status
        incident.status = IncidentStatus.INVESTIGATING
        incident.assigned_to = "soc_team"
        
        # Send to SOC dashboard/queue
        soc_payload = {
            'incident_id': incident.incident_id,
            'severity': incident.severity.value,
            'threat_type': incident.threat_type,
            'source_ip': incident.source_ip,
            'risk_score': incident.risk_score,
            'escalation_time': datetime.now().isoformat()
        }
        
        # Store in high-priority queue
        await self.redis_client.lpush('soc_escalation_queue', json.dumps(soc_payload))
    
    async def create_jira_ticket(self, incident: SecurityIncident):
        """Create JIRA ticket for incident tracking"""
        try:
            jira_config = self.config.get('jira', {})
            if not jira_config.get('enabled'):
                logger.info(f"JIRA integration disabled, would create ticket for incident {incident.incident_id}")
                return
            
            ticket_data = {
                'fields': {
                    'project': {'key': jira_config['project_key']},
                    'summary': incident.title,
                    'description': incident.description,
                    'issuetype': {'name': 'Security Incident'},
                    'priority': {'name': self.map_severity_to_jira_priority(incident.severity)},
                    'labels': ['security', 'automated', incident.threat_type],
                    'customfield_10001': incident.incident_id  # Custom field for incident ID
                }
            }
            
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    jira_config['username'],
                    jira_config['password']
                )
                
                async with session.post(
                    f"{jira_config['url']}/rest/api/2/issue",
                    auth=auth,
                    json=ticket_data
                ) as response:
                    if response.status == 201:
                        ticket_response = await response.json()
                        ticket_key = ticket_response['key']
                        
                        incident.artifacts.append({
                            'type': 'jira_ticket',
                            'value': ticket_key,
                            'description': f'JIRA ticket for incident tracking'
                        })
                        
                        logger.info(f"Created JIRA ticket {ticket_key} for incident {incident.incident_id}")
                    else:
                        logger.error(f"Failed to create JIRA ticket: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error creating JIRA ticket: {e}")
    
    def map_severity_to_jira_priority(self, severity: IncidentSeverity) -> str:
        """Map incident severity to JIRA priority"""
        mapping = {
            IncidentSeverity.CRITICAL: 'Highest',
            IncidentSeverity.HIGH: 'High',
            IncidentSeverity.MEDIUM: 'Medium',
            IncidentSeverity.LOW: 'Low'
        }
        return mapping.get(severity, 'Medium')
    
    async def notify_security_team(self, incident: SecurityIncident):
        """Send notifications to security team"""
        if self.slack_client:
            await self.send_slack_notification(incident)
        
        # Send email notifications
        await self.send_email_notification(incident)
    
    async def send_slack_notification(self, incident: SecurityIncident):
        """Send Slack notification"""
        try:
            color_map = {
                IncidentSeverity.CRITICAL: 'danger',
                IncidentSeverity.HIGH: 'warning',
                IncidentSeverity.MEDIUM: 'good',
                IncidentSeverity.LOW: '#439FE0'
            }
            
            message = {
                'channel': self.config['slack']['security_channel'],
                'text': f"🚨 Security Incident: {incident.title}",
                'attachments': [{
                    'color': color_map.get(incident.severity, 'good'),
                    'fields': [
                        {'title': 'Incident ID', 'value': incident.incident_id, 'short': True},
                        {'title': 'Severity', 'value': incident.severity.value.upper(), 'short': True},
                        {'title': 'Threat Type', 'value': incident.threat_type, 'short': True},
                        {'title': 'Risk Score', 'value': f"{incident.risk_score}/100", 'short': True},
                        {'title': 'Source IP', 'value': incident.source_ip, 'short': True},
                        {'title': 'Target IP', 'value': incident.target_ip, 'short': True},
                        {'title': 'Status', 'value': incident.status.value.upper(), 'short': True},
                        {'title': 'Detection Time', 'value': incident.detection_time, 'short': True}
                    ],
                    'actions': [
                        {
                            'type': 'button',
                            'text': 'View Incident',
                            'url': f"{self.config.get('dashboard_url', '')}/incidents/{incident.incident_id}"
                        }
                    ]
                }]
            }
            
            await self.slack_client.chat_postMessage(**message)
            logger.info(f"Sent Slack notification for incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    async def send_email_notification(self, incident: SecurityIncident):
        """Send email notification"""
        # Implementation would integrate with email service
        logger.info(f"Sending email notification for incident {incident.incident_id}")
    
    async def monitor_source_ip(self, incident: SecurityIncident):
        """Add source IP to monitoring watchlist"""
        monitoring_entry = {
            'ip': incident.source_ip,
            'incident_id': incident.incident_id,
            'added_time': datetime.now().isoformat(),
            'monitoring_duration': 24 * 3600,  # 24 hours
            'alert_threshold': 5  # Alert if seen 5+ times
        }
        
        await self.redis_client.setex(
            f"monitor_ip:{incident.source_ip}",
            24 * 3600,  # 24 hours TTL
            json.dumps(monitoring_entry)
        )
        
        logger.info(f"Added {incident.source_ip} to monitoring watchlist")
    
    async def backup_critical_data(self, incident: SecurityIncident):
        """Initiate backup of critical data"""
        logger.info(f"Initiating critical data backup for incident {incident.incident_id}")
        
        # This would integrate with backup systems
        backup_tasks = [
            "Backup user databases",
            "Backup configuration files",
            "Backup application data",
            "Create system snapshots"
        ]
        
        for task in backup_tasks:
            logger.info(f"Backup task: {task}")
    
    async def scan_network_for_indicators(self, incident: SecurityIncident):
        """Scan network for indicators of compromise"""
        logger.info(f"Scanning network for IoCs related to incident {incident.incident_id}")
        
        # This would integrate with vulnerability scanners, EDR systems
        scan_targets = [
            incident.source_ip,
            incident.target_ip,
            "Network segments with similar traffic patterns"
        ]
        
        for target in scan_targets:
            logger.info(f"Scanning target: {target}")
    
    async def block_data_channels(self, incident: SecurityIncident):
        """Block data exfiltration channels"""
        logger.info(f"Blocking data channels for incident {incident.incident_id}")
        
        # Block common exfiltration methods
        blocking_actions = [
            "Block FTP/SFTP from affected systems",
            "Restrict cloud storage access",
            "Monitor email attachments",
            "Block P2P protocols"
        ]
        
        for action in blocking_actions:
            logger.info(f"Data blocking action: {action}")
    
    async def audit_data_access(self, incident: SecurityIncident):
        """Audit data access patterns"""
        logger.info(f"Auditing data access for incident {incident.incident_id}")
        
        # This would query access logs, database logs, etc.
        audit_queries = [
            "Recent file access by affected users",
            "Database queries from affected systems",
            "Cloud storage access patterns",
            "Email and document downloads"
        ]
        
        for query in audit_queries:
            logger.info(f"Audit query: {query}")
    
    async def notify_compliance_team(self, incident: SecurityIncident):
        """Notify compliance team for regulatory requirements"""
        logger.info(f"Notifying compliance team for incident {incident.incident_id}")
        
        # This would send notifications to compliance team
        compliance_notification = {
            'incident_id': incident.incident_id,
            'potential_data_breach': True,
            'regulatory_requirements': ['GDPR', 'SOX', 'PCI-DSS'],
            'notification_deadline': (datetime.now() + timedelta(hours=72)).isoformat()
        }
        
        logger.info(f"Compliance notification: {compliance_notification}")
    
    async def implement_rate_limiting(self, incident: SecurityIncident):
        """Implement rate limiting for brute force protection"""
        logger.info(f"Implementing rate limiting for incident {incident.incident_id}")
        
        # This would configure rate limiting rules
        rate_limit_rules = [
            f"Limit login attempts from {incident.source_ip}",
            "Implement CAPTCHA for suspicious IPs",
            "Increase authentication delays",
            "Enable account lockout policies"
        ]
        
        for rule in rate_limit_rules:
            logger.info(f"Rate limiting rule: {rule}")
    
    async def force_password_reset(self, incident: SecurityIncident):
        """Force password reset for affected accounts"""
        logger.info(f"Forcing password reset for incident {incident.incident_id}")
        
        # This would integrate with identity management systems
        reset_actions = [
            "Identify affected user accounts",
            "Force password reset for compromised accounts",
            "Invalidate existing sessions",
            "Require password complexity validation"
        ]
        
        for action in reset_actions:
            logger.info(f"Password reset action: {action}")
    
    async def enable_mfa(self, incident: SecurityIncident):
        """Enable multi-factor authentication"""
        logger.info(f"Enabling MFA for incident {incident.incident_id}")
        
        # This would configure MFA requirements
        mfa_actions = [
            "Enable MFA for affected accounts",
            "Require MFA for administrative access",
            "Configure backup authentication methods",
            "Update authentication policies"
        ]
        
        for action in mfa_actions:
            logger.info(f"MFA action: {action}")
    
    async def page_on_call_engineer(self, incident: SecurityIncident):
        """Page on-call security engineer"""
        logger.info(f"Paging on-call engineer for incident {incident.incident_id}")
        
        # This would integrate with PagerDuty, OpsGenie, etc.
        page_data = {
            'incident_id': incident.incident_id,
            'severity': incident.severity.value,
            'summary': incident.title,
            'urgency': 'high' if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL] else 'low'
        }
        
        logger.info(f"Paging data: {page_data}")
    
    async def store_incident(self, incident: SecurityIncident):
        """Store incident in database"""
        try:
            # Store in Elasticsearch
            await self.es_client.index(
                index=f"security-incidents-{datetime.now().strftime('%Y.%m')}",
                id=incident.incident_id,
                body=asdict(incident)
            )
            
            # Cache in Redis for quick access
            await self.redis_client.setex(
                f"incident:{incident.incident_id}",
                7 * 24 * 3600,  # 7 days TTL
                json.dumps(asdict(incident), default=str)
            )
            
            # Add to active incidents
            self.active_incidents[incident.incident_id] = incident
            
            logger.info(f"Stored incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error storing incident: {e}")
    
    async def send_notifications(self, incident: SecurityIncident):
        """Send appropriate notifications based on incident severity"""
        if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            await self.notify_security_team(incident)
        
        if incident.severity == IncidentSeverity.CRITICAL:
            await self.page_on_call_engineer(incident)

async def main():
    """Main function for testing"""
    config = {
        'redis': {'host': 'localhost', 'port': 6379},
        'elasticsearch': {'host': 'localhost:9200'},
        'slack': {
            'enabled': True,
            'bot_token': 'xoxb-your-bot-token',
            'security_channel': '#security-alerts'
        },
        'pfsense': {
            'enabled': True,
            'url': 'https://firewall.enterprise.com',
            'username': 'admin',
            'password': 'password'
        },
        'jira': {
            'enabled': True,
            'url': 'https://company.atlassian.net',
            'username': 'security@company.com',
            'password': 'api-token',
            'project_key': 'SEC'
        },
        'auto_block_threshold': 80,
        'escalation_threshold': 70,
        'notification_threshold': 60
    }
    
    engine = AutomatedResponseEngine(config)
    await engine.initialize()
    
    # Test with sample alert
    sample_alert = {
        'threat_type': 'malware',
        'source_ip': '192.168.1.100',
        'target_ip': '10.0.1.50',
        'risk_score': 85,
        'timestamp': datetime.now().isoformat(),
        'signature': 'Malware communication detected',
        'mitre_tactics': ['T1071', 'T1041']
    }
    
    incident = await engine.process_threat_alert(sample_alert)
    if incident:
        logger.info(f"Created incident: {incident.incident_id}")

if __name__ == '__main__':
    asyncio.run(main())
