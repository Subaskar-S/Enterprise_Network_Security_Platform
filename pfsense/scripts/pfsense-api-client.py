#!/usr/bin/env python3
"""
pfSense API Client for Enterprise Security Platform
Provides automated firewall management and integration
"""

import requests
import json
import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FirewallRule:
    """Firewall rule data structure"""
    interface: str
    action: str  # pass, block, reject
    protocol: str  # tcp, udp, icmp, any
    source: str
    destination: str
    port: Optional[str] = None
    description: str = ""
    log: bool = True
    tracker: Optional[int] = None

@dataclass
class VPNUser:
    """VPN user configuration"""
    username: str
    password: str
    email: str
    certificate: Optional[str] = None
    enabled: bool = True
    description: str = ""

class PfSenseAPIClient:
    """pfSense API client for automated security operations"""
    
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = True):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = None
        self.csrf_token = None
        
        # API endpoints
        self.endpoints = {
            'login': '/api/v1/access_token',
            'firewall_rules': '/api/v1/firewall/rule',
            'firewall_aliases': '/api/v1/firewall/alias',
            'interfaces': '/api/v1/interface',
            'system_info': '/api/v1/system/info',
            'vpn_users': '/api/v1/user',
            'certificates': '/api/v1/system/certificate',
            'logs': '/api/v1/status/log',
            'traffic_shaper': '/api/v1/firewall/traffic_shaper',
            'nat_rules': '/api/v1/firewall/nat/port_forward'
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    async def connect(self):
        """Establish connection to pfSense API"""
        try:
            self.session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl),
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Authenticate and get access token
            auth_data = {
                'client_id': self.username,
                'client_token': self.password
            }
            
            async with self.session.post(
                f"{self.host}{self.endpoints['login']}",
                json=auth_data
            ) as response:
                if response.status == 200:
                    token_data = await response.json()
                    self.access_token = token_data.get('data', {}).get('token')
                    
                    # Set authorization header for future requests
                    self.session.headers.update({
                        'Authorization': f'Bearer {self.access_token}',
                        'Content-Type': 'application/json'
                    })
                    
                    logger.info("Successfully connected to pfSense API")
                else:
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Failed to connect to pfSense API: {e}")
            raise
    
    async def disconnect(self):
        """Close connection to pfSense API"""
        if self.session:
            await self.session.close()
            logger.info("Disconnected from pfSense API")
    
    async def get_system_info(self) -> Dict:
        """Get pfSense system information"""
        try:
            async with self.session.get(
                f"{self.host}{self.endpoints['system_info']}"
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Failed to get system info: {response.status}")
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            raise
    
    async def create_firewall_rule(self, rule: FirewallRule) -> Dict:
        """Create a new firewall rule"""
        try:
            rule_data = {
                'type': rule.action,
                'interface': rule.interface,
                'ipprotocol': 'inet',
                'protocol': rule.protocol,
                'source': {'address': rule.source},
                'destination': {'address': rule.destination},
                'descr': rule.description,
                'log': rule.log
            }
            
            # Add port if specified
            if rule.port:
                rule_data['destination']['port'] = rule.port
            
            # Add tracker if specified
            if rule.tracker:
                rule_data['tracker'] = rule.tracker
            
            async with self.session.post(
                f"{self.host}{self.endpoints['firewall_rules']}",
                json=rule_data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Created firewall rule: {rule.description}")
                    return result
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to create firewall rule: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error creating firewall rule: {e}")
            raise
    
    async def delete_firewall_rule(self, rule_id: Union[int, str]) -> bool:
        """Delete a firewall rule by ID"""
        try:
            async with self.session.delete(
                f"{self.host}{self.endpoints['firewall_rules']}/{rule_id}"
            ) as response:
                if response.status == 200:
                    logger.info(f"Deleted firewall rule: {rule_id}")
                    return True
                else:
                    raise Exception(f"Failed to delete firewall rule: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error deleting firewall rule: {e}")
            return False
    
    async def block_ip_address(self, ip_address: str, description: str = "Auto-blocked by security platform") -> Dict:
        """Block an IP address by creating a firewall rule"""
        rule = FirewallRule(
            interface='wan',
            action='block',
            protocol='any',
            source=ip_address,
            destination='any',
            description=description,
            log=True
        )
        
        return await self.create_firewall_rule(rule)
    
    async def unblock_ip_address(self, ip_address: str) -> bool:
        """Unblock an IP address by removing firewall rules"""
        try:
            # Get all firewall rules
            rules = await self.get_firewall_rules()
            
            # Find rules blocking this IP
            rules_to_delete = []
            for rule in rules.get('data', []):
                if (rule.get('type') == 'block' and 
                    rule.get('source', {}).get('address') == ip_address):
                    rules_to_delete.append(rule.get('id'))
            
            # Delete matching rules
            success = True
            for rule_id in rules_to_delete:
                if not await self.delete_firewall_rule(rule_id):
                    success = False
            
            if rules_to_delete:
                logger.info(f"Unblocked IP {ip_address}, removed {len(rules_to_delete)} rules")
            else:
                logger.warning(f"No blocking rules found for IP {ip_address}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    async def get_firewall_rules(self) -> Dict:
        """Get all firewall rules"""
        try:
            async with self.session.get(
                f"{self.host}{self.endpoints['firewall_rules']}"
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Failed to get firewall rules: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            raise
    
    async def create_alias(self, name: str, alias_type: str, addresses: List[str], description: str = "") -> Dict:
        """Create a firewall alias"""
        try:
            alias_data = {
                'name': name,
                'type': alias_type,  # host, network, port
                'address': addresses,
                'descr': description
            }
            
            async with self.session.post(
                f"{self.host}{self.endpoints['firewall_aliases']}",
                json=alias_data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Created firewall alias: {name}")
                    return result
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to create alias: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error creating alias: {e}")
            raise
    
    async def update_threat_intel_blocklist(self, malicious_ips: List[str]) -> bool:
        """Update threat intelligence IP blocklist"""
        try:
            # Update the threat_intel_blocklist alias
            alias_name = "threat_intel_blocklist"
            
            # First, try to delete existing alias
            try:
                await self.session.delete(
                    f"{self.host}{self.endpoints['firewall_aliases']}/{alias_name}"
                )
            except:
                pass  # Alias might not exist
            
            # Create new alias with updated IPs
            await self.create_alias(
                name=alias_name,
                alias_type="network",
                addresses=malicious_ips,
                description="Threat intelligence IP blocklist - Auto-updated"
            )
            
            logger.info(f"Updated threat intel blocklist with {len(malicious_ips)} IPs")
            return True
            
        except Exception as e:
            logger.error(f"Error updating threat intel blocklist: {e}")
            return False
    
    async def create_vpn_user(self, user: VPNUser) -> Dict:
        """Create a VPN user"""
        try:
            user_data = {
                'username': user.username,
                'password': user.password,
                'email': user.email,
                'disabled': not user.enabled,
                'descr': user.description
            }
            
            async with self.session.post(
                f"{self.host}{self.endpoints['vpn_users']}",
                json=user_data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Created VPN user: {user.username}")
                    return result
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to create VPN user: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error creating VPN user: {e}")
            raise
    
    async def get_interface_statistics(self) -> Dict:
        """Get network interface statistics"""
        try:
            async with self.session.get(
                f"{self.host}{self.endpoints['interfaces']}"
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Failed to get interface stats: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error getting interface statistics: {e}")
            raise
    
    async def get_firewall_logs(self, limit: int = 100) -> Dict:
        """Get firewall logs"""
        try:
            params = {'limit': limit}
            async with self.session.get(
                f"{self.host}{self.endpoints['logs']}/firewall",
                params=params
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Failed to get firewall logs: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error getting firewall logs: {e}")
            raise
    
    async def apply_configuration(self) -> bool:
        """Apply pending firewall configuration changes"""
        try:
            async with self.session.post(
                f"{self.host}/api/v1/firewall/apply"
            ) as response:
                if response.status == 200:
                    logger.info("Applied firewall configuration changes")
                    return True
                else:
                    raise Exception(f"Failed to apply configuration: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error applying configuration: {e}")
            return False
    
    async def backup_configuration(self) -> str:
        """Backup pfSense configuration"""
        try:
            async with self.session.get(
                f"{self.host}/api/v1/diagnostics/config_history"
            ) as response:
                if response.status == 200:
                    backup_data = await response.text()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"pfsense_backup_{timestamp}.xml"
                    
                    with open(filename, 'w') as f:
                        f.write(backup_data)
                    
                    logger.info(f"Configuration backed up to {filename}")
                    return filename
                else:
                    raise Exception(f"Failed to backup configuration: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error backing up configuration: {e}")
            raise

class SecurityAutomation:
    """Security automation using pfSense API"""
    
    def __init__(self, pfsense_client: PfSenseAPIClient):
        self.pfsense = pfsense_client
        self.blocked_ips = set()
    
    async def emergency_block_ip(self, ip_address: str, reason: str = "Emergency security block") -> bool:
        """Emergency IP blocking with immediate application"""
        try:
            # Create blocking rule
            await self.pfsense.block_ip_address(ip_address, f"EMERGENCY: {reason}")
            
            # Apply configuration immediately
            await self.pfsense.apply_configuration()
            
            # Track blocked IP
            self.blocked_ips.add(ip_address)
            
            logger.warning(f"Emergency blocked IP {ip_address}: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to emergency block IP {ip_address}: {e}")
            return False
    
    async def bulk_block_ips(self, ip_list: List[str], reason: str = "Bulk security block") -> int:
        """Block multiple IPs efficiently using aliases"""
        try:
            # Create alias for bulk blocking
            alias_name = f"bulk_block_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            await self.pfsense.create_alias(
                name=alias_name,
                alias_type="network",
                addresses=ip_list,
                description=f"Bulk block: {reason}"
            )
            
            # Create single rule to block the alias
            rule = FirewallRule(
                interface='wan',
                action='block',
                protocol='any',
                source=alias_name,
                destination='any',
                description=f"Bulk block rule: {reason}",
                log=True
            )
            
            await self.pfsense.create_firewall_rule(rule)
            await self.pfsense.apply_configuration()
            
            # Track blocked IPs
            self.blocked_ips.update(ip_list)
            
            logger.info(f"Bulk blocked {len(ip_list)} IPs using alias {alias_name}")
            return len(ip_list)
            
        except Exception as e:
            logger.error(f"Failed to bulk block IPs: {e}")
            return 0
    
    async def auto_unblock_expired(self, expiry_hours: int = 24) -> int:
        """Automatically unblock IPs after expiry period"""
        try:
            # This would typically check a database or cache for expiry times
            # For now, we'll implement a simple time-based check
            
            rules = await self.pfsense.get_firewall_rules()
            expired_rules = []
            
            for rule in rules.get('data', []):
                if (rule.get('type') == 'block' and 
                    'Auto-blocked' in rule.get('descr', '')):
                    # Check if rule is older than expiry_hours
                    # This would need to be implemented based on rule creation time
                    # For now, we'll skip the actual implementation
                    pass
            
            # Unblock expired IPs
            unblocked_count = 0
            for rule_id in expired_rules:
                if await self.pfsense.delete_firewall_rule(rule_id):
                    unblocked_count += 1
            
            if unblocked_count > 0:
                await self.pfsense.apply_configuration()
                logger.info(f"Auto-unblocked {unblocked_count} expired IPs")
            
            return unblocked_count
            
        except Exception as e:
            logger.error(f"Error in auto-unblock: {e}")
            return 0

async def main():
    """Example usage of pfSense API client"""
    config = {
        'host': 'https://firewall.enterprise.com',
        'username': 'admin',
        'password': 'your_password',
        'verify_ssl': True
    }
    
    async with PfSenseAPIClient(**config) as pfsense:
        # Get system information
        system_info = await pfsense.get_system_info()
        print(f"pfSense Version: {system_info.get('data', {}).get('version')}")
        
        # Example: Block a malicious IP
        await pfsense.block_ip_address(
            '192.0.2.100', 
            'Blocked by security platform - malicious activity detected'
        )
        
        # Apply configuration
        await pfsense.apply_configuration()
        
        # Create security automation instance
        automation = SecurityAutomation(pfsense)
        
        # Example: Emergency block
        await automation.emergency_block_ip(
            '198.51.100.50',
            'Critical threat detected by AI engine'
        )

if __name__ == '__main__':
    asyncio.run(main())
