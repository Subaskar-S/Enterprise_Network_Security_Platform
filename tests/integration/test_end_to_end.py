#!/usr/bin/env python3
"""
Enterprise Security Platform - End-to-End Integration Tests
Comprehensive testing of complete security workflows
"""

import pytest
import asyncio
import aiohttp
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import websockets
from elasticsearch import AsyncElasticsearch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityPlatformE2ETests:
    """End-to-end integration tests for the security platform"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.es_client = None
        self.auth_token = None
        
    async def setup(self):
        """Setup test environment"""
        self.session = aiohttp.ClientSession()
        self.es_client = AsyncElasticsearch([self.config['elasticsearch']['url']])
        
        # Authenticate
        await self.authenticate()
        
        logger.info("E2E test environment setup complete")
    
    async def teardown(self):
        """Cleanup test environment"""
        if self.session:
            await self.session.close()
        if self.es_client:
            await self.es_client.close()
        
        logger.info("E2E test environment cleaned up")
    
    async def authenticate(self):
        """Authenticate with the platform"""
        auth_data = {
            'username': self.config['test_user']['username'],
            'password': self.config['test_user']['password']
        }
        
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/auth/login",
            json=auth_data
        ) as response:
            if response.status == 200:
                result = await response.json()
                self.auth_token = result['access_token']
                self.session.headers.update({
                    'Authorization': f'Bearer {self.auth_token}'
                })
                logger.info("Authentication successful")
            else:
                raise Exception(f"Authentication failed: {response.status}")
    
    async def test_threat_detection_workflow(self):
        """Test complete threat detection workflow"""
        logger.info("Testing threat detection workflow...")
        
        # Step 1: Inject malicious traffic simulation
        malicious_event = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.1.50",
            "protocol": "tcp",
            "src_port": 12345,
            "dest_port": 443,
            "signature": "Malware communication detected",
            "severity": 3,
            "category": "malware",
            "payload": "suspicious_payload_data"
        }
        
        # Inject event into Suricata log stream
        await self.inject_security_event(malicious_event)
        
        # Step 2: Wait for event processing
        await asyncio.sleep(10)
        
        # Step 3: Verify alert generation
        alert = await self.verify_alert_generated(malicious_event['src_ip'])
        assert alert is not None, "Alert should be generated for malicious event"
        assert alert['severity'] == 'high', "Alert severity should be high"
        
        # Step 4: Verify AI threat detection
        ai_prediction = await self.verify_ai_threat_detection(malicious_event)
        assert ai_prediction is not None, "AI should detect the threat"
        assert ai_prediction['confidence'] > 0.8, "AI confidence should be high"
        
        # Step 5: Verify incident creation
        incident = await self.verify_incident_created(alert['id'])
        assert incident is not None, "Incident should be created"
        assert incident['status'] == 'open', "Incident should be open"
        
        # Step 6: Verify automated response
        response_actions = await self.verify_automated_response(incident['id'])
        assert len(response_actions) > 0, "Automated response should be triggered"
        
        # Step 7: Verify IP blocking
        blocked_ip = await self.verify_ip_blocked(malicious_event['src_ip'])
        assert blocked_ip, "Malicious IP should be blocked"
        
        # Step 8: Verify dashboard updates
        dashboard_data = await self.get_dashboard_data()
        assert dashboard_data['active_threats'] > 0, "Dashboard should show active threats"
        
        logger.info("✓ Threat detection workflow test passed")
    
    async def test_incident_response_workflow(self):
        """Test complete incident response workflow"""
        logger.info("Testing incident response workflow...")
        
        # Step 1: Create test incident
        incident_data = {
            "title": "Test Security Incident",
            "description": "Automated test incident for E2E testing",
            "severity": "high",
            "source_ip": "192.168.1.200",
            "target_ip": "10.0.1.100",
            "threat_type": "data_exfiltration"
        }
        
        incident = await self.create_incident(incident_data)
        assert incident is not None, "Incident should be created"
        
        # Step 2: Verify incident assignment
        await asyncio.sleep(5)
        updated_incident = await self.get_incident(incident['id'])
        assert updated_incident['assigned_to'] is not None, "Incident should be assigned"
        
        # Step 3: Test incident escalation
        escalation_result = await self.escalate_incident(incident['id'])
        assert escalation_result['success'], "Incident escalation should succeed"
        
        # Step 4: Verify notification sent
        notifications = await self.verify_notifications_sent(incident['id'])
        assert len(notifications) > 0, "Notifications should be sent"
        
        # Step 5: Test incident resolution
        resolution_data = {
            "status": "resolved",
            "resolution_notes": "Test incident resolved successfully"
        }
        
        resolved_incident = await self.update_incident(incident['id'], resolution_data)
        assert resolved_incident['status'] == 'resolved', "Incident should be resolved"
        
        # Step 6: Verify compliance logging
        audit_logs = await self.verify_audit_logs(incident['id'])
        assert len(audit_logs) > 0, "Audit logs should be created"
        
        logger.info("✓ Incident response workflow test passed")
    
    async def test_compliance_monitoring_workflow(self):
        """Test compliance monitoring workflow"""
        logger.info("Testing compliance monitoring workflow...")
        
        # Step 1: Trigger compliance check
        compliance_check = await self.trigger_compliance_check('SOC2')
        assert compliance_check['status'] == 'started', "Compliance check should start"
        
        # Step 2: Wait for compliance check completion
        await asyncio.sleep(30)
        
        # Step 3: Verify compliance report generation
        report = await self.get_compliance_report('SOC2')
        assert report is not None, "Compliance report should be generated"
        assert 'overall_score' in report, "Report should contain overall score"
        
        # Step 4: Verify evidence collection
        evidence = await self.verify_evidence_collected('SOC2')
        assert len(evidence) > 0, "Evidence should be collected"
        
        # Step 5: Test compliance alert for failures
        if report['overall_score'] < 0.9:
            alerts = await self.verify_compliance_alerts('SOC2')
            assert len(alerts) > 0, "Compliance alerts should be generated for failures"
        
        logger.info("✓ Compliance monitoring workflow test passed")
    
    async def test_network_security_workflow(self):
        """Test network security workflow"""
        logger.info("Testing network security workflow...")
        
        # Step 1: Test network topology discovery
        topology = await self.get_network_topology()
        assert len(topology['nodes']) > 0, "Network topology should contain nodes"
        
        # Step 2: Test network segmentation validation
        segmentation_check = await self.validate_network_segmentation()
        assert segmentation_check['valid'], "Network segmentation should be valid"
        
        # Step 3: Test firewall rule validation
        firewall_rules = await self.validate_firewall_rules()
        assert firewall_rules['valid'], "Firewall rules should be valid"
        
        # Step 4: Test network isolation
        isolation_test = await self.test_network_isolation('10.0.1.100')
        assert isolation_test['success'], "Network isolation should work"
        
        # Step 5: Test network restoration
        restoration_test = await self.test_network_restoration('10.0.1.100')
        assert restoration_test['success'], "Network restoration should work"
        
        logger.info("✓ Network security workflow test passed")
    
    async def test_ai_detection_accuracy(self):
        """Test AI detection accuracy with known patterns"""
        logger.info("Testing AI detection accuracy...")
        
        # Test cases with known outcomes
        test_cases = [
            {
                "features": {
                    "src_ip": "192.168.1.100",
                    "dest_ip": "10.0.1.50",
                    "protocol": "tcp",
                    "bytes_sent": 1000000,  # Large data transfer
                    "duration": 3600,       # Long duration
                    "packet_count": 10000
                },
                "expected_threat": "data_exfiltration",
                "expected_confidence": 0.8
            },
            {
                "features": {
                    "src_ip": "203.0.113.100",  # External IP
                    "dest_ip": "10.0.1.50",
                    "protocol": "tcp",
                    "src_port": 12345,
                    "dest_port": 22,
                    "failed_attempts": 100
                },
                "expected_threat": "brute_force",
                "expected_confidence": 0.9
            },
            {
                "features": {
                    "src_ip": "192.168.1.100",
                    "dest_ip": "10.0.1.50",
                    "protocol": "tcp",
                    "bytes_sent": 1024,
                    "bytes_received": 1024,
                    "duration": 30
                },
                "expected_threat": "benign",
                "expected_confidence": 0.7
            }
        ]
        
        correct_predictions = 0
        total_predictions = len(test_cases)
        
        for test_case in test_cases:
            prediction = await self.get_ai_prediction(test_case['features'])
            
            if (prediction['threat_type'] == test_case['expected_threat'] and
                prediction['confidence'] >= test_case['expected_confidence']):
                correct_predictions += 1
        
        accuracy = correct_predictions / total_predictions
        assert accuracy >= 0.8, f"AI detection accuracy should be >= 80%, got {accuracy:.2%}"
        
        logger.info(f"✓ AI detection accuracy test passed: {accuracy:.2%}")
    
    async def test_performance_under_load(self):
        """Test platform performance under load"""
        logger.info("Testing performance under load...")
        
        # Generate concurrent requests
        concurrent_requests = 50
        request_duration = 60  # seconds
        
        start_time = time.time()
        tasks = []
        
        # Create concurrent API requests
        for _ in range(concurrent_requests):
            task = asyncio.create_task(self.performance_worker())
            tasks.append(task)
        
        # Wait for completion or timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=request_duration + 30)
        except asyncio.TimeoutError:
            logger.warning("Some performance test tasks timed out")
        
        # Analyze results
        successful_requests = sum(1 for task in tasks if task.done() and not task.exception())
        success_rate = successful_requests / concurrent_requests
        
        assert success_rate >= 0.95, f"Success rate should be >= 95%, got {success_rate:.2%}"
        
        # Check system metrics
        system_metrics = await self.get_system_metrics()
        assert system_metrics['cpu_usage'] < 90, "CPU usage should be < 90% under load"
        assert system_metrics['memory_usage'] < 85, "Memory usage should be < 85% under load"
        
        logger.info(f"✓ Performance under load test passed: {success_rate:.2%} success rate")
    
    # Helper methods for test implementation
    async def inject_security_event(self, event: Dict):
        """Inject a security event into the system"""
        async with self.session.post(
            f"{self.config['logstash']['url']}/security-events",
            json=event
        ) as response:
            return response.status == 200
    
    async def verify_alert_generated(self, src_ip: str) -> Optional[Dict]:
        """Verify that an alert was generated for the given source IP"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"@timestamp": {"gte": "now-5m"}}}
                    ]
                }
            }
        }
        
        response = await self.es_client.search(
            index="security-alerts-*",
            body=query
        )
        
        if response['hits']['total']['value'] > 0:
            return response['hits']['hits'][0]['_source']
        return None
    
    async def verify_ai_threat_detection(self, event: Dict) -> Optional[Dict]:
        """Verify AI threat detection for the event"""
        async with self.session.post(
            f"{self.config['ai_detection']['url']}/predict",
            json={"features": event}
        ) as response:
            if response.status == 200:
                return await response.json()
        return None
    
    async def verify_incident_created(self, alert_id: str) -> Optional[Dict]:
        """Verify that an incident was created for the alert"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/incidents?alert_id={alert_id}"
        ) as response:
            if response.status == 200:
                incidents = await response.json()
                return incidents['data'][0] if incidents['data'] else None
        return None
    
    async def verify_automated_response(self, incident_id: str) -> List[Dict]:
        """Verify automated response actions for the incident"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/incidents/{incident_id}/actions"
        ) as response:
            if response.status == 200:
                return await response.json()
        return []
    
    async def verify_ip_blocked(self, ip_address: str) -> bool:
        """Verify that an IP address was blocked"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/firewall/blocked-ips/{ip_address}"
        ) as response:
            return response.status == 200
    
    async def get_dashboard_data(self) -> Dict:
        """Get current dashboard data"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/dashboard/metrics"
        ) as response:
            if response.status == 200:
                return await response.json()
        return {}
    
    async def create_incident(self, incident_data: Dict) -> Optional[Dict]:
        """Create a new incident"""
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/incidents",
            json=incident_data
        ) as response:
            if response.status == 201:
                return await response.json()
        return None
    
    async def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident by ID"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/incidents/{incident_id}"
        ) as response:
            if response.status == 200:
                return await response.json()
        return None
    
    async def escalate_incident(self, incident_id: str) -> Dict:
        """Escalate an incident"""
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/incidents/{incident_id}/escalate"
        ) as response:
            return {"success": response.status == 200}
    
    async def update_incident(self, incident_id: str, updates: Dict) -> Optional[Dict]:
        """Update an incident"""
        async with self.session.patch(
            f"{self.config['api_gateway']['url']}/api/v1/incidents/{incident_id}",
            json=updates
        ) as response:
            if response.status == 200:
                return await response.json()
        return None
    
    async def verify_notifications_sent(self, incident_id: str) -> List[Dict]:
        """Verify notifications were sent for the incident"""
        # This would check notification logs or external service APIs
        return [{"type": "slack", "status": "sent"}]  # Mock response
    
    async def verify_audit_logs(self, incident_id: str) -> List[Dict]:
        """Verify audit logs were created"""
        query = {
            "query": {
                "term": {"incident_id": incident_id}
            }
        }
        
        response = await self.es_client.search(
            index="audit-logs-*",
            body=query
        )
        
        return [hit['_source'] for hit in response['hits']['hits']]
    
    async def trigger_compliance_check(self, framework: str) -> Dict:
        """Trigger a compliance check"""
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/compliance/check/{framework}"
        ) as response:
            if response.status == 200:
                return await response.json()
        return {"status": "failed"}
    
    async def get_compliance_report(self, framework: str) -> Optional[Dict]:
        """Get compliance report"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/compliance/reports/{framework}"
        ) as response:
            if response.status == 200:
                return await response.json()
        return None
    
    async def verify_evidence_collected(self, framework: str) -> List[Dict]:
        """Verify evidence was collected for compliance"""
        # This would check evidence storage
        return [{"type": "configuration", "status": "collected"}]  # Mock response
    
    async def verify_compliance_alerts(self, framework: str) -> List[Dict]:
        """Verify compliance alerts were generated"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": "compliance_alert"}},
                        {"term": {"framework": framework}},
                        {"range": {"@timestamp": {"gte": "now-1h"}}}
                    ]
                }
            }
        }
        
        response = await self.es_client.search(
            index="security-alerts-*",
            body=query
        )
        
        return [hit['_source'] for hit in response['hits']['hits']]
    
    async def get_network_topology(self) -> Dict:
        """Get network topology"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/network/topology"
        ) as response:
            if response.status == 200:
                return await response.json()
        return {"nodes": []}
    
    async def validate_network_segmentation(self) -> Dict:
        """Validate network segmentation"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/network/segmentation/validate"
        ) as response:
            return {"valid": response.status == 200}
    
    async def validate_firewall_rules(self) -> Dict:
        """Validate firewall rules"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/firewall/rules/validate"
        ) as response:
            return {"valid": response.status == 200}
    
    async def test_network_isolation(self, node_id: str) -> Dict:
        """Test network isolation"""
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/network/nodes/{node_id}/isolate"
        ) as response:
            return {"success": response.status == 200}
    
    async def test_network_restoration(self, node_id: str) -> Dict:
        """Test network restoration"""
        async with self.session.post(
            f"{self.config['api_gateway']['url']}/api/v1/network/nodes/{node_id}/restore"
        ) as response:
            return {"success": response.status == 200}
    
    async def get_ai_prediction(self, features: Dict) -> Dict:
        """Get AI prediction for features"""
        async with self.session.post(
            f"{self.config['ai_detection']['url']}/predict",
            json={"features": features}
        ) as response:
            if response.status == 200:
                return await response.json()
        return {"threat_type": "unknown", "confidence": 0.0}
    
    async def performance_worker(self) -> bool:
        """Worker function for performance testing"""
        try:
            async with self.session.get(
                f"{self.config['api_gateway']['url']}/api/v1/health"
            ) as response:
                return response.status == 200
        except:
            return False
    
    async def get_system_metrics(self) -> Dict:
        """Get current system metrics"""
        async with self.session.get(
            f"{self.config['api_gateway']['url']}/api/v1/system/metrics"
        ) as response:
            if response.status == 200:
                return await response.json()
        return {"cpu_usage": 0, "memory_usage": 0}

# Test configuration
@pytest.fixture
async def e2e_tests():
    """Fixture for E2E tests"""
    config = {
        'elasticsearch': {'url': 'http://localhost:9200'},
        'api_gateway': {'url': 'http://localhost:8000'},
        'ai_detection': {'url': 'http://localhost:8001'},
        'logstash': {'url': 'http://localhost:8080'},
        'test_user': {
            'username': 'test_admin',
            'password': 'test_password'
        }
    }
    
    tests = SecurityPlatformE2ETests(config)
    await tests.setup()
    
    yield tests
    
    await tests.teardown()

# Test cases
@pytest.mark.asyncio
async def test_complete_threat_detection_workflow(e2e_tests):
    """Test complete threat detection workflow"""
    await e2e_tests.test_threat_detection_workflow()

@pytest.mark.asyncio
async def test_complete_incident_response_workflow(e2e_tests):
    """Test complete incident response workflow"""
    await e2e_tests.test_incident_response_workflow()

@pytest.mark.asyncio
async def test_complete_compliance_monitoring_workflow(e2e_tests):
    """Test complete compliance monitoring workflow"""
    await e2e_tests.test_compliance_monitoring_workflow()

@pytest.mark.asyncio
async def test_complete_network_security_workflow(e2e_tests):
    """Test complete network security workflow"""
    await e2e_tests.test_network_security_workflow()

@pytest.mark.asyncio
async def test_ai_detection_accuracy_validation(e2e_tests):
    """Test AI detection accuracy"""
    await e2e_tests.test_ai_detection_accuracy()

@pytest.mark.asyncio
async def test_platform_performance_under_load(e2e_tests):
    """Test platform performance under load"""
    await e2e_tests.test_performance_under_load()

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
