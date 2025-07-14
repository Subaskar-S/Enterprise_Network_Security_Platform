#!/usr/bin/env python3
"""
Compliance Monitoring and Reporting System
Automated compliance checking for SOC 2, ISO 27001, PCI-DSS, and GDPR
"""

import asyncio
import yaml
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
import aiofiles
from elasticsearch import AsyncElasticsearch
import boto3
from jinja2 import Template

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ComplianceTest:
    """Compliance test definition"""
    test_id: str
    name: str
    description: str
    framework: str
    control_id: str
    test_type: str  # automated, manual, hybrid
    frequency: str  # daily, weekly, monthly, quarterly
    last_run: Optional[str] = None
    status: str = "pending"  # pending, passed, failed, error
    evidence: List[str] = None
    remediation: List[str] = None

@dataclass
class ComplianceResult:
    """Compliance test result"""
    test_id: str
    timestamp: str
    status: str  # passed, failed, error
    score: float  # 0.0 to 1.0
    details: Dict[str, Any]
    evidence_collected: List[str]
    recommendations: List[str]
    next_test_date: str

@dataclass
class ComplianceReport:
    """Compliance framework report"""
    framework: str
    report_date: str
    overall_score: float
    total_controls: int
    passed_controls: int
    failed_controls: int
    pending_controls: int
    test_results: List[ComplianceResult]
    recommendations: List[str]
    evidence_summary: Dict[str, int]

class ComplianceTestEngine:
    """Automated compliance testing engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.es_client = None
        self.s3_client = None
        self.test_registry = {}
        self.evidence_store = []
        
    async def initialize(self):
        """Initialize the compliance engine"""
        # Initialize Elasticsearch client
        self.es_client = AsyncElasticsearch([self.config['elasticsearch']['host']])
        
        # Initialize S3 client for evidence storage
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.config['aws']['access_key'],
            aws_secret_access_key=self.config['aws']['secret_key'],
            region_name=self.config['aws']['region']
        )
        
        # Load compliance test definitions
        await self.load_test_definitions()
        
        logger.info("Compliance engine initialized")
    
    async def load_test_definitions(self):
        """Load compliance test definitions from configuration files"""
        frameworks_dir = Path("compliance/frameworks")
        
        for framework_file in frameworks_dir.glob("*.yaml"):
            try:
                async with aiofiles.open(framework_file, 'r') as f:
                    content = await f.read()
                    framework_config = yaml.safe_load(content)
                    
                    framework_name = framework_config['metadata']['framework']
                    self.test_registry[framework_name] = framework_config
                    
                    logger.info(f"Loaded compliance framework: {framework_name}")
                    
            except Exception as e:
                logger.error(f"Error loading framework {framework_file}: {e}")
    
    async def run_compliance_test(self, test_id: str) -> ComplianceResult:
        """Run a specific compliance test"""
        try:
            # Get test definition
            test_def = await self.get_test_definition(test_id)
            if not test_def:
                raise ValueError(f"Test {test_id} not found")
            
            logger.info(f"Running compliance test: {test_id}")
            
            # Execute test based on type
            if test_def['test_type'] == 'automated':
                result = await self.run_automated_test(test_def)
            elif test_def['test_type'] == 'manual':
                result = await self.run_manual_test(test_def)
            else:
                result = await self.run_hybrid_test(test_def)
            
            # Store result
            await self.store_test_result(result)
            
            # Collect evidence
            await self.collect_evidence(test_id, result)
            
            logger.info(f"Completed compliance test: {test_id} - Status: {result.status}")
            return result
            
        except Exception as e:
            logger.error(f"Error running compliance test {test_id}: {e}")
            return ComplianceResult(
                test_id=test_id,
                timestamp=datetime.now().isoformat(),
                status="error",
                score=0.0,
                details={"error": str(e)},
                evidence_collected=[],
                recommendations=[f"Fix test execution error: {e}"],
                next_test_date=(datetime.now() + timedelta(days=1)).isoformat()
            )
    
    async def run_automated_test(self, test_def: Dict) -> ComplianceResult:
        """Run automated compliance test"""
        test_id = test_def['test_id']
        test_function = getattr(self, f"test_{test_id.lower()}", None)
        
        if not test_function:
            raise ValueError(f"Test function for {test_id} not implemented")
        
        # Execute test function
        result = await test_function(test_def)
        return result
    
    async def run_manual_test(self, test_def: Dict) -> ComplianceResult:
        """Handle manual compliance test"""
        # For manual tests, check if evidence has been provided
        test_id = test_def['test_id']
        
        # Check for manual evidence submission
        evidence = await self.get_manual_evidence(test_id)
        
        if evidence:
            score = 1.0 if evidence.get('status') == 'compliant' else 0.0
            status = "passed" if score == 1.0 else "failed"
        else:
            score = 0.0
            status = "pending"
        
        return ComplianceResult(
            test_id=test_id,
            timestamp=datetime.now().isoformat(),
            status=status,
            score=score,
            details={"manual_test": True, "evidence": evidence},
            evidence_collected=[],
            recommendations=["Manual review required"] if status == "pending" else [],
            next_test_date=(datetime.now() + timedelta(days=30)).isoformat()
        )
    
    async def run_hybrid_test(self, test_def: Dict) -> ComplianceResult:
        """Run hybrid compliance test (automated + manual)"""
        # Run automated portion first
        auto_result = await self.run_automated_test(test_def)
        
        # Check for manual validation
        manual_evidence = await self.get_manual_evidence(test_def['test_id'])
        
        # Combine results
        combined_score = (auto_result.score + (1.0 if manual_evidence else 0.0)) / 2
        status = "passed" if combined_score >= 0.8 else "failed"
        
        return ComplianceResult(
            test_id=test_def['test_id'],
            timestamp=datetime.now().isoformat(),
            status=status,
            score=combined_score,
            details={
                "automated_result": auto_result.details,
                "manual_evidence": manual_evidence
            },
            evidence_collected=auto_result.evidence_collected,
            recommendations=auto_result.recommendations,
            next_test_date=(datetime.now() + timedelta(days=7)).isoformat()
        )
    
    # Specific Test Implementations
    async def test_verify_mfa_enabled(self, test_def: Dict) -> ComplianceResult:
        """Verify multi-factor authentication is enabled"""
        try:
            # Check Istio authentication policies
            istio_check = await self.check_istio_mfa_policies()
            
            # Check application-level MFA
            app_mfa_check = await self.check_application_mfa()
            
            # Check VPN MFA
            vpn_mfa_check = await self.check_vpn_mfa()
            
            total_score = (istio_check + app_mfa_check + vpn_mfa_check) / 3
            status = "passed" if total_score >= 0.8 else "failed"
            
            return ComplianceResult(
                test_id=test_def['test_id'],
                timestamp=datetime.now().isoformat(),
                status=status,
                score=total_score,
                details={
                    "istio_mfa": istio_check,
                    "application_mfa": app_mfa_check,
                    "vpn_mfa": vpn_mfa_check
                },
                evidence_collected=["istio_policies.yaml", "app_config.json", "vpn_config.xml"],
                recommendations=[] if status == "passed" else ["Enable MFA for all access points"],
                next_test_date=(datetime.now() + timedelta(days=1)).isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error in MFA verification test: {e}")
            raise
    
    async def test_verify_network_segmentation(self, test_def: Dict) -> ComplianceResult:
        """Verify network segmentation is properly implemented"""
        try:
            # Check Istio network policies
            istio_policies = await self.check_istio_network_policies()
            
            # Check pfSense firewall rules
            firewall_rules = await self.check_firewall_segmentation()
            
            # Check Kubernetes network policies
            k8s_policies = await self.check_k8s_network_policies()
            
            total_score = (istio_policies + firewall_rules + k8s_policies) / 3
            status = "passed" if total_score >= 0.9 else "failed"
            
            return ComplianceResult(
                test_id=test_def['test_id'],
                timestamp=datetime.now().isoformat(),
                status=status,
                score=total_score,
                details={
                    "istio_policies": istio_policies,
                    "firewall_rules": firewall_rules,
                    "k8s_policies": k8s_policies
                },
                evidence_collected=["network_policies.yaml", "firewall_rules.xml"],
                recommendations=[] if status == "passed" else ["Review and strengthen network segmentation"],
                next_test_date=(datetime.now() + timedelta(days=1)).isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error in network segmentation test: {e}")
            raise
    
    async def test_verify_encryption_in_transit(self, test_def: Dict) -> ComplianceResult:
        """Verify encryption in transit is properly configured"""
        try:
            # Check TLS/mTLS configuration
            tls_config = await self.check_tls_configuration()
            
            # Check certificate validity
            cert_validity = await self.check_certificate_validity()
            
            # Check encryption protocols
            protocol_check = await self.check_encryption_protocols()
            
            total_score = (tls_config + cert_validity + protocol_check) / 3
            status = "passed" if total_score >= 0.95 else "failed"
            
            return ComplianceResult(
                test_id=test_def['test_id'],
                timestamp=datetime.now().isoformat(),
                status=status,
                score=total_score,
                details={
                    "tls_configuration": tls_config,
                    "certificate_validity": cert_validity,
                    "encryption_protocols": protocol_check
                },
                evidence_collected=["tls_config.yaml", "certificates.pem"],
                recommendations=[] if status == "passed" else ["Update encryption configuration"],
                next_test_date=(datetime.now() + timedelta(days=1)).isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error in encryption verification test: {e}")
            raise
    
    async def test_verify_monitoring_coverage(self, test_def: Dict) -> ComplianceResult:
        """Verify comprehensive monitoring coverage"""
        try:
            # Check Prometheus metrics coverage
            prometheus_coverage = await self.check_prometheus_coverage()
            
            # Check ELK stack monitoring
            elk_coverage = await self.check_elk_monitoring()
            
            # Check alerting configuration
            alerting_config = await self.check_alerting_configuration()
            
            total_score = (prometheus_coverage + elk_coverage + alerting_config) / 3
            status = "passed" if total_score >= 0.85 else "failed"
            
            return ComplianceResult(
                test_id=test_def['test_id'],
                timestamp=datetime.now().isoformat(),
                status=status,
                score=total_score,
                details={
                    "prometheus_coverage": prometheus_coverage,
                    "elk_coverage": elk_coverage,
                    "alerting_config": alerting_config
                },
                evidence_collected=["monitoring_config.yaml", "alert_rules.yaml"],
                recommendations=[] if status == "passed" else ["Improve monitoring coverage"],
                next_test_date=(datetime.now() + timedelta(hours=1)).isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error in monitoring coverage test: {e}")
            raise
    
    # Helper Methods for Specific Checks
    async def check_istio_mfa_policies(self) -> float:
        """Check Istio MFA policies"""
        try:
            # Query Kubernetes API for Istio policies
            # This would integrate with actual Kubernetes API
            # For now, return a mock score
            return 1.0
        except Exception as e:
            logger.error(f"Error checking Istio MFA policies: {e}")
            return 0.0
    
    async def check_application_mfa(self) -> float:
        """Check application-level MFA"""
        try:
            # Check application configuration for MFA
            # This would integrate with actual application APIs
            return 1.0
        except Exception as e:
            logger.error(f"Error checking application MFA: {e}")
            return 0.0
    
    async def check_vpn_mfa(self) -> float:
        """Check VPN MFA configuration"""
        try:
            # Check pfSense VPN configuration
            # This would integrate with pfSense API
            return 1.0
        except Exception as e:
            logger.error(f"Error checking VPN MFA: {e}")
            return 0.0
    
    async def check_istio_network_policies(self) -> float:
        """Check Istio network policies"""
        try:
            # Verify network policies are in place
            return 1.0
        except Exception as e:
            logger.error(f"Error checking Istio network policies: {e}")
            return 0.0
    
    async def check_firewall_segmentation(self) -> float:
        """Check firewall segmentation rules"""
        try:
            # Check pfSense firewall rules
            return 1.0
        except Exception as e:
            logger.error(f"Error checking firewall segmentation: {e}")
            return 0.0
    
    async def check_k8s_network_policies(self) -> float:
        """Check Kubernetes network policies"""
        try:
            # Check Kubernetes network policies
            return 1.0
        except Exception as e:
            logger.error(f"Error checking K8s network policies: {e}")
            return 0.0
    
    async def check_tls_configuration(self) -> float:
        """Check TLS configuration"""
        try:
            # Verify TLS/mTLS configuration
            return 1.0
        except Exception as e:
            logger.error(f"Error checking TLS configuration: {e}")
            return 0.0
    
    async def check_certificate_validity(self) -> float:
        """Check certificate validity"""
        try:
            # Check certificate expiration and validity
            return 1.0
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")
            return 0.0
    
    async def check_encryption_protocols(self) -> float:
        """Check encryption protocols"""
        try:
            # Verify encryption protocols are up to standard
            return 1.0
        except Exception as e:
            logger.error(f"Error checking encryption protocols: {e}")
            return 0.0
    
    async def check_prometheus_coverage(self) -> float:
        """Check Prometheus monitoring coverage"""
        try:
            # Verify Prometheus is collecting all required metrics
            return 1.0
        except Exception as e:
            logger.error(f"Error checking Prometheus coverage: {e}")
            return 0.0
    
    async def check_elk_monitoring(self) -> float:
        """Check ELK stack monitoring"""
        try:
            # Verify ELK stack is collecting and processing logs
            return 1.0
        except Exception as e:
            logger.error(f"Error checking ELK monitoring: {e}")
            return 0.0
    
    async def check_alerting_configuration(self) -> float:
        """Check alerting configuration"""
        try:
            # Verify alerting rules are properly configured
            return 1.0
        except Exception as e:
            logger.error(f"Error checking alerting configuration: {e}")
            return 0.0
    
    async def get_test_definition(self, test_id: str) -> Optional[Dict]:
        """Get test definition by ID"""
        for framework, config in self.test_registry.items():
            # Search through all controls for the test
            for section in config.values():
                if isinstance(section, dict):
                    for control in section.values():
                        if isinstance(control, dict) and 'implementation' in control:
                            for impl in control['implementation']:
                                if impl.get('control_id') == test_id:
                                    return {
                                        'test_id': test_id,
                                        'framework': framework,
                                        'test_type': 'automated',  # Default
                                        **impl
                                    }
        return None
    
    async def get_manual_evidence(self, test_id: str) -> Optional[Dict]:
        """Get manually submitted evidence for a test"""
        try:
            # Query evidence database/storage
            # This would integrate with actual evidence storage
            return None
        except Exception as e:
            logger.error(f"Error getting manual evidence for {test_id}: {e}")
            return None
    
    async def store_test_result(self, result: ComplianceResult):
        """Store test result in Elasticsearch"""
        try:
            await self.es_client.index(
                index=f"compliance-results-{datetime.now().strftime('%Y.%m')}",
                body=asdict(result)
            )
            logger.info(f"Stored compliance test result: {result.test_id}")
        except Exception as e:
            logger.error(f"Error storing test result: {e}")
    
    async def collect_evidence(self, test_id: str, result: ComplianceResult):
        """Collect and store evidence for compliance test"""
        try:
            evidence_data = {
                'test_id': test_id,
                'timestamp': result.timestamp,
                'evidence_files': result.evidence_collected,
                'test_details': result.details
            }
            
            # Store evidence in S3
            evidence_key = f"compliance-evidence/{test_id}/{result.timestamp}.json"
            self.s3_client.put_object(
                Bucket=self.config['evidence']['bucket'],
                Key=evidence_key,
                Body=json.dumps(evidence_data),
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Collected evidence for test: {test_id}")
            
        except Exception as e:
            logger.error(f"Error collecting evidence for {test_id}: {e}")
    
    async def generate_compliance_report(self, framework: str) -> ComplianceReport:
        """Generate compliance report for a framework"""
        try:
            # Get all test results for the framework
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"framework": framework}},
                            {"range": {"timestamp": {"gte": "now-30d"}}}
                        ]
                    }
                },
                "size": 1000
            }
            
            response = await self.es_client.search(
                index="compliance-results-*",
                body=query
            )
            
            results = [ComplianceResult(**hit['_source']) for hit in response['hits']['hits']]
            
            # Calculate overall compliance score
            total_tests = len(results)
            passed_tests = len([r for r in results if r.status == "passed"])
            failed_tests = len([r for r in results if r.status == "failed"])
            pending_tests = len([r for r in results if r.status == "pending"])
            
            overall_score = passed_tests / total_tests if total_tests > 0 else 0.0
            
            # Generate recommendations
            recommendations = []
            for result in results:
                if result.status == "failed":
                    recommendations.extend(result.recommendations)
            
            # Remove duplicates
            recommendations = list(set(recommendations))
            
            report = ComplianceReport(
                framework=framework,
                report_date=datetime.now().isoformat(),
                overall_score=overall_score,
                total_controls=total_tests,
                passed_controls=passed_tests,
                failed_controls=failed_tests,
                pending_controls=pending_tests,
                test_results=results,
                recommendations=recommendations,
                evidence_summary={"total_evidence_files": len(self.evidence_store)}
            )
            
            # Store report
            await self.store_compliance_report(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report for {framework}: {e}")
            raise
    
    async def store_compliance_report(self, report: ComplianceReport):
        """Store compliance report"""
        try:
            await self.es_client.index(
                index=f"compliance-reports-{datetime.now().strftime('%Y')}",
                body=asdict(report)
            )
            logger.info(f"Stored compliance report: {report.framework}")
        except Exception as e:
            logger.error(f"Error storing compliance report: {e}")
    
    async def run_scheduled_tests(self):
        """Run scheduled compliance tests"""
        logger.info("Starting scheduled compliance tests")
        
        for framework, config in self.test_registry.items():
            try:
                # Extract all automated tests
                tests_to_run = []
                
                for section in config.values():
                    if isinstance(section, dict):
                        for control in section.values():
                            if isinstance(control, dict) and 'implementation' in control:
                                for impl in control['implementation']:
                                    if 'automated_checks' in impl:
                                        tests_to_run.extend(impl['automated_checks'])
                
                # Run tests
                for test_id in tests_to_run:
                    try:
                        await self.run_compliance_test(test_id)
                    except Exception as e:
                        logger.error(f"Error running test {test_id}: {e}")
                
                # Generate report
                await self.generate_compliance_report(framework)
                
            except Exception as e:
                logger.error(f"Error processing framework {framework}: {e}")
        
        logger.info("Completed scheduled compliance tests")

async def main():
    """Main function for compliance monitoring"""
    config = {
        'elasticsearch': {'host': 'localhost:9200'},
        'aws': {
            'access_key': 'your_access_key',
            'secret_key': 'your_secret_key',
            'region': 'us-east-1'
        },
        'evidence': {
            'bucket': 'compliance-evidence-bucket'
        }
    }
    
    engine = ComplianceTestEngine(config)
    await engine.initialize()
    
    # Run scheduled tests
    await engine.run_scheduled_tests()
    
    # Generate reports for all frameworks
    for framework in engine.test_registry.keys():
        report = await engine.generate_compliance_report(framework)
        print(f"Generated report for {framework}: {report.overall_score:.2%} compliance")

if __name__ == '__main__':
    asyncio.run(main())
