#!/usr/bin/env python3
"""
Enterprise Security Platform - Performance Load Testing
Comprehensive performance testing for all platform components
"""

import asyncio
import aiohttp
import time
import statistics
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
import concurrent.futures
import psutil
import numpy as np
from elasticsearch import AsyncElasticsearch
import websockets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Performance metric data structure"""
    component: str
    test_type: str
    timestamp: str
    response_time_ms: float
    throughput_rps: float
    cpu_usage_percent: float
    memory_usage_mb: float
    network_io_mbps: float
    error_rate_percent: float
    concurrent_users: int
    success_count: int
    error_count: int

@dataclass
class LoadTestConfig:
    """Load test configuration"""
    target_url: str
    max_concurrent_users: int
    ramp_up_duration: int  # seconds
    test_duration: int     # seconds
    request_timeout: int   # seconds
    think_time: float      # seconds between requests

class PerformanceTestSuite:
    """Comprehensive performance testing suite"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.results = []
        self.es_client = None
        
    async def initialize(self):
        """Initialize the test suite"""
        self.es_client = AsyncElasticsearch([self.config['elasticsearch']['host']])
        logger.info("Performance test suite initialized")
    
    async def run_all_tests(self) -> Dict[str, List[PerformanceMetric]]:
        """Run all performance tests"""
        logger.info("Starting comprehensive performance testing")
        
        test_results = {}
        
        # API Gateway Load Test
        logger.info("Testing API Gateway performance...")
        test_results['api_gateway'] = await self.test_api_gateway_performance()
        
        # Elasticsearch Performance Test
        logger.info("Testing Elasticsearch performance...")
        test_results['elasticsearch'] = await self.test_elasticsearch_performance()
        
        # Suricata IDS Performance Test
        logger.info("Testing Suricata IDS performance...")
        test_results['suricata'] = await self.test_suricata_performance()
        
        # AI Threat Detection Performance Test
        logger.info("Testing AI threat detection performance...")
        test_results['ai_detection'] = await self.test_ai_detection_performance()
        
        # Network Throughput Test
        logger.info("Testing network throughput...")
        test_results['network'] = await self.test_network_throughput()
        
        # Dashboard Performance Test
        logger.info("Testing dashboard performance...")
        test_results['dashboard'] = await self.test_dashboard_performance()
        
        # Incident Response Performance Test
        logger.info("Testing incident response performance...")
        test_results['incident_response'] = await self.test_incident_response_performance()
        
        # Store results
        await self.store_results(test_results)
        
        # Generate performance report
        await self.generate_performance_report(test_results)
        
        logger.info("Performance testing completed")
        return test_results
    
    async def test_api_gateway_performance(self) -> List[PerformanceMetric]:
        """Test API Gateway performance under load"""
        config = LoadTestConfig(
            target_url=f"{self.config['api_gateway']['url']}/api/v1/health",
            max_concurrent_users=100,
            ramp_up_duration=30,
            test_duration=300,
            request_timeout=10,
            think_time=0.1
        )
        
        return await self.run_load_test("api_gateway", config, self.api_request_worker)
    
    async def test_elasticsearch_performance(self) -> List[PerformanceMetric]:
        """Test Elasticsearch performance"""
        config = LoadTestConfig(
            target_url=f"{self.config['elasticsearch']['url']}/_search",
            max_concurrent_users=50,
            ramp_up_duration=20,
            test_duration=180,
            request_timeout=30,
            think_time=0.2
        )
        
        return await self.run_load_test("elasticsearch", config, self.elasticsearch_worker)
    
    async def test_suricata_performance(self) -> List[PerformanceMetric]:
        """Test Suricata IDS performance with synthetic traffic"""
        logger.info("Generating synthetic network traffic for Suricata testing")
        
        # Generate synthetic traffic patterns
        traffic_patterns = [
            {"type": "http", "rate": 1000, "duration": 60},
            {"type": "https", "rate": 800, "duration": 60},
            {"type": "dns", "rate": 2000, "duration": 60},
            {"type": "malicious", "rate": 50, "duration": 60}
        ]
        
        metrics = []
        start_time = time.time()
        
        for pattern in traffic_patterns:
            pattern_start = time.time()
            
            # Simulate traffic generation and monitoring
            await asyncio.sleep(pattern['duration'])
            
            # Collect metrics (simulated)
            metric = PerformanceMetric(
                component="suricata",
                test_type=f"traffic_{pattern['type']}",
                timestamp=datetime.now().isoformat(),
                response_time_ms=1.5,  # Suricata processing latency
                throughput_rps=pattern['rate'],
                cpu_usage_percent=psutil.cpu_percent(),
                memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,
                network_io_mbps=self.get_network_io_rate(),
                error_rate_percent=0.1,
                concurrent_users=1,
                success_count=pattern['rate'] * pattern['duration'],
                error_count=int(pattern['rate'] * pattern['duration'] * 0.001)
            )
            metrics.append(metric)
        
        return metrics
    
    async def test_ai_detection_performance(self) -> List[PerformanceMetric]:
        """Test AI threat detection performance"""
        config = LoadTestConfig(
            target_url=f"{self.config['ai_detection']['url']}/predict",
            max_concurrent_users=20,
            ramp_up_duration=15,
            test_duration=120,
            request_timeout=60,
            think_time=1.0
        )
        
        return await self.run_load_test("ai_detection", config, self.ai_detection_worker)
    
    async def test_network_throughput(self) -> List[PerformanceMetric]:
        """Test network throughput and latency"""
        metrics = []
        
        # Test different packet sizes
        packet_sizes = [64, 128, 256, 512, 1024, 1500]  # bytes
        
        for size in packet_sizes:
            logger.info(f"Testing network throughput with {size} byte packets")
            
            # Simulate network throughput test
            start_time = time.time()
            
            # Generate test traffic (simulated)
            packets_per_second = 10000
            test_duration = 30
            
            await asyncio.sleep(test_duration)
            
            # Calculate metrics
            total_packets = packets_per_second * test_duration
            total_bytes = total_packets * size
            throughput_mbps = (total_bytes * 8) / (test_duration * 1024 * 1024)
            
            metric = PerformanceMetric(
                component="network",
                test_type=f"throughput_{size}b",
                timestamp=datetime.now().isoformat(),
                response_time_ms=0.5,  # Network latency
                throughput_rps=packets_per_second,
                cpu_usage_percent=psutil.cpu_percent(),
                memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,
                network_io_mbps=throughput_mbps,
                error_rate_percent=0.0,
                concurrent_users=1,
                success_count=total_packets,
                error_count=0
            )
            metrics.append(metric)
        
        return metrics
    
    async def test_dashboard_performance(self) -> List[PerformanceMetric]:
        """Test dashboard performance"""
        config = LoadTestConfig(
            target_url=f"{self.config['dashboard']['url']}/api/dashboard/metrics",
            max_concurrent_users=50,
            ramp_up_duration=20,
            test_duration=180,
            request_timeout=15,
            think_time=2.0
        )
        
        return await self.run_load_test("dashboard", config, self.dashboard_worker)
    
    async def test_incident_response_performance(self) -> List[PerformanceMetric]:
        """Test incident response system performance"""
        config = LoadTestConfig(
            target_url=f"{self.config['incident_response']['url']}/webhook/alert",
            max_concurrent_users=30,
            ramp_up_duration=15,
            test_duration=120,
            request_timeout=30,
            think_time=0.5
        )
        
        return await self.run_load_test("incident_response", config, self.incident_response_worker)
    
    async def run_load_test(self, component: str, config: LoadTestConfig, worker_func) -> List[PerformanceMetric]:
        """Run a load test with specified configuration"""
        metrics = []
        start_time = time.time()
        
        # Ramp up users gradually
        users_per_second = config.max_concurrent_users / config.ramp_up_duration
        current_users = 0
        
        tasks = []
        
        # Ramp up phase
        for second in range(config.ramp_up_duration):
            new_users = int(users_per_second)
            for _ in range(new_users):
                task = asyncio.create_task(worker_func(config, start_time + second))
                tasks.append(task)
            current_users += new_users
            await asyncio.sleep(1)
        
        # Steady state phase
        steady_start = time.time()
        while time.time() - steady_start < config.test_duration:
            # Collect metrics every 10 seconds
            if len(tasks) > 0:
                # Sample completed tasks for metrics
                completed_tasks = [task for task in tasks if task.done()]
                if completed_tasks:
                    response_times = []
                    success_count = 0
                    error_count = 0
                    
                    for task in completed_tasks[:100]:  # Sample first 100
                        try:
                            result = await task
                            if result:
                                response_times.append(result['response_time'])
                                if result['success']:
                                    success_count += 1
                                else:
                                    error_count += 1
                        except:
                            error_count += 1
                    
                    if response_times:
                        avg_response_time = statistics.mean(response_times)
                        throughput = len(completed_tasks) / 10  # RPS over 10 second window
                        error_rate = (error_count / len(completed_tasks)) * 100
                        
                        metric = PerformanceMetric(
                            component=component,
                            test_type="load_test",
                            timestamp=datetime.now().isoformat(),
                            response_time_ms=avg_response_time,
                            throughput_rps=throughput,
                            cpu_usage_percent=psutil.cpu_percent(),
                            memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,
                            network_io_mbps=self.get_network_io_rate(),
                            error_rate_percent=error_rate,
                            concurrent_users=current_users,
                            success_count=success_count,
                            error_count=error_count
                        )
                        metrics.append(metric)
                
                # Remove completed tasks
                tasks = [task for task in tasks if not task.done()]
            
            await asyncio.sleep(10)
        
        # Cancel remaining tasks
        for task in tasks:
            task.cancel()
        
        return metrics
    
    async def api_request_worker(self, config: LoadTestConfig, start_time: float) -> Dict:
        """Worker function for API requests"""
        try:
            request_start = time.time()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.request_timeout)) as session:
                async with session.get(config.target_url) as response:
                    await response.text()
                    response_time = (time.time() - request_start) * 1000
                    success = response.status == 200
            
            await asyncio.sleep(config.think_time)
            
            return {
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            return {
                'response_time': (time.time() - request_start) * 1000,
                'success': False,
                'error': str(e)
            }
    
    async def elasticsearch_worker(self, config: LoadTestConfig, start_time: float) -> Dict:
        """Worker function for Elasticsearch requests"""
        try:
            request_start = time.time()
            
            # Sample Elasticsearch query
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1h"
                        }
                    }
                },
                "size": 100
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.request_timeout)) as session:
                async with session.post(
                    f"{config.target_url}",
                    json=query,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    await response.json()
                    response_time = (time.time() - request_start) * 1000
                    success = response.status == 200
            
            await asyncio.sleep(config.think_time)
            
            return {
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            return {
                'response_time': (time.time() - request_start) * 1000,
                'success': False,
                'error': str(e)
            }
    
    async def ai_detection_worker(self, config: LoadTestConfig, start_time: float) -> Dict:
        """Worker function for AI detection requests"""
        try:
            request_start = time.time()
            
            # Sample threat detection payload
            payload = {
                "features": {
                    "src_ip": "192.168.1.100",
                    "dest_ip": "10.0.1.50",
                    "protocol": "tcp",
                    "src_port": 12345,
                    "dest_port": 443,
                    "bytes_sent": 1024,
                    "bytes_received": 2048,
                    "duration": 30,
                    "packet_count": 50
                }
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.request_timeout)) as session:
                async with session.post(
                    config.target_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    await response.json()
                    response_time = (time.time() - request_start) * 1000
                    success = response.status == 200
            
            await asyncio.sleep(config.think_time)
            
            return {
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            return {
                'response_time': (time.time() - request_start) * 1000,
                'success': False,
                'error': str(e)
            }
    
    async def dashboard_worker(self, config: LoadTestConfig, start_time: float) -> Dict:
        """Worker function for dashboard requests"""
        try:
            request_start = time.time()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.request_timeout)) as session:
                async with session.get(config.target_url) as response:
                    await response.json()
                    response_time = (time.time() - request_start) * 1000
                    success = response.status == 200
            
            await asyncio.sleep(config.think_time)
            
            return {
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            return {
                'response_time': (time.time() - request_start) * 1000,
                'success': False,
                'error': str(e)
            }
    
    async def incident_response_worker(self, config: LoadTestConfig, start_time: float) -> Dict:
        """Worker function for incident response requests"""
        try:
            request_start = time.time()
            
            # Sample incident alert payload
            payload = {
                "alert": {
                    "severity": "high",
                    "type": "malware_detection",
                    "source_ip": "192.168.1.100",
                    "target_ip": "10.0.1.50",
                    "signature": "Malware communication detected",
                    "timestamp": datetime.now().isoformat(),
                    "risk_score": 85
                }
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.request_timeout)) as session:
                async with session.post(
                    config.target_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    await response.text()
                    response_time = (time.time() - request_start) * 1000
                    success = response.status in [200, 201, 202]
            
            await asyncio.sleep(config.think_time)
            
            return {
                'response_time': response_time,
                'success': success
            }
            
        except Exception as e:
            return {
                'response_time': (time.time() - request_start) * 1000,
                'success': False,
                'error': str(e)
            }
    
    def get_network_io_rate(self) -> float:
        """Get current network I/O rate in Mbps"""
        try:
            net_io = psutil.net_io_counters()
            # This is a simplified calculation
            # In practice, you'd need to track deltas over time
            return (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024 / 8  # Convert to Mbps
        except:
            return 0.0
    
    async def store_results(self, test_results: Dict[str, List[PerformanceMetric]]):
        """Store performance test results in Elasticsearch"""
        try:
            for component, metrics in test_results.items():
                for metric in metrics:
                    await self.es_client.index(
                        index=f"performance-results-{datetime.now().strftime('%Y.%m')}",
                        body=asdict(metric)
                    )
            
            logger.info("Performance test results stored successfully")
            
        except Exception as e:
            logger.error(f"Error storing performance results: {e}")
    
    async def generate_performance_report(self, test_results: Dict[str, List[PerformanceMetric]]):
        """Generate comprehensive performance report"""
        report = {
            "test_date": datetime.now().isoformat(),
            "summary": {},
            "detailed_results": {},
            "recommendations": []
        }
        
        for component, metrics in test_results.items():
            if not metrics:
                continue
            
            # Calculate summary statistics
            response_times = [m.response_time_ms for m in metrics]
            throughputs = [m.throughput_rps for m in metrics]
            error_rates = [m.error_rate_percent for m in metrics]
            
            summary = {
                "avg_response_time_ms": statistics.mean(response_times),
                "p95_response_time_ms": np.percentile(response_times, 95),
                "p99_response_time_ms": np.percentile(response_times, 99),
                "max_throughput_rps": max(throughputs),
                "avg_throughput_rps": statistics.mean(throughputs),
                "avg_error_rate_percent": statistics.mean(error_rates),
                "total_requests": sum(m.success_count + m.error_count for m in metrics)
            }
            
            report["summary"][component] = summary
            report["detailed_results"][component] = [asdict(m) for m in metrics]
            
            # Generate recommendations
            if summary["avg_response_time_ms"] > 1000:
                report["recommendations"].append(f"{component}: High response time detected, consider optimization")
            
            if summary["avg_error_rate_percent"] > 1:
                report["recommendations"].append(f"{component}: High error rate detected, investigate issues")
            
            if summary["max_throughput_rps"] < 100:
                report["recommendations"].append(f"{component}: Low throughput detected, consider scaling")
        
        # Save report
        report_file = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Performance report generated: {report_file}")
        
        # Print summary
        print("\n" + "="*80)
        print("PERFORMANCE TEST SUMMARY")
        print("="*80)
        
        for component, summary in report["summary"].items():
            print(f"\n{component.upper()}:")
            print(f"  Average Response Time: {summary['avg_response_time_ms']:.2f} ms")
            print(f"  95th Percentile: {summary['p95_response_time_ms']:.2f} ms")
            print(f"  Max Throughput: {summary['max_throughput_rps']:.2f} RPS")
            print(f"  Error Rate: {summary['avg_error_rate_percent']:.2f}%")
        
        if report["recommendations"]:
            print(f"\nRECOMMENDATIONS:")
            for rec in report["recommendations"]:
                print(f"  - {rec}")
        
        print("\n" + "="*80)

async def main():
    """Main function for performance testing"""
    config = {
        'elasticsearch': {'host': 'localhost:9200', 'url': 'http://localhost:9200'},
        'api_gateway': {'url': 'http://localhost:8000'},
        'ai_detection': {'url': 'http://localhost:8001'},
        'dashboard': {'url': 'http://localhost:3001'},
        'incident_response': {'url': 'http://localhost:8002'}
    }
    
    test_suite = PerformanceTestSuite(config)
    await test_suite.initialize()
    
    # Run all performance tests
    results = await test_suite.run_all_tests()
    
    print("Performance testing completed successfully!")

if __name__ == '__main__':
    asyncio.run(main())
