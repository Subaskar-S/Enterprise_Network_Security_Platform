#!/usr/bin/env python3
"""
AI-Based Threat Detection System for Enterprise Security Platform
Implements machine learning models for anomaly detection and threat classification
"""

import numpy as np
import pandas as pd
import logging
import asyncio
import json
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

# ML Libraries
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
import joblib

# Deep Learning
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Conv1D, MaxPooling1D
from tensorflow.keras.optimizers import Adam

# Data Processing
from elasticsearch import AsyncElasticsearch
import redis.asyncio as redis
from kafka import KafkaConsumer, KafkaProducer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatPrediction:
    """Threat prediction result"""
    timestamp: str
    source_ip: str
    threat_type: str
    confidence: float
    risk_score: int
    features: Dict
    model_version: str
    explanation: str

class FeatureExtractor:
    """Extract features from security events for ML models"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
    def extract_network_features(self, events: List[Dict]) -> pd.DataFrame:
        """Extract network-based features"""
        features = []
        
        for event in events:
            feature_dict = {
                # Basic network features
                'src_port': event.get('src_port', 0),
                'dest_port': event.get('dest_port', 0),
                'protocol_tcp': 1 if event.get('protocol') == 'tcp' else 0,
                'protocol_udp': 1 if event.get('protocol') == 'udp' else 0,
                'protocol_icmp': 1 if event.get('protocol') == 'icmp' else 0,
                
                # Traffic volume features
                'bytes_sent': event.get('bytes_sent', 0),
                'bytes_received': event.get('bytes_received', 0),
                'packet_count': event.get('packet_count', 0),
                
                # Timing features
                'duration': event.get('duration', 0),
                'hour_of_day': datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())).hour,
                'day_of_week': datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())).weekday(),
                
                # Geographic features
                'src_country_us': 1 if event.get('src_geoip', {}).get('country_code2') == 'US' else 0,
                'src_country_unknown': 1 if not event.get('src_geoip') else 0,
                
                # Response features
                'response_code': event.get('response_code', 0),
                'response_error': 1 if event.get('response_code', 200) >= 400 else 0,
                
                # Behavioral features
                'user_agent_suspicious': 1 if self._is_suspicious_user_agent(event.get('user_agent', '')) else 0,
                'path_suspicious': 1 if self._is_suspicious_path(event.get('path', '')) else 0,
                
                # Target information
                'target': event.get('label', 'benign')  # For training data
            }
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def extract_behavioral_features(self, user_events: List[Dict]) -> Dict:
        """Extract user behavioral features"""
        if not user_events:
            return {}
            
        # Sort events by timestamp
        sorted_events = sorted(user_events, key=lambda x: x.get('timestamp', ''))
        
        features = {
            'total_events': len(user_events),
            'unique_destinations': len(set(event.get('dest_ip', '') for event in user_events)),
            'unique_ports': len(set(event.get('dest_port', 0) for event in user_events)),
            'total_bytes': sum(event.get('bytes_sent', 0) + event.get('bytes_received', 0) for event in user_events),
            'avg_session_duration': np.mean([event.get('duration', 0) for event in user_events]),
            'failed_attempts': sum(1 for event in user_events if event.get('response_code', 200) >= 400),
            'night_activity': sum(1 for event in user_events if self._is_night_time(event.get('timestamp', ''))),
            'weekend_activity': sum(1 for event in user_events if self._is_weekend(event.get('timestamp', ''))),
        }
        
        # Time-based patterns
        if len(sorted_events) > 1:
            intervals = []
            for i in range(1, len(sorted_events)):
                prev_time = datetime.fromisoformat(sorted_events[i-1].get('timestamp', datetime.now().isoformat()))
                curr_time = datetime.fromisoformat(sorted_events[i].get('timestamp', datetime.now().isoformat()))
                intervals.append((curr_time - prev_time).total_seconds())
            
            features.update({
                'avg_interval': np.mean(intervals),
                'std_interval': np.std(intervals),
                'regularity_score': 1.0 / (1.0 + np.std(intervals)) if intervals else 0
            })
        
        return features
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        suspicious_patterns = ['bot', 'crawler', 'scanner', 'sqlmap', 'nikto', 'nessus', 'burp']
        return any(pattern in user_agent.lower() for pattern in suspicious_patterns)
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if URL path is suspicious"""
        suspicious_patterns = ['union', 'select', 'insert', 'delete', 'script', 'javascript', '../']
        return any(pattern in path.lower() for pattern in suspicious_patterns)
    
    def _is_night_time(self, timestamp: str) -> bool:
        """Check if timestamp is during night hours (10 PM - 6 AM)"""
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.hour >= 22 or dt.hour <= 6
        except:
            return False
    
    def _is_weekend(self, timestamp: str) -> bool:
        """Check if timestamp is during weekend"""
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.weekday() >= 5  # Saturday = 5, Sunday = 6
        except:
            return False

class AnomalyDetector:
    """Anomaly detection using Isolation Forest and DBSCAN"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def train(self, training_data: pd.DataFrame):
        """Train anomaly detection models"""
        logger.info("Training anomaly detection models...")
        
        # Prepare features (exclude target column)
        feature_columns = [col for col in training_data.columns if col != 'target']
        X = training_data[feature_columns]
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        
        # Train DBSCAN for clustering
        self.dbscan.fit(X_scaled)
        
        self.is_trained = True
        logger.info("Anomaly detection models trained successfully")
    
    def detect_anomalies(self, data: pd.DataFrame) -> List[Dict]:
        """Detect anomalies in new data"""
        if not self.is_trained:
            raise ValueError("Models must be trained before detection")
        
        feature_columns = [col for col in data.columns if col != 'target']
        X = data[feature_columns]
        X_scaled = self.scaler.transform(X)
        
        # Isolation Forest predictions (-1 = anomaly, 1 = normal)
        isolation_predictions = self.isolation_forest.predict(X_scaled)
        isolation_scores = self.isolation_forest.decision_function(X_scaled)
        
        # DBSCAN clustering (-1 = noise/anomaly)
        dbscan_predictions = self.dbscan.fit_predict(X_scaled)
        
        anomalies = []
        for i, (iso_pred, iso_score, db_pred) in enumerate(zip(isolation_predictions, isolation_scores, dbscan_predictions)):
            if iso_pred == -1 or db_pred == -1:
                anomalies.append({
                    'index': i,
                    'isolation_score': float(iso_score),
                    'is_isolation_anomaly': iso_pred == -1,
                    'is_dbscan_anomaly': db_pred == -1,
                    'confidence': abs(float(iso_score))
                })
        
        return anomalies

class ThreatClassifier:
    """Multi-class threat classification using Random Forest and Neural Networks"""
    
    def __init__(self):
        self.rf_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42
        )
        self.nn_model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        
    def build_neural_network(self, input_dim: int, num_classes: int):
        """Build neural network for threat classification"""
        model = Sequential([
            Dense(128, activation='relu', input_dim=input_dim),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train(self, training_data: pd.DataFrame):
        """Train threat classification models"""
        logger.info("Training threat classification models...")
        
        feature_columns = [col for col in training_data.columns if col != 'target']
        X = training_data[feature_columns]
        y = training_data['target']
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Train Random Forest
        self.rf_classifier.fit(X_train, y_train)
        
        # Train Neural Network
        num_classes = len(self.label_encoder.classes_)
        self.nn_model = self.build_neural_network(X_scaled.shape[1], num_classes)
        
        self.nn_model.fit(
            X_train, y_train,
            epochs=50,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=0
        )
        
        # Evaluate models
        rf_predictions = self.rf_classifier.predict(X_test)
        nn_predictions = np.argmax(self.nn_model.predict(X_test), axis=1)
        
        logger.info("Random Forest Classification Report:")
        logger.info(classification_report(y_test, rf_predictions, target_names=self.label_encoder.classes_))
        
        logger.info("Neural Network Classification Report:")
        logger.info(classification_report(y_test, nn_predictions, target_names=self.label_encoder.classes_))
        
        self.is_trained = True
        logger.info("Threat classification models trained successfully")
    
    def predict(self, data: pd.DataFrame) -> List[Dict]:
        """Predict threat types for new data"""
        if not self.is_trained:
            raise ValueError("Models must be trained before prediction")
        
        feature_columns = [col for col in data.columns if col != 'target']
        X = data[feature_columns]
        X_scaled = self.scaler.transform(X)
        
        # Random Forest predictions
        rf_predictions = self.rf_classifier.predict(X_scaled)
        rf_probabilities = self.rf_classifier.predict_proba(X_scaled)
        
        # Neural Network predictions
        nn_probabilities = self.nn_model.predict(X_scaled)
        nn_predictions = np.argmax(nn_probabilities, axis=1)
        
        predictions = []
        for i, (rf_pred, rf_prob, nn_pred, nn_prob) in enumerate(zip(rf_predictions, rf_probabilities, nn_predictions, nn_probabilities)):
            # Ensemble prediction (average probabilities)
            ensemble_prob = (rf_prob + nn_prob) / 2
            ensemble_pred = np.argmax(ensemble_prob)
            
            predictions.append({
                'index': i,
                'rf_prediction': self.label_encoder.inverse_transform([rf_pred])[0],
                'nn_prediction': self.label_encoder.inverse_transform([nn_pred])[0],
                'ensemble_prediction': self.label_encoder.inverse_transform([ensemble_pred])[0],
                'confidence': float(np.max(ensemble_prob)),
                'probabilities': {
                    class_name: float(prob) 
                    for class_name, prob in zip(self.label_encoder.classes_, ensemble_prob)
                }
            })
        
        return predictions

class SequentialThreatDetector:
    """LSTM-based sequential threat detection for time series analysis"""
    
    def __init__(self, sequence_length: int = 10):
        self.sequence_length = sequence_length
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def build_lstm_model(self, input_shape: Tuple[int, int]):
        """Build LSTM model for sequential threat detection"""
        model = Sequential([
            LSTM(64, return_sequences=True, input_shape=input_shape),
            Dropout(0.3),
            LSTM(32, return_sequences=False),
            Dropout(0.3),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def prepare_sequences(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequential data for LSTM training"""
        feature_columns = [col for col in data.columns if col != 'target']
        X = data[feature_columns].values
        y = (data['target'] != 'benign').astype(int).values
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Create sequences
        X_sequences = []
        y_sequences = []
        
        for i in range(len(X_scaled) - self.sequence_length + 1):
            X_sequences.append(X_scaled[i:i + self.sequence_length])
            y_sequences.append(y[i + self.sequence_length - 1])
        
        return np.array(X_sequences), np.array(y_sequences)
    
    def train(self, training_data: pd.DataFrame):
        """Train LSTM model for sequential threat detection"""
        logger.info("Training sequential threat detection model...")
        
        X_sequences, y_sequences = self.prepare_sequences(training_data)
        
        # Split data
        split_idx = int(0.8 * len(X_sequences))
        X_train, X_test = X_sequences[:split_idx], X_sequences[split_idx:]
        y_train, y_test = y_sequences[:split_idx], y_sequences[split_idx:]
        
        # Build and train model
        input_shape = (self.sequence_length, X_sequences.shape[2])
        self.model = self.build_lstm_model(input_shape)
        
        self.model.fit(
            X_train, y_train,
            epochs=30,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=0
        )
        
        self.is_trained = True
        logger.info("Sequential threat detection model trained successfully")
    
    def predict_sequence(self, sequence_data: np.ndarray) -> float:
        """Predict threat probability for a sequence"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        sequence_scaled = self.scaler.transform(sequence_data)
        sequence_reshaped = sequence_scaled.reshape(1, self.sequence_length, -1)
        
        prediction = self.model.predict(sequence_reshaped)[0][0]
        return float(prediction)

class ThreatDetectionEngine:
    """Main threat detection engine coordinating all ML models"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.sequential_detector = SequentialThreatDetector()
        
        # Data sources
        self.es_client = None
        self.redis_client = None
        self.kafka_consumer = None
        self.kafka_producer = None
        
        # Model persistence
        self.model_dir = Path(config.get('model_dir', './models'))
        self.model_dir.mkdir(exist_ok=True)
        
    async def initialize(self):
        """Initialize the threat detection engine"""
        # Initialize data connections
        self.es_client = AsyncElasticsearch([self.config['elasticsearch']['host']])
        self.redis_client = redis.Redis(host=self.config['redis']['host'], port=6379, db=0)
        
        # Load pre-trained models if available
        await self.load_models()
        
        logger.info("Threat detection engine initialized")
    
    async def train_models(self, training_data_query: str = None):
        """Train all ML models with historical data"""
        logger.info("Starting model training process...")
        
        # Fetch training data from Elasticsearch
        training_data = await self.fetch_training_data(training_data_query)
        
        if training_data.empty:
            logger.error("No training data available")
            return
        
        # Extract features
        feature_data = self.feature_extractor.extract_network_features(training_data.to_dict('records'))
        
        # Train models
        self.anomaly_detector.train(feature_data)
        self.threat_classifier.train(feature_data)
        self.sequential_detector.train(feature_data)
        
        # Save models
        await self.save_models()
        
        logger.info("Model training completed successfully")
    
    async def process_real_time_events(self):
        """Process real-time security events for threat detection"""
        logger.info("Starting real-time threat detection...")
        
        # This would typically consume from Kafka or similar streaming platform
        while True:
            try:
                # Simulate processing events (replace with actual Kafka consumer)
                events = await self.fetch_recent_events()
                
                if events:
                    predictions = await self.analyze_events(events)
                    
                    for prediction in predictions:
                        if prediction.risk_score >= 70:
                            await self.handle_high_risk_threat(prediction)
                
                await asyncio.sleep(5)  # Process every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in real-time processing: {e}")
                await asyncio.sleep(10)
    
    async def analyze_events(self, events: List[Dict]) -> List[ThreatPrediction]:
        """Analyze events and generate threat predictions"""
        predictions = []
        
        # Extract features
        feature_data = self.feature_extractor.extract_network_features(events)
        
        # Anomaly detection
        anomalies = self.anomaly_detector.detect_anomalies(feature_data)
        
        # Threat classification
        classifications = self.threat_classifier.predict(feature_data)
        
        # Combine results
        for i, event in enumerate(events):
            is_anomaly = any(anomaly['index'] == i for anomaly in anomalies)
            classification = next((c for c in classifications if c['index'] == i), None)
            
            if is_anomaly or (classification and classification['confidence'] > 0.7):
                prediction = ThreatPrediction(
                    timestamp=event.get('timestamp', datetime.now().isoformat()),
                    source_ip=event.get('src_ip', ''),
                    threat_type=classification['ensemble_prediction'] if classification else 'anomaly',
                    confidence=classification['confidence'] if classification else 0.8,
                    risk_score=self.calculate_risk_score(event, is_anomaly, classification),
                    features=feature_data.iloc[i].to_dict(),
                    model_version='1.0',
                    explanation=self.generate_explanation(event, is_anomaly, classification)
                )
                predictions.append(prediction)
        
        return predictions
    
    def calculate_risk_score(self, event: Dict, is_anomaly: bool, classification: Dict) -> int:
        """Calculate risk score based on various factors"""
        base_score = 30
        
        if is_anomaly:
            base_score += 40
        
        if classification:
            threat_type = classification['ensemble_prediction']
            confidence = classification['confidence']
            
            threat_scores = {
                'malware': 50,
                'intrusion': 45,
                'data_exfiltration': 40,
                'brute_force': 35,
                'reconnaissance': 25
            }
            
            base_score += threat_scores.get(threat_type, 20) * confidence
        
        # Additional factors
        if event.get('src_network_segment') == 'external':
            base_score += 15
        
        if event.get('dest_port') in [22, 3389, 445, 1433, 3306]:  # Critical services
            base_score += 10
        
        return min(int(base_score), 100)
    
    def generate_explanation(self, event: Dict, is_anomaly: bool, classification: Dict) -> str:
        """Generate human-readable explanation for the threat prediction"""
        explanations = []
        
        if is_anomaly:
            explanations.append("Detected anomalous behavior pattern")
        
        if classification:
            threat_type = classification['ensemble_prediction']
            confidence = classification['confidence']
            explanations.append(f"Classified as {threat_type} with {confidence:.2%} confidence")
        
        if event.get('src_network_segment') == 'external':
            explanations.append("Traffic originates from external network")
        
        return "; ".join(explanations)
    
    async def handle_high_risk_threat(self, prediction: ThreatPrediction):
        """Handle high-risk threat predictions"""
        logger.warning(f"High-risk threat detected: {prediction.threat_type} from {prediction.source_ip}")
        
        # Store in Redis for immediate access
        await self.redis_client.setex(
            f"threat:{prediction.source_ip}:{int(datetime.now().timestamp())}",
            3600,  # 1 hour TTL
            json.dumps(prediction.__dict__)
        )
        
        # Send to Elasticsearch for long-term storage
        await self.es_client.index(
            index=f"threat-predictions-{datetime.now().strftime('%Y.%m.%d')}",
            body=prediction.__dict__
        )
        
        # Trigger automated response if risk score is very high
        if prediction.risk_score >= 90:
            await self.trigger_automated_response(prediction)
    
    async def trigger_automated_response(self, prediction: ThreatPrediction):
        """Trigger automated response for critical threats"""
        logger.critical(f"Triggering automated response for critical threat from {prediction.source_ip}")
        
        # This would integrate with firewall APIs, SOAR platforms, etc.
        # For now, just log the action
        response_actions = {
            'block_ip': prediction.source_ip,
            'alert_soc': True,
            'create_incident': True,
            'threat_type': prediction.threat_type,
            'risk_score': prediction.risk_score
        }
        
        logger.info(f"Automated response actions: {response_actions}")
    
    async def fetch_training_data(self, query: str = None) -> pd.DataFrame:
        """Fetch training data from Elasticsearch"""
        # Implementation would query Elasticsearch for historical security events
        # For now, return empty DataFrame
        return pd.DataFrame()
    
    async def fetch_recent_events(self) -> List[Dict]:
        """Fetch recent security events for analysis"""
        # Implementation would query recent events from Elasticsearch or Kafka
        # For now, return empty list
        return []
    
    async def save_models(self):
        """Save trained models to disk"""
        joblib.dump(self.anomaly_detector, self.model_dir / 'anomaly_detector.pkl')
        joblib.dump(self.threat_classifier, self.model_dir / 'threat_classifier.pkl')
        
        if self.sequential_detector.model:
            self.sequential_detector.model.save(self.model_dir / 'sequential_detector.h5')
        
        logger.info("Models saved successfully")
    
    async def load_models(self):
        """Load pre-trained models from disk"""
        try:
            if (self.model_dir / 'anomaly_detector.pkl').exists():
                self.anomaly_detector = joblib.load(self.model_dir / 'anomaly_detector.pkl')
                
            if (self.model_dir / 'threat_classifier.pkl').exists():
                self.threat_classifier = joblib.load(self.model_dir / 'threat_classifier.pkl')
                
            if (self.model_dir / 'sequential_detector.h5').exists():
                self.sequential_detector.model = load_model(self.model_dir / 'sequential_detector.h5')
                self.sequential_detector.is_trained = True
                
            logger.info("Pre-trained models loaded successfully")
            
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")

async def main():
    """Main function for threat detection engine"""
    config = {
        'elasticsearch': {'host': 'localhost:9200'},
        'redis': {'host': 'localhost'},
        'model_dir': './models'
    }
    
    engine = ThreatDetectionEngine(config)
    await engine.initialize()
    
    # Train models with historical data (if available)
    # await engine.train_models()
    
    # Start real-time threat detection
    await engine.process_real_time_events()

if __name__ == '__main__':
    asyncio.run(main())
