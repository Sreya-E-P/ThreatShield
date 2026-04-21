# backend/scripts/train_model.py
"""
Model training script for ThreatShield AI models
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import json
import logging
from pathlib import Path
import argparse
import random
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ai_models.zero_day_predictor import ZeroDayPredictor, ThreatType
from ai_models.autonomous_defense import AutonomousDefenseService, CyberDefenseEnv, DefenseAction

logger = logging.getLogger(__name__)

class ModelTrainer:
    """Production model trainer for ThreatShield AI models"""
    
    def __init__(self, model_type='zero_day_predictor'):
        self.model_type = model_type
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Training on device: {self.device}")
        
        # Create output directory
        self.output_dir = Path('models')
        self.output_dir.mkdir(exist_ok=True)
        
    def train_zero_day_predictor(self, epochs=100, batch_size=32, samples=500):
        """Train zero-day prediction model"""
        logger.info("Training Zero-Day Predictor...")
        
        # Initialize model
        model = ZeroDayPredictor()
        model.model.to(self.device)
        
        # Generate synthetic training data
        train_data = self._generate_training_data(num_samples=samples)
        
        if not train_data:
            logger.error("No training data generated!")
            return model
        
        # Training loop
        optimizer = optim.Adam(model.model.parameters(), lr=0.001)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10)
        
        for epoch in range(epochs):
            model.model.train()
            total_loss = 0
            batch_count = 0
            
            # Shuffle training data
            random.shuffle(train_data)
            
            for i in range(0, len(train_data), batch_size):
                try:
                    batch = train_data[i:i+batch_size]
                    if not batch:
                        continue
                    
                    optimizer.zero_grad()
                    
                    batch_loss = 0
                    valid_samples = 0
                    
                    for sample in batch:
                        # Create graph from threats
                        graph = model._create_threat_graph(sample['threats'])
                        if graph is None:
                            continue
                        
                        # Create timestamps
                        timestamps = model._create_timestamps(sample['threats'])
                        
                        # Forward pass
                        threat_probs, risk_score, zero_day_prob = model.model(
                            graph['x'], graph['edge_index'], timestamps
                        )
                        
                        # Calculate loss
                        loss = self._calculate_loss(
                            threat_probs, risk_score, zero_day_prob, sample['labels']
                        )
                        
                        batch_loss += loss.item()
                        loss.backward()
                        valid_samples += 1
                    
                    if valid_samples > 0:
                        optimizer.step()
                        total_loss += batch_loss / valid_samples
                        batch_count += 1
                        
                except Exception as e:
                    logger.warning(f"Training batch failed: {e}")
                    continue
            
            # Learning rate scheduling
            if batch_count > 0:
                avg_loss = total_loss / batch_count
                scheduler.step(avg_loss)
                
                if epoch % 10 == 0:
                    logger.info(f"Epoch {epoch}/{epochs}, Loss: {avg_loss:.4f}, "
                              f"LR: {optimizer.param_groups[0]['lr']:.6f}")
        
        # Save model
        model_path = self.output_dir / 'zero_day_predictor.pt'
        model.save_model(str(model_path))
        logger.info(f"Model saved to {model_path}")
        
        # Test the model
        self._test_zero_day_model(model, train_data[:10])
        
        return model
    
    def train_defense_agent(self, episodes=1000):
        """Train defense agent using RL"""
        logger.info(f"Training Defense Agent for {episodes} episodes...")
        
        # Initialize defense service
        defense_service = AutonomousDefenseService()
        
        # Train the agent
        defense_service._train_initial_model(episodes=episodes)
        
        # Save the trained agent
        model_path = self.output_dir / 'defense_agent.pt'
        defense_service.agent.save_model(str(model_path))
        logger.info(f"Defense agent saved to {model_path}")
        
        # Test the agent
        self._test_defense_agent(defense_service)
        
        return defense_service
    
    def _generate_training_data(self, num_samples=1000):
        """Generate synthetic training data with proper structure"""
        data = []
        
        # Generate different types of threat scenarios
        for i in range(num_samples):
            # Create synthetic threat graph
            threats = self._create_synthetic_threats()
            
            # Create labels based on threat characteristics
            # Zero-day label: higher probability for novel threats
            has_novel_threats = any(t.get("source") == "unknown" for t in threats)
            has_recent_threats = any(
                datetime.fromisoformat(t.get("timestamp", datetime.now().isoformat()).replace('Z', '+00:00')) > 
                datetime.now() - timedelta(days=1)
                for t in threats
            )
            
            # Determine if this is a zero-day scenario
            is_zero_day = (has_novel_threats and has_recent_threats) or random.random() < 0.3
            
            # Calculate risk score based on severity
            risk_score = 0.0
            for threat in threats:
                severity = threat.get("severity", "medium")
                if severity == "critical":
                    risk_score += 0.3
                elif severity == "high":
                    risk_score += 0.2
                elif severity == "medium":
                    risk_score += 0.15
                else:
                    risk_score += 0.1
            
            risk_score = min(risk_score / len(threats) if threats else 0.5, 1.0)
            
            data.append({
                'threats': threats,
                'labels': {
                    'zero_day': float(is_zero_day),
                    'risk_score': risk_score,
                }
            })
        
        logger.info(f"Generated {len(data)} training samples")
        return data
    
    def _create_synthetic_threats(self):
        """Create synthetic threat data for training"""
        threats = []
        
        num_threats = random.randint(3, 10)
        threat_types = list(ThreatType.__members__.values())
        
        for i in range(num_threats):
            threat_type = random.choice(threat_types)
            
            # Generate realistic timestamp within last 30 days
            days_ago = random.randint(0, 30)
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            timestamp = datetime.now() - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
            
            # Generate severity with distribution
            severity_weights = ["low", "medium", "high", "critical"]
            severity_probs = [0.3, 0.4, 0.2, 0.1]
            severity = random.choices(severity_weights, weights=severity_probs)[0]
            
            # Generate source with some unknown sources
            sources = ["misp", "virustotal", "alienvault", "internal", "unknown"]
            source_probs = [0.3, 0.25, 0.2, 0.2, 0.05]
            source = random.choices(sources, weights=source_probs)[0]
            
            threat = {
                'id': f'threat_{i}_{random.randint(1000, 9999)}',
                'type': threat_type.value,
                'severity': severity,
                'title': f'Synthetic {threat_type.value} threat {i}',
                'description': 'Generated for training purposes. This is a simulated threat to train the AI model.',
                'timestamp': timestamp.isoformat(),
                'source': source,
                'risk_score': random.uniform(0.3, 0.9),
                'indicators': [
                    f'hash_{random.randint(100000, 999999)}',
                    f'domain_{random.randint(100, 999)}.example.com',
                    f'ip_{random.randint(10, 255)}.{random.randint(10, 255)}.{random.randint(10, 255)}.{random.randint(10, 255)}'
                ],
                'affected_systems': random.randint(1, 10),
                'propagation_rate': random.uniform(0.1, 0.9),
                'complexity': random.uniform(0.3, 0.9),
                'detection_age_hours': random.randint(0, 48),
                'resource_usage': random.uniform(0.1, 0.8),
                'lateral_movement': random.choice([True, False]),
                'metadata': {
                    'synthetic': True,
                    'generated_at': datetime.now().isoformat(),
                    'simulation_id': random.randint(1000, 9999),
                }
            }
            
            # Add type-specific data
            if threat_type == ThreatType.MALWARE:
                threat['hashes'] = {
                    'md5': f"{random.getrandbits(128):032x}",
                    'sha1': f"{random.getrandbits(160):040x}",
                    'sha256': f"{random.getrandbits(256):064x}"
                }
                threat['behaviors'] = random.sample([
                    'persistence_mechanism', 'code_injection', 'process_hollowing',
                    'registry_modification', 'file_creation', 'network_communication'
                ], random.randint(2, 4))
                
            elif threat_type == ThreatType.PHISHING:
                threat['email'] = {
                    'sender': f'sender{random.randint(1, 100)}@example.com',
                    'subject': f'URGENT: Action Required {random.randint(100, 999)}',
                    'body': f'Please verify your account immediately. Click here: http://phish{random.randint(1, 100)}.xyz'
                }
                
            elif threat_type == ThreatType.EXPLOIT:
                threat['cve'] = {
                    'id': f'CVE-2024-{random.randint(1000, 9999)}',
                    'cvss_score': random.uniform(5.0, 10.0),
                    'attack_vector': random.choice(['NETWORK', 'LOCAL', 'ADJACENT'])
                }
            
            threats.append(threat)
        
        return threats
    
    def _calculate_loss(self, threat_probs, risk_score, zero_day_prob, labels):
        """Calculate combined loss"""
        # Zero-day prediction loss
        zero_day_loss = nn.BCELoss()(
            zero_day_prob, 
            torch.tensor([[labels['zero_day']]], device=self.device)
        )
        
        # Risk score loss
        risk_loss = nn.MSELoss()(
            risk_score,
            torch.tensor([[labels['risk_score']]], device=self.device)
        )
        
        # Threat classification loss (optional)
        # For now, focus on zero-day and risk prediction
        
        return zero_day_loss + 0.5 * risk_loss
    
    def _test_zero_day_model(self, model, test_data):
        """Test the trained zero-day model"""
        logger.info("Testing trained zero-day model...")
        
        model.model.eval()
        with torch.no_grad():
            correct_zero_day = 0
            total_zero_day = 0
            risk_errors = []
            
            for sample in test_data[:5]:  # Test on first 5 samples
                try:
                    # Create graph from threats
                    graph = model._create_threat_graph(sample['threats'])
                    if graph is None:
                        continue
                    
                    # Create timestamps
                    timestamps = model._create_timestamps(sample['threats'])
                    
                    # Forward pass
                    threat_probs, risk_score, zero_day_prob = model.model(
                        graph['x'], graph['edge_index'], timestamps
                    )
                    
                    # Check zero-day prediction
                    predicted_zero_day = zero_day_prob.item() > 0.5
                    actual_zero_day = sample['labels']['zero_day'] > 0.5
                    
                    if predicted_zero_day == actual_zero_day:
                        correct_zero_day += 1
                    total_zero_day += 1
                    
                    # Calculate risk error
                    risk_error = abs(risk_score.item() - sample['labels']['risk_score'])
                    risk_errors.append(risk_error)
                    
                except Exception as e:
                    logger.warning(f"Test sample failed: {e}")
                    continue
            
            if total_zero_day > 0:
                accuracy = correct_zero_day / total_zero_day
                avg_risk_error = sum(risk_errors) / len(risk_errors) if risk_errors else 0
                logger.info(f"Zero-Day Test Results - Accuracy: {accuracy:.2%}, "
                          f"Avg Risk Error: {avg_risk_error:.4f}")
    
    def _test_defense_agent(self, defense_service):
        """Test the trained defense agent"""
        logger.info("Testing trained defense agent...")
        
        env = CyberDefenseEnv()
        state, _ = env.reset()
        total_reward = 0
        steps = 0
        
        for _ in range(10):  # Test for 10 episodes
            state, _ = env.reset()
            episode_reward = 0
            done = False
            
            while not done:
                action = defense_service.agent.select_action(state, training=False)
                next_state, reward, terminated, truncated, info = env.step(action)
                done = terminated or truncated
                
                episode_reward += reward
                state = next_state
                steps += 1
            
            total_reward += episode_reward
            
            logger.info(f"Test Episode - Reward: {episode_reward:.2f}, "
                       f"Final Asset Value: {info['asset_value']:.1f}")
        
        avg_reward = total_reward / 10
        logger.info(f"Defense Agent Test Results - Avg Reward: {avg_reward:.2f}, "
                   f"Avg Steps: {steps/10:.1f}")

def main():
    """Main training script"""
    parser = argparse.ArgumentParser(description='Train ThreatShield AI models')
    parser.add_argument('--model', type=str, default='all',
                       choices=['zero_day_predictor', 'defense_agent', 'all'],
                       help='Model to train')
    parser.add_argument('--epochs', type=int, default=100,
                       help='Number of training epochs (for zero-day)')
    parser.add_argument('--episodes', type=int, default=1000,
                       help='Number of training episodes (for defense agent)')
    parser.add_argument('--batch-size', type=int, default=32,
                       help='Training batch size')
    parser.add_argument('--samples', type=int, default=500,
                       help='Number of training samples to generate')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Train models
    trainer = ModelTrainer()
    
    if args.model in ['zero_day_predictor', 'all']:
        logger.info("=" * 50)
        trainer.train_zero_day_predictor(
            epochs=args.epochs, 
            batch_size=args.batch_size,
            samples=args.samples
        )
    
    if args.model in ['defense_agent', 'all']:
        logger.info("=" * 50)
        trainer.train_defense_agent(episodes=args.episodes)
    
    logger.info("=" * 50)
    logger.info("Training completed successfully!")

if __name__ == '__main__':
    main()