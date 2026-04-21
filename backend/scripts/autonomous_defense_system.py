# scripts/autonomous_defense_system.py
"""
COMPLETE AUTONOMOUS DEFENSE SYSTEM
- Detects threats (Zero-Day detector)
- Recommends actions (Defense Agent)
- EXECUTES actions automatically (Isolate, Block IPs, etc.)
"""

import joblib
import json
import numpy as np
import logging
import time
import threading
import queue
import subprocess
import platform
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import signal

# Fix Windows console encoding
if platform.system() == "Windows":
    sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('autonomous_defense.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AutonomousDefenseSystem:
    """
    Complete autonomous defense system
    - Detects threats
    - Predicts risk
    - Recommends actions
    - EXECUTES actions automatically
    """
    
    def __init__(self, auto_execute: bool = True):
        self.models_dir = Path(__file__).parent.parent / "models"
        self.auto_execute = auto_execute
        self.os_type = platform.system()
        self.actions_log = []
        self.threats_detected = []
        self.running = True
        
        # Action queue
        self.action_queue = queue.Queue()
        
        # Start background worker
        self.worker_thread = threading.Thread(target=self._action_worker, daemon=True)
        self.worker_thread.start()
        
        # Load models
        self._load_models()
        
        logger.info(f"Autonomous Defense System initialized")
        logger.info(f"  OS