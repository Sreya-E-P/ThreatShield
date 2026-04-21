import pytest
import asyncio
from src.ai_models.autonomous_defense import AutonomousDefenseService

@pytest.fixture
def defense_service():
    return AutonomousDefenseService()

@pytest.mark.asyncio
async def test_threat_handling(defense_service):
    threat_data = {
        "type": "ransomware",
        "risk_score": 0.9,
        "propagation_speed": 0.8,
        "affected_assets": 2,
        "detection_age_hours": 1,
        "resource_usage": 0.6,
        "lateral_movement": True
    }
    
    result = await defense_service.handle_threat(threat_data)
    
    assert "action_taken" in result
    assert "confidence" in result
    assert "effectiveness" in result
    assert result["confidence"] > 0