import json
import os
import secrets
import string
from datetime import datetime
from typing import Dict, Any, List

class HoneyTokenManager:
    """
    Manages generation, registration, and active tracking of
    AWS canary IAM keys, decoy S3 buckets, and trap resources.
    """

    REGISTRY_PATH = "data/honey_registry.json"

    @classmethod
    def _generate_synthetic_key(cls) -> Dict[str, str]:
        """Generates realistic AWS IAM Access Key ID and Secret Key for decoy traps."""
        chars = string.ascii_letters + string.digits
        key_id = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        secret_key = "".join(secrets.choice(chars) for _ in range(40))
        return {"access_key_id": key_id, "secret_access_key": secret_key}

    @classmethod
    def register_token(cls, token_type: str, resource_name: str, deployment_location: str) -> Dict[str, Any]:
        """Registers a new canary asset in the tracking registry."""
        registry = cls.load_registry()
        
        credentials = cls._generate_synthetic_key() if token_type == "IAM_ACCESS_KEY" else None

        token_record = {
            "token_id": f"HTOKEN-{secrets.token_hex(4).upper()}",
            "type": token_type,
            "resource_identifier": resource_name,
            "access_key_id": credentials["access_key_id"] if credentials else None,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "deployment_location": deployment_location,
            "status": "ARMED_ACTIVE",
            "trigger_count": 0
        }

        registry["tokens"].append(token_record)
        cls._save_registry(registry)
        return token_record

    @classmethod
    def load_registry(cls) -> Dict[str, Any]:
        """Loads all armed canary tokens."""
        if not os.path.exists(cls.REGISTRY_PATH):
            default_reg = {
                "metadata": {"version": "1.0", "engine": "HoneyTrap-Sentinel"},
                "tokens": []
            }
            cls._save_registry(default_reg)
            return default_reg
        try:
            with open(cls.REGISTRY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"tokens": []}

    @classmethod
    def _save_registry(cls, registry_data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(cls.REGISTRY_PATH), exist_ok=True)
        with open(cls.REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry_data, f, indent=2)
