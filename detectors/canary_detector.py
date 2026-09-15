import json
import os
from typing import List, Dict, Any

class CanaryDetector:
    """
    Ingests CloudTrail audit streams and correlates API calls against 
    the active honeytoken registry to detect unauthorized decoy triggers.
    """

    @classmethod
    def scan_cloudtrail_log(cls, log_path: str, registered_tokens: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not os.path.exists(log_path):
            return []

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        records = data.get("Records", [])
        if not records and isinstance(data, list):
            records = data

        tracked_keys = {
            t["access_key_id"]: t for t in registered_tokens if t.get("access_key_id")
        }
        tracked_buckets = {
            t["resource_identifier"]: t for t in registered_tokens if t["type"] == "DECOY_S3_BUCKET"
        }

        tripped_alerts = []

        for event in records:
            user_identity = event.get("userIdentity", {})
            caller_key = user_identity.get("accessKeyId")
            event_name = event.get("eventName", "UnknownAction")
            source_ip = event.get("sourceIPAddress", "UnknownIP")
            user_agent = event.get("userAgent", "UnknownAgent")
            event_time = event.get("eventTime", "N/A")
            request_params = event.get("requestParameters") or {}

            # 1. Detect Honey Access Key Compromise
            if caller_key in tracked_keys:
                token_meta = tracked_keys[caller_key]
                tripped_alerts.append({
                    "alert_id": f"ALERT-IAM-{caller_key[-6:]}",
                    "trigger_type": "HONEY_KEY_INVOCATION",
                    "canary_token_id": token_meta["token_id"],
                    "event_name": event_name,
                    "event_time": event_time,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "compromised_key": caller_key,
                    "target_resource": token_meta["resource_identifier"],
                    "deployment_bait": token_meta["deployment_location"],
                    "severity": "CRITICAL"
                })

            # 2. Detect Decoy S3 Bucket Probing
            bucket_name = request_params.get("bucketName")
            if bucket_name in tracked_buckets:
                token_meta = tracked_buckets[bucket_name]
                tripped_alerts.append({
                    "alert_id": f"ALERT-S3-{bucket_name[-6:]}",
                    "trigger_type": "DECOY_S3_ACCESS",
                    "canary_token_id": token_meta["token_id"],
                    "event_name": event_name,
                    "event_time": event_time,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "compromised_key": caller_key or "Anonymous/Public",
                    "target_resource": bucket_name,
                    "deployment_bait": token_meta["deployment_location"],
                    "severity": "HIGH"
                })

        return tripped_alerts
