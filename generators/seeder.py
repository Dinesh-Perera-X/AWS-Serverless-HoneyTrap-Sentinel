from core.token_manager import HoneyTokenManager

class TrapSeeder:
    """
    Deploys standard enterprise decoy configurations into the local registry.
    """

    SEED_TRAPS = [
        {
            "type": "IAM_ACCESS_KEY",
            "resource": "arn:aws:iam::123456789012:user/devops-deployer-backup",
            "location": "Public GitHub Repo / .env.sample commit"
        },
        {
            "type": "IAM_ACCESS_KEY",
            "resource": "arn:aws:iam::123456789012:user/db-migration-admin",
            "location": "Exposed Pastebin dump / Developer Slack snippet"
        },
        {
            "type": "DECOY_S3_BUCKET",
            "resource": "corp-customer-database-backup-2026",
            "location": "Unlinked S3 Bucket naming bait"
        }
    ]

    @classmethod
    def seed_initial_traps(cls):
        registry = HoneyTokenManager.load_registry()
        if not registry["tokens"]:
            for trap in cls.SEED_TRAPS:
                HoneyTokenManager.register_token(
                    token_type=trap["type"],
                    resource_name=trap["resource"],
                    deployment_location=trap["location"]
                )
