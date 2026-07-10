"""Install-time safety helpers for Hermes sidecar integration."""

from .detect import HermesDetection, detect_hermes
from .manifest import file_sha256
from .recovery import (
    RecoveryClassification,
    RecoveryEvidence,
    RecoveryFinding,
    RecoveryPlan,
    plan_recovery,
    sanitize_recovery_plan,
)

__all__ = [
    "HermesDetection",
    "RecoveryClassification",
    "RecoveryEvidence",
    "RecoveryFinding",
    "RecoveryPlan",
    "detect_hermes",
    "file_sha256",
    "plan_recovery",
    "sanitize_recovery_plan",
]
