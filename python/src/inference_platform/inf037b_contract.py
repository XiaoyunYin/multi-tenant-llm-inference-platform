"""Offline contract: v4 binding; inherited constants cite immutable v3 lines.

No live collector, source join, scheduler default or paid entry point lives here.
"""

from enum import StrEnum
from pathlib import Path

REGISTRATION_ID = "inf037b-v4-r315"
REGISTRATION_COMMIT = "d35a358fc5c0ac2c8411df64e650eac60391bdb4"
REGISTRATION_GIT_BLOB_SHA256 = "f2c95f9a2f9922794acacf290c47a1c5a6f6598f14ca5dfed0f002cbc14808cc"
REGISTRATION_PATH = "docs/INF037B_REGISTRATION_V4_R315.md"
SESSION_ENVELOPE_MS = 18_000_000
EXPORT_BOUND_MS = 3_600_000
EXPORT_CLEANUP_MS = 5_400_000
PREPARATION_BRANCH_MS = 1_740_000
PREPARATION_OVERHEAD_MS = 60_000
MAX_PLACEMENT_OBSERVATION_AGE_MS = 60_000
SCHEMA_VERSION = 1  # :23
SOURCE_KINDS = ("client", "gateway", "kubernetes", "vllm", "redis", "clocks", "controller")  # :104
TARGET_ORDER = (0, 1, 0)  # :61
MAX_ATTEMPTS = 3  # :73, :89
MAX_RESETS = 2  # :73
RESET_MS = 300_000  # :73
USABLE_MS = 300_000  # :71-72
PRE_MS, TRIGGER_MS, RECOVERY_MS, DRAIN_MS = 600_000, 30_000, 600_000, 30_000  # :66-71
ATTEMPT_MS = PRE_MS + TRIGGER_MS + USABLE_MS + RECOVERY_MS + DRAIN_MS  # :73
CAMPAIGN_MS = MAX_ATTEMPTS * ATTEMPT_MS + MAX_RESETS * RESET_MS  # :73
AGE_MS, RENEWAL_MS, TTL_MS = 3_000, 3_100, 8_000  # :64
MIN_GRACE_MS = 35_000  # :71-72
CLOCK_UNCERTAINTY_MS = 100  # :25
GATEWAYS = ("gateway0", "gateway1")  # :60, :106; pseudonyms, not infrastructure IDs
MAX_TOKENS = 1  # :15, :106
UNEXERCISED = "not_exercised_max_tokens_1"  # :106
STAGE1_CATEGORIES = (  # :106
    "mid_decode_interruption",
    "partial_after_content",
    "false_completion_after_content",
)
CACHE_STATES = ("cold", "node_cached")  # :72, verified model-cache cases
IMAGE_CACHE_STATES = ("cold", "node_cached")  # :72, separately observed
DBIND_COMPONENTS = ("termination_grace", "kill_device_release", "controller_scheduler")  # :72


class BudgetStatus(StrEnum):
    """Registration :36, :80-85; absence of evidence is not a status."""

    WITHIN = "within"
    EXCEEDED = "exceeded"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"
    RIGHT_CENSORED = "right_censored"


def nonnegative(value: int, name: str) -> int:
    """Registration :31, integer units; reject bools and implicit/negative time."""
    if type(value) is not int or value < 0:
        raise ValueError(f"{name}: expected nonnegative integer")
    return value


def registration_bytes(repo: Path) -> bytes:
    return (repo / REGISTRATION_PATH).read_bytes()
