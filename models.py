"""Legacy docker-per-team ORM mappings.

Stable-random extension models deliberately live outside this import surface.
The legacy startup path must never import them before its Final-marker gate has
admitted the extension schema.
"""

from .legacy_models import (
    ContainerChallengeModel,
    ContainerCheatLog,
    ContainerFlagModel,
    ContainerInfoModel,
    ContainerSettingsModel,
)

__all__ = (
    "ContainerChallengeModel",
    "ContainerCheatLog",
    "ContainerFlagModel",
    "ContainerInfoModel",
    "ContainerSettingsModel",
)
