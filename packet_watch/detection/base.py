from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from packet_watch.models import DetectionResult, ParsedPacket

if TYPE_CHECKING:
    from packet_watch.state import SourceState


class Detector(ABC):
    rule_id: str
    attack_type: str

    @abstractmethod
    def detect(self, packet: ParsedPacket, state: SourceState) -> DetectionResult | None:
        raise NotImplementedError
