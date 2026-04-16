from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..models import ProbeResult, VulnerabilityFinding


@dataclass(slots=True)
class PluginContext:
    target: str
    probe: ProbeResult


class VulnerabilityPlugin(Protocol):
    plugin_id: str

    def applies(self, ctx: PluginContext) -> bool:
        ...

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        ...
