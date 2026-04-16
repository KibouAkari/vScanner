from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from .models import ProbeResult, VulnerabilityFinding
from .plugins.base import PluginContext, VulnerabilityPlugin


class VulnerabilityEngine:
    def __init__(self, plugins: list[VulnerabilityPlugin] | None = None) -> None:
        self.plugins = plugins or self._discover_plugins()

    def _discover_plugins(self) -> list[VulnerabilityPlugin]:
        instances: list[VulnerabilityPlugin] = []
        package_name = "scanner_v2.plugins"
        package = importlib.import_module(package_name)

        for module_info in pkgutil.iter_modules(package.__path__):
            if module_info.name in {"base", "__init__"}:
                continue
            module = importlib.import_module(f"{package_name}.{module_info.name}")
            for attr_name in dir(module):
                obj: Any = getattr(module, attr_name)
                if not isinstance(obj, type):
                    continue
                if not attr_name.endswith("Plugin"):
                    continue
                if not hasattr(obj, "check") or not hasattr(obj, "applies"):
                    continue
                instances.append(obj())
        return instances

    def run(self, target: str, probes: list[ProbeResult]) -> list[VulnerabilityFinding]:
        out: list[VulnerabilityFinding] = []
        for probe in probes:
            ctx = PluginContext(target=target, probe=probe)
            for plugin in self.plugins:
                try:
                    if plugin.applies(ctx):
                        out.extend(plugin.check(ctx))
                except Exception:
                    # Keep scanning resilient even when one plugin fails.
                    continue
        return out
