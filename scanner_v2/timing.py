from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass


@dataclass(slots=True)
class AdaptiveRateController:
    base_timeout_s: float
    jitter_min_ms: int
    jitter_max_ms: int
    burst_limit: int

    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0

    async def pace(self, sequence_index: int) -> None:
        if sequence_index and sequence_index % max(self.burst_limit, 1) == 0:
            await asyncio.sleep(0.025)
        jitter = random.randint(self.jitter_min_ms, self.jitter_max_ms) / 1000.0
        if jitter > 0:
            await asyncio.sleep(jitter)

    def observe(self, ok: bool) -> None:
        if ok:
            self.successes += 1
            self.consecutive_failures = 0
            return
        self.failures += 1
        self.consecutive_failures += 1

    def timeout_for_attempt(self, attempt: int) -> float:
        # Backoff when the target/network drops too many probes.
        factor = 1.0 + min(self.consecutive_failures, 5) * 0.18 + attempt * 0.15
        return max(0.15, self.base_timeout_s * factor)
