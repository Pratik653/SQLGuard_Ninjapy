"""Project configuration file (``sqlninja.yaml``) for CLI and CI use."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sqlguard_ninja.benchmarking.compare import Thresholds


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BenchmarkSection(_M):
    dataset: str = "builtin:v1"
    adapter: str = "native"
    output: str = "results/latest.json"
    report: str | None = "results/latest.md"
    dialect: str | None = None


class CISection(_M):
    baseline: str = "benchmarks/baselines/native.json"
    max_security_regressions: int = 0
    max_usability_regressions: int = 0
    max_new_errors: int = 0
    min_recall: float | None = None
    max_false_positive_rate: float | None = None
    max_p95_latency_increase_pct: float | None = None
    approved_label_changes: str | None = None
    """Path to a LABEL_CHANGES.yaml listing reviewed relabels (CODEOWNERS-protected)."""

    def thresholds(self, allow_benchmark_change: bool = False) -> Thresholds:
        return Thresholds(
            max_security_regressions=self.max_security_regressions,
            max_usability_regressions=self.max_usability_regressions,
            max_new_errors=self.max_new_errors,
            min_recall=self.min_recall,
            max_false_positive_rate=self.max_false_positive_rate,
            max_p95_latency_increase_pct=self.max_p95_latency_increase_pct,
            allow_benchmark_change=allow_benchmark_change,
        )


class ProjectConfig(_M):
    version: Literal[1] = 1
    policy: str | None = None
    benchmark: BenchmarkSection = Field(default_factory=BenchmarkSection)
    ci: CISection = Field(default_factory=CISection)

    @classmethod
    def load(cls, path: str | Path) -> tuple[ProjectConfig, Path]:
        """Load the config; relative paths inside it are resolved against its directory."""
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls.model_validate(data), p.resolve().parent


DEFAULT_CONFIG = """\
# sqlninja project configuration
version: 1
policy: policies/policy.yaml
benchmark:
  dataset: benchmarks/cases          # a directory with manifest.yaml
  adapter: native
  output: results/latest.json
  report: results/latest.md
ci:
  baseline: benchmarks/baseline.json # approved result; update only by explicit review
  max_security_regressions: 0        # unsafe query newly allowed
  max_usability_regressions: 0       # legitimate query newly blocked
  max_new_errors: 0
  min_recall: 0.95
"""
