"""Abstract provider interface and normalized dataclasses.

All providers return these dataclasses — never raw API responses.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ComputeResource:
    id: str
    name: str
    state: str          # running | stopped | terminated | unknown
    type: str           # e.g. t3.micro, Standard_D2s_v3
    region: str
    cloud: str          # aws | azure | gcp
    account: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    tags: dict = field(default_factory=dict)
    launched_at: Optional[str] = None


@dataclass
class StorageResource:
    id: str
    name: str
    region: str
    cloud: str
    account: str
    size_gb: Optional[float] = None
    public: bool = False
    tags: dict = field(default_factory=dict)
    created_at: Optional[str] = None


@dataclass
class DatabaseResource:
    id: str
    name: str
    engine: str
    state: str
    region: str
    cloud: str
    account: str
    instance_class: Optional[str] = None
    storage_gb: Optional[int] = None
    multi_az: bool = False
    tags: dict = field(default_factory=dict)


class CloudProvider(ABC):
    """Abstract interface every cloud provider must implement."""

    def fetch_debug_context(
        self,
        symptom: str,
        hints: list[str],
        context: dict,
        minutes: int = 120,
    ) -> None:
        """Fetch symptom-specific debug evidence and merge into context (in place).

        Default is a no-op. Each provider overrides this with cloud-specific
        log/audit/metric fetching relevant for root-cause analysis.

        Args:
            symptom: Raw symptom string from the user.
            hints:   Service/resource name hints extracted from the symptom.
            context: Mutable dict — add keys directly (audit_logs, service_logs,
                     network_context, alb_resource_map, etc.).
            minutes: Lookback window in minutes.
        """

    @abstractmethod
    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        """List compute instances."""

    @abstractmethod
    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        """Get full details for a single instance."""

    @abstractmethod
    def stop_compute(self, account: str, instance_id: str) -> None:
        """Stop a compute instance."""

    @abstractmethod
    def start_compute(self, account: str, instance_id: str) -> None:
        """Start a stopped compute instance."""
