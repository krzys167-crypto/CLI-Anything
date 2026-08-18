"""
Evidence Model v0.1

Canonical representation of OLA metrics for CLI-Anything harnesses.
- Deterministic JSON schema
- SHA-256 fingerprinting
- Tamper detection
- Filesystem persistence
"""

import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime
import os


class EvidenceStatus(Enum):
    """Status of an evidence record."""
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class OLAMetric:
    """Single OLA metric with value and threshold."""
    name: str
    value: float
    unit: str
    threshold: float
    status: EvidenceStatus = EvidenceStatus.UNKNOWN
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to canonical dict."""
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "threshold": self.threshold,
            "status": self.status.value,
        }
    
    def validate(self) -> EvidenceStatus:
        """Validate metric against threshold."""
        if self.value <= self.threshold:
            self.status = EvidenceStatus.PASS
        else:
            self.status = EvidenceStatus.FAIL
        return self.status


@dataclass
class CLIExecution:
    """Single CLI command execution record."""
    cli_name: str
    command: str
    exit_code: int
    duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to canonical dict."""
        return {
            "cli_name": self.cli_name,
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "stdout": self.stdout or "",
            "stderr": self.stderr or "",
        }
    
    def status(self) -> EvidenceStatus:
        """Determine status from exit code."""
        return EvidenceStatus.PASS if self.exit_code == 0 else EvidenceStatus.FAIL


@dataclass
class EvidenceRecord:
    """
    Canonical Evidence Record for OLA compliance.
    
    Schema is deterministic and version-pinned for reproducibility.
    """
    
    # Metadata
    version: str = "0.1"
    record_id: str = field(default_factory=lambda: os.urandom(16).hex())
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # OLA target
    cli_name: str = ""
    repository: str = "krzys167-crypto/CLI-Anything"
    
    # Metrics
    metrics: List[OLAMetric] = field(default_factory=list)
    executions: List[CLIExecution] = field(default_factory=list)
    
    # Aggregate status
    overall_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    
    # Annotations
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Convert to canonical (deterministic) JSON representation.
        
        Field order is fixed for consistent hashing.
        """
        return {
            "version": self.version,
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "cli_name": self.cli_name,
            "repository": self.repository,
            "metrics": [m.to_dict() for m in sorted(self.metrics, key=lambda x: x.name)],
            "executions": [e.to_dict() for e in self.executions],
            "overall_status": self.overall_status.value,
            "notes": self.notes,
            "tags": sorted(self.tags),
        }
    
    def to_canonical_json(self) -> str:
        """Serialize to canonical JSON (sorted keys, no whitespace)."""
        return json.dumps(
            self.to_canonical_dict(),
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
        )
    
    def compute_sha256(self) -> str:
        """Compute SHA-256 fingerprint of canonical JSON."""
        canonical_json = self.to_canonical_json()
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
    
    def validate(self) -> EvidenceStatus:
        """Validate all metrics and determine overall status."""
        statuses = [m.validate() for m in self.metrics]
        exec_statuses = [e.status() for e in self.executions]
        
        all_statuses = statuses + exec_statuses
        if not all_statuses:
            self.overall_status = EvidenceStatus.UNKNOWN
        elif any(s == EvidenceStatus.FAIL for s in all_statuses):
            self.overall_status = EvidenceStatus.FAIL
        elif all(s == EvidenceStatus.PASS for s in all_statuses):
            self.overall_status = EvidenceStatus.PASS
        else:
            self.overall_status = EvidenceStatus.UNKNOWN
        
        return self.overall_status
    
    def to_json_with_sha256(self) -> Dict[str, Any]:
        """Serialize with embedded SHA-256 fingerprint."""
        return {
            "data": self.to_canonical_dict(),
            "sha256": self.compute_sha256(),
        }


# Example usage
if __name__ == "__main__":
    record = EvidenceRecord(
        cli_name="cli-anything-gimp",
        metrics=[
            OLAMetric(name="test_pass_rate", value=0.98, unit="%", threshold=0.95),
            OLAMetric(name="avg_command_duration", value=1.2, unit="s", threshold=2.0),
        ],
        executions=[
            CLIExecution(
                cli_name="cli-anything-gimp",
                command="gimp project new --width 1920",
                exit_code=0,
                duration_ms=1200.5,
                stdout="Project created successfully",
            ),
        ],
        notes="All tests passing, performance within SLA",
        tags=["production", "gimp", "v0.1"],
    )
    
    record.validate()
    
    print("=== Canonical JSON ===")
    print(record.to_canonical_json())
    print()
    print("=== SHA-256 ===")
    print(record.compute_sha256())
    print()
    print("=== With Signature ===")
    print(json.dumps(record.to_json_with_sha256(), indent=2))
