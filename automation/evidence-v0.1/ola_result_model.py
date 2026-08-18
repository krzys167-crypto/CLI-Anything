"""
OLA Result Model v0.1

Separates pipeline execution, evidence integrity, and harness health.
Three independent status dimensions.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List
from enum import Enum
from datetime import datetime


class StatusValue(Enum):
    """Status enum - PASS, FAIL, UNKNOWN."""
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class PipelineStatus:
    """Pipeline execution status - technical success only."""
    status: StatusValue = StatusValue.UNKNOWN
    startTime: str = ""
    endTime: str = ""
    duration_seconds: float = 0.0
    errorMessage: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "startTime": self.startTime,
            "endTime": self.endTime,
            "duration_seconds": self.duration_seconds,
            "errorMessage": self.errorMessage,
        }


@dataclass
class EvidenceIntegrityStatus:
    """Evidence integrity - schema, hashing, verification."""
    status: StatusValue = StatusValue.UNKNOWN
    total_records: int = 0
    verified: int = 0
    invalid: int = 0
    verification_errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "total_records": self.total_records,
            "verified": self.verified,
            "invalid": self.invalid,
            "verification_errors": self.verification_errors,
        }


@dataclass
class HarnessHealthStatus:
    """Harness health - observed software component status."""
    status: StatusValue = StatusValue.UNKNOWN
    total: int = 0
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0
    details: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "total": self.total,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "unknown": self.unknown_count,
            "details": self.details,
        }
    
    def compute_status(self) -> StatusValue:
        """
        Compute harness health status from counts.
        
        PASS: all harnesses PASS
        FAIL: at least one harness FAIL
        UNKNOWN: cannot determine (no data)
        """
        if self.total == 0:
            return StatusValue.UNKNOWN
        
        if self.fail_count > 0:
            return StatusValue.FAIL
        
        if self.pass_count == self.total:
            return StatusValue.PASS
        
        return StatusValue.UNKNOWN


@dataclass
class OLAEvidenceReport:
    """
    Complete OLA Evidence Report.
    
    Three independent status dimensions:
    1. Pipeline execution (technical)
    2. Evidence integrity (cryptographic)
    3. Harness health (observed state)
    """
    
    schemaVersion: str = "0.1"
    reportId: str = ""
    generatedAt: str = ""
    commitSha: str = ""
    workflowRunId: str = ""
    repository: str = "krzys167-crypto/CLI-Anything"
    
    # Three independent status dimensions
    pipeline: PipelineStatus = field(default_factory=PipelineStatus)
    evidence: EvidenceIntegrityStatus = field(default_factory=EvidenceIntegrityStatus)
    harnessHealth: HarnessHealthStatus = field(default_factory=HarnessHealthStatus)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to canonical dict."""
        return {
            "schemaVersion": self.schemaVersion,
            "reportId": self.reportId,
            "generatedAt": self.generatedAt,
            "commitSha": self.commitSha,
            "workflowRunId": self.workflowRunId,
            "repository": self.repository,
            "pipeline": self.pipeline.to_dict(),
            "evidence": self.evidence.to_dict(),
            "harnessHealth": self.harnessHealth.to_dict(),
        }
    
    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_compact_json(self) -> str:
        """Serialize to compact JSON (no whitespace)."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
        )


# Example: 0 PASS / 69 FAIL / 0 UNKNOWN
if __name__ == "__main__":
    report = OLAEvidenceReport(
        reportId="run-32125121845",
        generatedAt=datetime.utcnow().isoformat(),
        commitSha="e9131964747f06ec2cd2e8d2198ce9e165f0873e",
        workflowRunId="32125121845",
    )
    
    # Pipeline: executed successfully
    report.pipeline.status = StatusValue.PASS
    report.pipeline.duration_seconds = 45.2
    
    # Evidence: all records verified
    report.evidence.status = StatusValue.PASS
    report.evidence.total_records = 69
    report.evidence.verified = 69
    report.evidence.invalid = 0
    
    # Harness Health: 69 FAIL, 0 PASS
    report.harnessHealth.total = 69
    report.harnessHealth.pass_count = 0
    report.harnessHealth.fail_count = 69
    report.harnessHealth.unknown_count = 0
    report.harnessHealth.status = report.harnessHealth.compute_status()
    
    print("=== OLA Evidence Report ===")
    print(report.to_json())
    print()
    print("Pipeline Status:", report.pipeline.status.value)
    print("Evidence Status:", report.evidence.status.value)
    print("Harness Health Status:", report.harnessHealth.status.value)
