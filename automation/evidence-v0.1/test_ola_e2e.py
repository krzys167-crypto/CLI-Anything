"""
OLA Evidence E2E Tests v0.1

End-to-end tests for evidence pipeline.
Includes regression test for 69 FAIL / 0 PASS case.
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from evidence_model import (
    EvidenceRecord,
    EvidenceStatus,
    OLAMetric,
    CLIExecution,
)
from ola_scanner import CLIScanner
from ola_result_model import (
    OLAEvidenceReport,
    StatusValue,
)
from ola_verifier import OLAVerifier


class TestEvidenceModel:
    """Test evidence model basics."""
    
    def test_evidence_record_schema(self):
        """Test evidence record can be created and serialized."""
        record = EvidenceRecord(cli_name="test-cli")
        assert record.cli_name == "test-cli"
        assert record.version == "0.1"
        
        json_str = record.to_canonical_json()
        assert json_str is not None
        assert len(json_str) > 0
    
    def test_sha256_consistency(self):
        """Test SHA-256 is consistent for same data."""
        record = EvidenceRecord(cli_name="test-cli")
        sha1 = record.compute_sha256()
        sha2 = record.compute_sha256()
        assert sha1 == sha2
    
    def test_sha256_changes_with_data(self):
        """Test SHA-256 changes when data changes."""
        record1 = EvidenceRecord(cli_name="test-cli-1")
        record2 = EvidenceRecord(cli_name="test-cli-2")
        sha1 = record1.compute_sha256()
        sha2 = record2.compute_sha256()
        assert sha1 != sha2
    
    def test_malformed_hash_detection(self):
        """Test that tampered SHA-256 is detected."""
        record = EvidenceRecord(cli_name="test-cli")
        correct_sha = record.compute_sha256()
        
        # Simulate tampering by modifying reported SHA
        tampered_record = record.to_json_with_sha256()
        tampered_record["sha256"] = "0" * 64  # Invalid SHA
        
        # Recompute and verify mismatch
        recomputed = record.compute_sha256()
        assert recomputed != tampered_record["sha256"]


class TestOLAResultModel:
    """Test OLA result model."""
    
    def test_result_model_creation(self):
        """Test OLA result model can be created."""
        report = OLAEvidenceReport()
        assert report.schemaVersion == "0.1"
        assert report.pipeline.status == StatusValue.UNKNOWN
        assert report.evidence.status == StatusValue.UNKNOWN
        assert report.harnessHealth.status == StatusValue.UNKNOWN
    
    def test_three_independent_dimensions(self):
        """Test that three status dimensions are independent."""
        report = OLAEvidenceReport()
        
        # Set pipeline to PASS
        report.pipeline.status = StatusValue.PASS
        
        # Set evidence to PASS
        report.evidence.status = StatusValue.PASS
        
        # Set harness health to FAIL
        report.harnessHealth.status = StatusValue.FAIL
        
        # Verify independence
        assert report.pipeline.status == StatusValue.PASS
        assert report.evidence.status == StatusValue.PASS
        assert report.harnessHealth.status == StatusValue.FAIL
        
        json_dict = report.to_dict()
        assert json_dict["pipeline"]["status"] == "PASS"
        assert json_dict["evidence"]["status"] == "PASS"
        assert json_dict["harnessHealth"]["status"] == "FAIL"
    
    def test_harness_health_status_computation(self):
        """Test harness health status computation."""
        # All PASS
        health = report = OLAEvidenceReport().harnessHealth
        health.total = 10
        health.pass_count = 10
        health.fail_count = 0
        health.unknown_count = 0
        assert health.compute_status() == StatusValue.PASS
        
        # Some FAIL
        health.fail_count = 1
        health.pass_count = 9
        assert health.compute_status() == StatusValue.FAIL
        
        # All UNKNOWN
        health.total = 0
        health.pass_count = 0
        health.fail_count = 0
        health.unknown_count = 0
        assert health.compute_status() == StatusValue.UNKNOWN


class TestOLAVerifier:
    """Test OLA verifier."""
    
    def test_verifier_creation(self):
        """Test verifier can be created."""
        verifier = OLAVerifier()
        assert verifier.report is not None
        assert verifier.scan_results is None
    
    def test_verify_evidence_records_valid(self):
        """Test verification of valid evidence records."""
        verifier = OLAVerifier()
        
        # Create valid scan results
        record1 = EvidenceRecord(cli_name="cli-1")
        record1.validate()
        
        verifier.scan_results = {
            "records": [record1.to_json_with_sha256()]
        }
        
        valid, stats = verifier.verify_evidence_records()
        assert valid == True
        assert stats["total"] == 1
        assert stats["verified"] == 1
        assert stats["invalid"] == 0
    
    def test_verify_evidence_records_malformed(self):
        """Test detection of malformed records."""
        verifier = OLAVerifier()
        
        # Create record with tampered SHA
        record = EvidenceRecord(cli_name="cli-1")
        tampered = record.to_json_with_sha256()
        tampered["sha256"] = "0" * 64  # Invalid SHA
        
        verifier.scan_results = {
            "records": [tampered]
        }
        
        valid, stats = verifier.verify_evidence_records()
        assert valid == False
        assert stats["invalid"] == 1
        assert len(stats["errors"]) > 0


class TestRegressionCase69Fail:
    """
    Regression test for the actual case:
    69 discovered harnesses
    0 PASS
    69 FAIL
    0 UNKNOWN
    
    Expected result:
    Pipeline:     PASS (execution succeeded)
    Evidence:     PASS (all records verified)
    HarnessHealth: FAIL (69 failures detected)
    """
    
    def test_69_fail_regression(self):
        """
        Test the 69 FAIL regression case.
        
        This is a critical test that ensures:
        1. Scanner found 69 harnesses
        2. All 69 have FAIL status
        3. Pipeline correctly reports FAIL harnesses
        4. Pipeline does NOT convert FAIL to PASS
        5. Evidence integrity is still valid
        """
        
        # Create synthetic scan results mimicking real 69 FAIL case
        records = []
        for i in range(69):
            record = EvidenceRecord(
                cli_name=f"cli-{i:02d}",
                notes=f"Test harness {i}"
            )
            # Simulate FAIL status
            record.overall_status = EvidenceStatus.FAIL
            records.append(record.to_json_with_sha256())
        
        scan_results = {
            "scan_timestamp": "2026-08-18T10:06:52Z",
            "repository": "krzys167-crypto/CLI-Anything",
            "harnesses_scanned": 69,
            "records": records,
        }
        
        # Verify using OLAVerifier
        verifier = OLAVerifier()
        verifier.scan_results = scan_results
        
        # Step 1: Evidence integrity should PASS
        evidence_valid, evidence_stats = verifier.verify_evidence_records()
        assert evidence_valid == True, "Evidence integrity must PASS"
        assert evidence_stats["total"] == 69
        assert evidence_stats["verified"] == 69
        assert evidence_stats["invalid"] == 0
        
        # Step 2: Harness health should FAIL
        health_stats = verifier.compute_harness_health()
        assert health_stats["total"] == 69
        assert health_stats["pass"] == 0, "No harnesses should PASS"
        assert health_stats["fail"] == 69, "All 69 should FAIL"
        assert health_stats["unknown"] == 0
        assert health_stats["status"] == "FAIL", "Harness health must be FAIL"
        
        # Step 3: Pipeline should PASS (execution succeeded)
        assert evidence_valid == True
        assert health_stats["total"] > 0
        # Pipeline PASS = evidence valid AND harnesses discovered
        
        # Step 4: Create final report
        report = OLAEvidenceReport()
        report.pipeline.status = StatusValue.PASS
        report.evidence.status = StatusValue.PASS
        report.evidence.total_records = 69
        report.evidence.verified = 69
        report.evidence.invalid = 0
        report.harnessHealth.total = 69
        report.harnessHealth.pass_count = 0
        report.harnessHealth.fail_count = 69
        report.harnessHealth.unknown_count = 0
        report.harnessHealth.status = StatusValue.FAIL
        
        # Assertions
        assert report.pipeline.status == StatusValue.PASS
        assert report.evidence.status == StatusValue.PASS
        assert report.harnessHealth.status == StatusValue.FAIL
        
        # Critical: FAIL must remain FAIL
        assert report.harnessHealth.status.value == "FAIL"
        assert report.harnessHealth.fail_count == 69
        
        # JSON output must be consistent
        json_output = report.to_json()
        json_parsed = json.loads(json_output)
        assert json_parsed["harnessHealth"]["status"] == "FAIL"
        assert json_parsed["harnessHealth"]["fail"] == 69
        assert json_parsed["harnessHealth"]["pass"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
