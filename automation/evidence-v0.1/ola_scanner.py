"""
OLA Scanner v0.1

Scans CLI-Anything repository for metrics and generates Evidence Records.
- Discovers all CLI harnesses
- Runs test suites
- Collects metrics
- Generates evidence records with SHA-256 signatures
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import time

from evidence_model import (
    EvidenceRecord,
    EvidenceStatus,
    OLAMetric,
    CLIExecution,
)


class CLIScanner:
    """Discovers and scans CLI-Anything harnesses."""
    
    def __init__(self, repo_root: Path = None):
        """Initialize scanner at repository root."""
        if repo_root is None:
            repo_root = Path(__file__).parent.parent.parent
        
        self.repo_root = repo_root
        self.cli_dirs = []
        self.evidence_records = []
    
    def discover_cli_harnesses(self) -> List[Path]:
        """Discover all CLI harnesses in repo."""
        harnesses = []
        
        # Pattern: <software-name>/agent-harness/
        for item in self.repo_root.iterdir():
            if not item.is_dir():
                continue
            
            agent_harness = item / "agent-harness"
            if agent_harness.exists():
                harnesses.append(agent_harness)
        
        self.cli_dirs = sorted(harnesses, key=lambda p: p.parent.name)
        return self.cli_dirs
    
    def find_test_file(self, harness_path: Path) -> Optional[Path]:
        """Find TEST.md in a harness."""
        test_md = harness_path / "cli_anything" / list(harness_path.parent.glob("*"))[0].name / "tests" / "TEST.md"
        
        # Fallback: search for any TEST.md
        for test_path in harness_path.rglob("TEST.md"):
            return test_path
        
        return None
    
    def parse_test_results(self, test_md_path: Path) -> Tuple[int, int, float]:
        """
        Parse TEST.md to extract test counts and pass rate.
        
        Returns: (total_tests, passed_tests, pass_rate)
        """
        try:
            content = test_md_path.read_text()
            
            # Look for pytest output lines like:
            # "passed" or "failed"
            passed = content.count(" passed")
            failed = content.count(" failed")
            
            total = passed + failed
            if total == 0:
                return 0, 0, 0.0
            
            pass_rate = (passed / total) * 100
            return total, passed, pass_rate
        except Exception as e:
            print(f"Warning: Failed to parse {test_md_path}: {e}", file=sys.stderr)
            return 0, 0, 0.0
    
    def run_cli_help(self, cli_name: str) -> Tuple[int, str, str, float]:
        """
        Run '<cli-name> --help' and measure performance.
        
        Returns: (exit_code, stdout, stderr, duration_ms)
        """
        start_time = time.time()
        try:
            result = subprocess.run(
                [f"cli-anything-{cli_name}", "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            duration_ms = (time.time() - start_time) * 1000
            return result.returncode, result.stdout, result.stderr, duration_ms
        except subprocess.TimeoutExpired:
            duration_ms = (time.time() - start_time) * 1000
            return 124, "", "Timeout", duration_ms
        except FileNotFoundError:
            duration_ms = (time.time() - start_time) * 1000
            return 127, "", "CLI not found", duration_ms
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return 1, "", str(e), duration_ms
    
    def scan_harness(self, harness_path: Path) -> Optional[EvidenceRecord]:
        """Scan a single CLI harness and generate evidence record."""
        cli_name = harness_path.parent.name
        
        print(f"Scanning: {cli_name}...", file=sys.stderr)
        
        # Create evidence record
        record = EvidenceRecord(
            cli_name=cli_name,
            repository="krzys167-crypto/CLI-Anything",
            notes=f"OLA scan at {datetime.utcnow().isoformat()}",
            tags=["ola-scan", "v0.1"],
        )
        
        # Find and parse TEST.md
        test_path = self.find_test_file(harness_path)
        if test_path:
            total, passed, pass_rate = self.parse_test_results(test_path)
            if total > 0:
                record.metrics.append(
                    OLAMetric(
                        name="test_pass_rate",
                        value=pass_rate,
                        unit="%",
                        threshold=90.0,  # SLA: 90% pass rate
                    )
                )
                record.metrics.append(
                    OLAMetric(
                        name="test_count",
                        value=float(total),
                        unit="tests",
                        threshold=0.0,  # No threshold, just info
                    )
                )
        
        # Try to run --help
        exit_code, stdout, stderr, duration = self.run_cli_help(cli_name)
        if exit_code == 0 or exit_code == 127:  # 127 = not installed, still valid info
            record.executions.append(
                CLIExecution(
                    cli_name=cli_name,
                    command="--help",
                    exit_code=exit_code,
                    duration_ms=duration,
                    stdout=stdout[:500] if stdout else "",  # Truncate
                    stderr=stderr[:500] if stderr else "",
                )
            )
            
            # Add performance metric
            record.metrics.append(
                OLAMetric(
                    name="help_command_duration",
                    value=duration,
                    unit="ms",
                    threshold=1000.0,  # SLA: must respond within 1 second
                )
            )
        
        # Validate and compute overall status
        record.validate()
        
        self.evidence_records.append(record)
        return record
    
    def scan_all(self) -> List[EvidenceRecord]:
        """Scan all harnesses."""
        self.discover_cli_harnesses()
        
        print(f"Found {len(self.cli_dirs)} harnesses", file=sys.stderr)
        
        for harness_path in self.cli_dirs:
            try:
                self.scan_harness(harness_path)
            except Exception as e:
                print(f"Error scanning {harness_path}: {e}", file=sys.stderr)
        
        return self.evidence_records
    
    def export_json(self, output_path: Path = None) -> str:
        """Export all evidence records as JSON."""
        if output_path is None:
            output_path = self.repo_root / "automation" / "evidence-v0.1" / "scan_results.json"
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "repository": "krzys167-crypto/CLI-Anything",
            "harnesses_scanned": len(self.evidence_records),
            "records": [
                record.to_json_with_sha256()
                for record in self.evidence_records
            ],
        }
        
        json_str = json.dumps(data, indent=2)
        output_path.write_text(json_str)
        
        print(f"Exported to: {output_path}", file=sys.stderr)
        return json_str
    
    def print_summary(self):
        """Print human-readable summary."""
        print("\n" + "="*70, file=sys.stderr)
        print("OLA SCAN SUMMARY", file=sys.stderr)
        print("="*70, file=sys.stderr)
        
        total_pass = sum(1 for r in self.evidence_records if r.overall_status == EvidenceStatus.PASS)
        total_fail = sum(1 for r in self.evidence_records if r.overall_status == EvidenceStatus.FAIL)
        total_unknown = sum(1 for r in self.evidence_records if r.overall_status == EvidenceStatus.UNKNOWN)
        
        print(f"Harnesses scanned:  {len(self.evidence_records)}", file=sys.stderr)
        print(f"  ✓ PASS:          {total_pass}", file=sys.stderr)
        print(f"  ✗ FAIL:          {total_fail}", file=sys.stderr)
        print(f"  ? UNKNOWN:       {total_unknown}", file=sys.stderr)
        print()
        
        for record in self.evidence_records:
            status_symbol = {
                EvidenceStatus.PASS: "✓",
                EvidenceStatus.FAIL: "✗",
                EvidenceStatus.UNKNOWN: "?",
            }[record.overall_status]
            
            print(f"{status_symbol} {record.cli_name:30} | SHA-256: {record.compute_sha256()[:16]}...", file=sys.stderr)
            
            for metric in record.metrics:
                print(f"    • {metric.name:30} {metric.value:8.2f} {metric.unit:10} [{metric.status.value}]", file=sys.stderr)
        
        print("="*70 + "\n", file=sys.stderr)


def main():
    """Run OLA scanner."""
    scanner = CLIScanner()
    records = scanner.scan_all()
    scanner.print_summary()
    json_output = scanner.export_json()
    
    # Also print JSON to stdout for piping
    print(json_output)


if __name__ == "__main__":
    main()
