#!/usr/bin/env python3
"""
Forensic Evidence Integrity & Chain of Custody Tool
Author: Zilan Karakoç
Description: CLI-based tool for cryptographic hash calculation, metadata extraction,
             and JSON/Manifest integrity verification for digital evidence.
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime

# Log yapılandırması (Adli inceleme iz kaydı için)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)


class ForensicValidator:
    """Digital Forensics Evidence Collector & Hash Validator"""

    CHUNK_SIZE = 65536  # 64 KB chunk size for memory-efficient large file processing

    def __init__(self, investigator: str = "Digital Forensics Analyst"):
        self.investigator = investigator

    def calculate_hashes(self, file_path: str) -> dict:
        """Calculates MD5, SHA-1, and SHA-256 hashes concurrently using chunking."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
        except PermissionError:
            logging.error(f"Permission denied while reading file: {file_path}")
            return {}
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {str(e)}")
            return {}

        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }

    def get_file_metadata(self, file_path: str) -> dict:
        """Extracts low-level OS metadata required for Chain of Custody reports."""
        stat_info = os.stat(file_path)
        return {
            "file_name": os.path.basename(file_path),
            "absolute_path": os.path.abspath(file_path),
            "size_bytes": stat_info.st_size,
            "created_time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified_time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed_time": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
        }

    def process_evidence(self, file_path: str, output_report: str = None) -> dict:
        """Main pipeline: Extracts metadata, computes hashes, and exports forensic JSON report."""
        if not os.path.isfile(file_path):
            logging.error(f"Target is not a valid file: {file_path}")
            return {}

        logging.info(f"Initiating forensic analysis on target: {file_path}")
        metadata = self.get_file_metadata(file_path)
        hashes = self.calculate_hashes(file_path)

        report = {
            "case_metadata": {
                "investigator": self.investigator,
                "acquisition_timestamp": datetime.now().isoformat(),
                "tool_version": "1.0.0",
            },
            "evidence_metadata": metadata,
            "cryptographic_hashes": hashes,
        }

        report_name = output_report or f"evidence_{metadata['file_name']}_report.json"
        with open(report_name, "w", encoding="utf-8") as rf:
            json.dump(report, rf, indent=4, ensure_ascii=False)

        logging.info(f"Forensic report generated: {report_name}")
        return report

    def verify_manifest(self, report_path: str, target_file: str) -> bool:
        """Verifies evidence integrity against a previously generated forensic JSON report."""
        if not os.path.exists(report_path):
            logging.error(f"Report file not found: {report_path}")
            return False

        with open(report_path, "r", encoding="utf-8") as rf:
            report_data = json.load(rf)

        expected_sha256 = report_data.get("cryptographic_hashes", {}).get("sha256")
        if not expected_sha256:
            logging.error("Report does not contain a valid SHA-256 hash.")
            return False

        current_hashes = self.calculate_hashes(target_file)
        current_sha256 = current_hashes.get("sha256")

        logging.info("Comparing cryptographic SHA-256 signatures...")
        if current_sha256 == expected_sha256:
            logging.info("[STATUS: PASS] Evidence integrity maintained. Hashes match.")
            return True
        else:
            logging.critical("[STATUS: FAIL] EVIDENCE TAMPERING DETECTED! Hash mismatch.")
            logging.warning(f"Expected : {expected_sha256}")
            logging.warning(f"Calculated: {current_sha256}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Digital Forensics Evidence Integrity & Chain of Custody Tool"
    )
    parser.add_argument("-f", "--file", help="Path to evidence file for analysis")
    parser.add_argument("-u", "--user", default="Zilan Karakoç", help="Investigator name")
    parser.add_argument("-o", "--output", help="Custom output JSON report file path")
    parser.add_argument("-v", "--verify", help="Path to JSON report file for verification")

    args = parser.parse_args()

    validator = ForensicValidator(investigator=args.user)

    if args.verify and args.file:
        validator.verify_manifest(args.verify, args.file)
    elif args.file:
        validator.process_evidence(args.file, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()