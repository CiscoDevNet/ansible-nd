#!/usr/bin/env python3
"""Refresh the compressed helper payloads embedded in shared Jenkinsfiles."""

import base64
import gzip
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JENKINSFILES = (
    ROOT / "Jenkinsfile_nd_jenkins_script",
    ROOT / "Jenkinsfile_nd_jenkins_script_temp_switches",
    ROOT / "Jenkinsfile_nd_jenkins_script_comm_list",
)
SOURCES = {
    "nd_report.py": ROOT / "playbooks/nd_report.py",
    "nd_result_summary.py": ROOT / "playbooks/nd_result_summary.py",
    "nd_reporting_pipeline.py": ROOT / "playbooks/nd_reporting_pipeline.py",
    "nd_test_activity.py": ROOT / "playbooks/nd_test_activity.py",
    "nd_prerequisite/interface_baseline.yaml": ROOT / "playbooks/nd_prerequisite/interface_baseline.yaml",
    "action_plugins/nd_interface_baseline.py": ROOT / "playbooks/action_plugins/nd_interface_baseline.py",
    "nd_prerequisite_profiles.yaml": ROOT / "tests/nd_prerequisite_profiles.yaml",
    "nd_prerequisite_orchestrator.py": ROOT / "tests/nd_prerequisite_orchestrator.py",
}
ENTRY = re.compile(
    r"(?m)^(?P<prefix>\s*'(?P<key>[^']+)': \[sha256: ')[^']+"
    r"(?P<middle>', bytes: )\d+(?P<encoded>, gzipBase64: ')[^']+(?P<suffix>'\],?)$"
)


def main():
    for jenkinsfile in JENKINSFILES:
        text = jenkinsfile.read_text()
        replaced = set()

        def refresh(match):
            key = match.group("key")
            source = SOURCES.get(key)
            if source is None or not source.is_file():
                return match.group(0)
            data = source.read_bytes()
            payload = base64.b64encode(gzip.compress(data, compresslevel=9, mtime=0)).decode("ascii")
            replaced.add(key)
            replacement = (
                match.group("prefix")
                + hashlib.sha256(data).hexdigest()
                + match.group("middle")
                + str(len(data))
                + match.group("encoded")
                + payload
                + match.group("suffix")
            )
            return replacement

        text = ENTRY.sub(refresh, text)
        if not replaced:
            raise SystemExit(f"No helper payloads refreshed in {jenkinsfile.name}")
        jenkinsfile.write_text(text)
        print(f"{jenkinsfile.name}: refreshed {', '.join(sorted(replaced))}")


if __name__ == "__main__":
    main()
