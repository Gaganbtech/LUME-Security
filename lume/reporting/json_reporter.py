"""JSON report generator for LUME security assessments."""

import json
from pathlib import Path
from typing import Optional, Union

from lume.core.verdict.models import ScanReport


class JSONReporter:
    """Serializes scan reports to structured JSON files."""

    def __init__(self, output_dir: Union[str, Path] = "reports"):
        self.output_dir = Path(output_dir)

    def generate(self, report: ScanReport, file_path: Optional[Union[str, Path]] = None) -> Path:
        """Write the ScanReport model to a JSON file.

        Args:
            report: The completed ScanReport instance.
            file_path: Optional exact output path. If None, auto-generates in output_dir.

        Returns:
            Path to the written JSON report file.
        """
        if file_path:
            target_path = Path(file_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            timestamp_str = report.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"lume_scan_{report.scan_id}_{timestamp_str}.json"
            target_path = self.output_dir / filename

        # Export Pydantic model to json dict with string-serialized timestamps
        report_data = json.loads(report.model_dump_json(indent=2))

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return target_path
