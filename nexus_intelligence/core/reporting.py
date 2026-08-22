import os
import json
import html
import re
import hashlib
from datetime import datetime
from typing import Dict, Any

class ReportingEngine:
    """
    Secured Forensic Reporting System.
    Implements strict sanitization to prevent Markdown/HTML injection.
    """
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def _sanitize(self, text: Any) -> str:
        """Prevents XSS and Markdown injection in forensic artifacts."""
        return html.escape(str(text))

    def generate_markdown(self, target: str, results: Dict[str, Any]) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"# Forensic Report: {self._sanitize(target)}\n"
        report += f"**Timestamp**: {ts}\n\n"
        
        for mod, data in results.items():
            report += f"## Module: {mod}\n"
            if "error" in data:
                report += f"> [!] Fault: {self._sanitize(data['error'])}\n\n"
                continue
            
            # Encapsulate all output in secure blocks
            clean_json = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
            report += "<pre><code>" + clean_json + "</code></pre>\n\n"
        
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("._")[:80] or "target"
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]
        filename = f"report_{slug}_{digest}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        os.chmod(path, 0o600)
        return path

    def generate_batch_summary(self, summary: Dict[str, Any]) -> str:
        """Write a reviewable summary for explicit bulk correlation."""
        report = "# Bulk correlation summary\n\n"
        report += f"**Targets**: {self._sanitize(summary.get('target_count', 0))}\n"
        report += f"**Findings**: {self._sanitize(summary.get('finding_count', 0))}\n"
        report += f"**Pairs above threshold**: {self._sanitize(len(summary.get('matches', [])))}\n\n"
        report += "## Similar observations across targets\n\n"
        matches = summary.get("matches", [])
        if not matches:
            report += "No cross-target pair reached the configured threshold.\n"
        else:
            for match in matches:
                left = match["left"].get("original", {})
                right = match["right"].get("original", {})
                report += (
                    f"- score `{self._sanitize(match['score'])}`: "
                    f"`{self._sanitize(left.get('target'))}` / `{self._sanitize(left.get('module'))}` "
                    f"↔ `{self._sanitize(right.get('target'))}` / `{self._sanitize(right.get('module'))}`\n"
                )

        digest = hashlib.sha256(json.dumps(summary, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:12]
        filename = f"batch_correlation_{digest}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        os.chmod(path, 0o600)
        return path
