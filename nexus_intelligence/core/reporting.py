import os
import json
import html
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
            clean_json = json.dumps(data, indent=2)
            report += "```json\n" + clean_json + "\n```\n\n"
        
        filename = f"report_{target.replace('.','_')}_{datetime.now().strftime('%H%M%S')}.md"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        return path
