import os
import json
from datetime import datetime
from typing import Dict, Any

class ReportingEngine:
    """
    Automated Forensic Reporting System.
    Generates structured Markdown reports from raw intelligence data.
    """
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def generate_markdown(self, target: str, results: Dict[str, Any]) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"# Forensic Intelligence Report: {target}\n"
        report += f"**Generated**: {timestamp}\n\n"
        report += "## Summary of Findings\n"
        
        for module, data in results.items():
            report += f"### Module: {module}\n"
            if "error" in data:
                report += f"> [!] Error: {data['error']}\n\n"
                continue
            
            # Format JSON data into readable Markdown blocks
            report += "```json\n" + json.dumps(data, indent=2) + "\n```\n\n"
        
        filename = f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        path = os.path.join(self.output_dir, filename)
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        
        return path
