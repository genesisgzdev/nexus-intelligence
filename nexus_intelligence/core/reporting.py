import os
import json
import html
import re
import hashlib
import tempfile
from datetime import datetime
from typing import Dict, Any
from .presentation import LABELS, describe

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
        report = f"# Informe de {self._sanitize(target)}\n\n"
        report += f"Consulta realizada: {ts}\n\n"
        incomplete = sum("error" in data for data in results.values())
        report += f"Se completaron {len(results) - incomplete} de {len(results)} consultas.\n\n"
        report += "Este informe reúne observaciones del dominio. Una respuesta correcta no demuestra que el sitio sea seguro y una consulta fallida no demuestra una amenaza.\n\n"
        
        for mod, data in results.items():
            report += f"## {self._sanitize(LABELS.get(mod, mod))}\n\n"
            report += self._sanitize(describe(mod, data)) + "\n\n"
            
            # Encapsulate all output in secure blocks
            clean_json = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
            report += "<details><summary>Ver los datos de esta consulta</summary>\n\n<pre><code>" + clean_json + "</code></pre>\n\n</details>\n\n"
        
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("._")[:80] or "target"
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]
        filename = f"report_{slug}_{digest}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        # Exclusive creation avoids overwriting concurrent scans, and creates
        # private evidence before writing rather than chmod after exposure.
        descriptor, path = tempfile.mkstemp(prefix=filename[:-3] + "_", suffix=".md", dir=self.output_dir)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(report)
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
        # Exclusive creation avoids overwriting concurrent scans, and creates
        # private evidence before writing rather than chmod after exposure.
        descriptor, path = tempfile.mkstemp(prefix=filename[:-3] + "_", suffix=".md", dir=self.output_dir)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(report)
        return path
