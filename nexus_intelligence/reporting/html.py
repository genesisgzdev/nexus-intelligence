"""
HTML report generator using Jinja2 templates.
"""
import os
from jinja2 import Environment, FileSystemLoader
from nexus_intelligence.reporting.base import BaseReporter

class HTMLReporter(BaseReporter):
    """Generates professional HTML reports."""
    
    def generate(self):
        template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report.html')
        
        rendered = template.render(
            target=self.target,
            data=self.data
        )
        
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(rendered)
