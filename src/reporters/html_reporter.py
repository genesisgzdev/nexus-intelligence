from reporters.base import BaseReporter
from jinja2 import Environment, FileSystemLoader
import os
import json

class HTMLReporter(BaseReporter):
    def generate(self):
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '..', 'templates')))
        template = env.get_template('report.html')
        
        html_out = template.render(
            target=self.target,
            data=self.data,
            json_dump=json.dumps(self.data)
        )
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html_out)
