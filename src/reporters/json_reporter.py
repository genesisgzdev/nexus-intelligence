import json
from reporters.base import BaseReporter

class JSONReporter(BaseReporter):
    def generate(self):
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump({self.target: self.data}, f, indent=4)
