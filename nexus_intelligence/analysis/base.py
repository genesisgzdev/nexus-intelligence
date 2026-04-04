from abc import ABC, abstractmethod
import time

class BaseModule(ABC):
    def __init__(self, target, config, logger):
        self.target = target
        self.config = config
        self.logger = logger

    def execute(self):
        start = time.time()
        res = self.run()
        res['_meta'] = {"runtime": round(time.time() - start, 4)}
        return res

    @abstractmethod
    def run(self): pass
