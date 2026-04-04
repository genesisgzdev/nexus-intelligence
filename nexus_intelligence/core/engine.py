import concurrent.futures
class IntelligenceEngine:
    def __init__(self, target, config, logger):
        self.target = target
        self.config = config
        self.logger = logger
    def run(self, modules):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as ex:
            instances = [m(self.target, self.config, self.logger) for m in modules]
            futures = {ex.submit(i.execute): i.__class__.__name__ for i in instances}
            for f in concurrent.futures.as_completed(futures):
                results[futures[f]] = f.result()
        return results
