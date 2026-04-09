import aiosqlite
import json
import os
from typing import Any, Dict

class PersistenceManager:
    """
    Local forensic database manager.
    Stores intelligence findings in a structured SQLite schema.
    """
    def __init__(self, db_path: str = "nexus_forensics.db"):
        self.db_path = db_path

    async def initialize(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    module TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            await db.commit()

    async def save_finding(self, target: str, module: str, data: Dict[str, Any]):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO intelligence (target, module, data) VALUES (?, ?, ?)",
                (target, module, json.dumps(data))
            )
            await db.commit()
