"""
MeTTa Knowledge Graph Client
Handles insertion and querying of knowledge graph facts
Respects environment variables for configuration
"""

import os
import json
import threading
from datetime import datetime
from typing import Dict, Any

# Load environment variables
USE_METTA_KG = os.getenv("USE_METTA_KG", "true").lower() == "true"
METTA_GRAPH_PATH = os.getenv("METTA_GRAPH_PATH", "./data/metta_knowledge_graph.metta")
METTA_LOGGING = os.getenv("METTA_LOGGING", "true").lower() == "true"
METTA_DEBUG = os.getenv("METTA_DEBUG", "false").lower() == "true"
METTA_PERSISTENCE = os.getenv("METTA_PERSISTENCE", "false").lower() == "true"

import json
import threading

class MeTTaKGClient:
    def __init__(self):
        self.graph_path = METTA_GRAPH_PATH
        self.kg_data = {}
        self.lock = threading.Lock()  # concurrency lock

        # Load persisted KG if it exists
        if os.path.exists(self.graph_path):
            try:
                with open(self.graph_path, "r") as f:
                    self.kg_data = json.load(f)
                if METTA_LOGGING:
                    print(f"[MeTTaKG] Loaded {len(self.kg_data)} facts from {self.graph_path}")
            except Exception as e:
                print(f"[MeTTaKG ERROR] Failed to load KG: {e}")

        if USE_METTA_KG:
            print(f"[MeTTaKG] Knowledge Graph enabled at {self.graph_path}")
        else:
            print("[MeTTaKG] Knowledge Graph disabled")

    def add_fact(self, fact_type: str, fact_value: Any, metadata: Dict[str, Any] = None):
        """Insert a new fact into the KG"""
        if not USE_METTA_KG:
            if METTA_DEBUG:
                print(f"[MeTTaKG DEBUG] Skipped adding fact because KG is disabled: {fact_type}={fact_value}")
            return

        timestamp = datetime.now().isoformat()
        metadata = metadata or {}
        self.kg_data[f"{fact_type}_{timestamp}"] = {
            "type": fact_type,
            "value": fact_value,
            "metadata": metadata,
            "timestamp": timestamp
        }

        if METTA_LOGGING:
            print(f"[MeTTaKG] Added fact: {fact_type}={fact_value}")

        if METTA_PERSISTENCE:
            self._save_to_disk()

        if METTA_DEBUG:
            print(f"[MeTTaKG DEBUG] Current KG size: {len(self.kg_data)}")

    def _save_to_disk(self):
        """Persist KG to disk"""
        os.makedirs(os.path.dirname(self.graph_path), exist_ok=True)
        try:
            import json
            with open(self.graph_path, "w") as f:
                json.dump(self.kg_data, f, indent=2)
            if METTA_LOGGING:
                print(f"[MeTTaKG] KG persisted to {self.graph_path}")
        except Exception as e:
            print(f"[MeTTaKG ERROR] Failed to persist KG: {e}")

    def query_facts(self, fact_type: str = None):
        """Retrieve facts optionally filtered by type"""
        if fact_type:
            return {k: v for k, v in self.kg_data.items() if v["type"] == fact_type}
        return self.kg_data
