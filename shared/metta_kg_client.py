class KGClient:
    """Simple in-memory MeTTa KG shim for development/testing."""
    def __init__(self):
        self.facts = []

    def insert_fact(self, fact: str):
        # Print the fact to the console when it’s inserted
        print(f"[KG] Inserting fact: {fact}")
        self.facts.append(fact)

    def query_facts(self, pattern: str):
        return [f for f in self.facts if pattern in f]
