# metta_demo.py
import json
from metta import MeTTa  # Ensure you have metta installed
from pyvis.network import Network

# -------------------------
# Initialize MeTTa
# -------------------------
kg = MeTTa()

# -------------------------
# Load project data
# -------------------------
# Solana rules
with open("solana_rules.json") as f:
    solana_rules = json.load(f)

# URL rules
with open("rules.json") as f:
    url_rules = json.load(f)

# -------------------------
# Add simple MeTTa facts
# -------------------------
# Project agents and artifacts
kg.assert_("(AnalyzerAgent analyzes URL)")
kg.assert_("(SolanaAnalyzer uses solana_rules.json)")
kg.assert_("(URLAnalyzer uses rules.json)")
kg.assert_("(Artifact type URL)")
kg.assert_("(Artifact type SolanaTransaction)")

# Add Solana rules as facts
for r in solana_rules:
    kg.assert_(f'({r["id"]} type {r["type"]})')
    kg.assert_(f'({r["id"]} severity {r["severity"]})')

# Add URL rules as facts (only a few for simplicity)
for r in url_rules[:5]:
    kg.assert_(f'({r["id"]} pattern "{r["pattern"]}")')
    kg.assert_(f'({r["id"]} severity {r["severity"]})')

# -------------------------
# Query some relationships
# -------------------------
facts = kg.query("(?a ?rel ?b)")

# -------------------------
# Visualize using pyvis
# -------------------------
net = Network(height="750px", width="100%", notebook=False)
for f in facts:
    a, rel, b = f
    net.add_node(a)
    net.add_node(b)
    net.add_edge(a, b, title=rel)

# Save visualization
net.show("metta_knowledge_graph.html")

print("Knowledge graph generated: metta_knowledge_graph.html")
