"""Capability tagging: annotate every graph node with the powers it grants.

Resolution order for a tool node:
  1. Exact tool name in the capability DB (``by_name``).
  2. Tool category in the capability DB (``by_category``).
  3. AST signature evidence for a custom function of the same name.

MCP servers are matched by substring against ``mcp_servers``.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from agentsec.models import (
    Capability,
    DataClass,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    TrustLevel,
)


class CapabilityTagger:
    def __init__(self, db_path: Optional[Path] = None, signatures: Optional[Dict] = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent / "data" / "capabilities.json"
        self.db = self._load(db_path)
        # {function_name: {capabilities:[...], evidence:[...]}} from SignatureScanner
        self.signatures = signatures or {}

    def _load(self, path: Path) -> Dict:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:  # pragma: no cover - defensive
            print(f"Warning: failed to load capability DB: {e}")
            return {"by_name": {}, "by_category": {}, "mcp_servers": {}}

    def tag(self, graph: GraphDefinition) -> GraphDefinition:
        for node in graph.nodes:
            if node.type in (NodeType.TOOL, NodeType.CUSTOM_TOOL):
                self._tag_tool(node)
            elif node.type == NodeType.MCP_SERVER:
                self._tag_mcp(node)
        return graph

    def _apply_profile(self, node: NodeDefinition, profile: Dict) -> None:
        caps = [Capability(c) for c in profile.get("capabilities", [])]
        for c in caps:
            if c not in node.capabilities:
                node.capabilities.append(c)
        if profile.get("is_source"):
            node.is_source = True
        if profile.get("trust") == "untrusted":
            node.trust = TrustLevel.UNTRUSTED
        if profile.get("data_class") == "private":
            node.data_class = DataClass.PRIVATE

    def _tag_tool(self, node: NodeDefinition) -> None:
        matched = False
        sig = self.signatures.get(node.name)

        # 1. Exact name (highest-confidence for known framework tools)
        by_name = self.db.get("by_name", {})
        if node.name in by_name:
            self._apply_profile(node, by_name[node.name])
            matched = True

        # 2. Category — only for KNOWN tools. Category keyword heuristics are
        #    unreliable for custom function names (e.g. "write_postmortem"
        #    contains "post"), so when we have precise AST signature evidence
        #    for this node we trust that instead and skip the category guess.
        if not sig:
            by_cat = self.db.get("by_category", {})
            cat_key = node.category.value if node.category else None
            if cat_key and cat_key in by_cat:
                self._apply_profile(node, by_cat[cat_key])
                matched = True

        # 3. AST signature (custom tools) — authoritative, evidence-based.
        if sig:
            for c in sig.get("capabilities", []):
                cap = Capability(c)
                if cap not in node.capabilities:
                    node.capabilities.append(cap)
            for ev in sig.get("evidence", []):
                if ev not in node.signature_evidence:
                    node.signature_evidence.append(ev)
            # An untrusted-content fetcher is also a taint source.
            if Capability.NETWORK_READ in node.capabilities and not node.is_source:
                node.is_source = True
                node.trust = TrustLevel.UNTRUSTED
            matched = True
            node.type = NodeType.CUSTOM_TOOL

        if not matched:
            # Unknown tool: mark description so the report is honest about it.
            if node.description and "unclassified" not in node.description.lower():
                node.description = (node.description or "") + " [capabilities unclassified]"

    def _tag_mcp(self, node: NodeDefinition) -> None:
        mcp = self.db.get("mcp_servers", {})
        name_l = node.name.lower()
        for key, profile in mcp.items():
            if key in name_l:
                self._apply_profile(node, profile)
                return
