"""Adapter: run rag-governance-demo in-process as a red-team target.

Loads the demo's real corpus, retriever, stub backend, and governance gate,
then answers each attack prompt exactly as the demo's CLI would. Poisoned
chunks from the attack setup are appended to the retriever's chunk list
*after* ingest, simulating a poisoned chunk that evaded ingest-time
sanitization. Retrieved chunk texts are attached to the response so the
citation-faithfulness judge can verify claims.

Usage:
    from ragredteam.adapters import RagGovernanceDemoTarget
    target = RagGovernanceDemoTarget("/path/to/rag-governance-demo")
"""
import sys
from pathlib import Path

from .target import Target, TargetResponse


class RagGovernanceDemoTarget(Target):
    name = "rag-governance-demo"

    def __init__(self, demo_path, domain=None, top_k=3, audit_path="/tmp/redteam-demo-audit.jsonl"):
        self.demo_path = Path(demo_path)
        self.domain = domain
        self.top_k = top_k
        self.audit_path = audit_path
        sys.path.insert(0, str(self.demo_path / "src"))
        from ingest import ingest  # noqa: E402
        from retrieve import TfidfRetriever  # noqa: E402
        from backends import StubBackend  # noqa: E402
        from gate import decide  # noqa: E402
        self._ingest = ingest
        self._decide = decide
        chunks = ingest(self.demo_path / "corpus", domain=domain)
        self._base_chunks = chunks
        self._retriever_cls = TfidfRetriever
        self._backend = StubBackend()

    def ask(self, query, context=None):
        context = context or {}
        chunks = list(self._base_chunks)
        for ch in context.get("extra_chunks", []):
            chunks.append(_dict_to_chunk(ch))
        retr = self._retriever_cls(chunks)
        scored = retr.search(query, self.top_k)
        res = self._decide(query, scored, self._backend,
                           audit_path=self.audit_path, domain=self.domain)
        chunk_texts = {c.chunk_id: c.text for _, c in scored}
        return TargetResponse(
            text=res.answer,
            decision=res.decision,
            citations=list(res.citations),
            score=res.top_score,
            extra={"chunk_texts": chunk_texts},
        )


def _dict_to_chunk(d):
    """Wrap a plain dict as the chunk object the retriever expects."""
    class C:
        pass
    c = C()
    c.doc_id = d.get("doc_id", "redteam-poison")
    c.chunk_id = d.get("chunk_id", "redteam-poison#c0")
    c.section = d.get("section", "planted")
    c.text = d.get("text", "")
    c.trust = d.get("trust", "untrusted")
    return c
