"""Target interface and built-in adapters.

A target is anything that answers a question. The harness only needs an
``ask`` method, so any RAG app can be red-teamed by wrapping it in a thin
adapter. Two adapters ship built-in:

* ``CallableTarget`` — wrap any ``fn(query, context) -> str | TargetResponse``.
* ``HttpTarget`` — POST ``{"query": ..., "context": ...}`` to an HTTP
  endpoint that returns ``{"text": ...}`` (optionally with ``decision``,
  ``citations``, ``score``).

``context`` is a dict the harness uses to smuggle attack setup into the
target — most importantly ``extra_chunks`` for poisoned-chunk attacks, where
the attack plants malicious chunks *after* ingest to simulate a chunk that
evaded ingest-time sanitization. Targets that do not understand a context
key should ignore it.
"""
from dataclasses import dataclass, field
import json
import urllib.request


@dataclass
class TargetResponse:
    text: str
    decision: str = "unknown"  # answer | refuse | escalate | unknown
    citations: list = field(default_factory=list)
    score: float | None = None
    # Adapter-provided metadata, e.g. {"chunk_texts": {chunk_id: text}}
    # for the citation-faithfulness judge.
    extra: dict = field(default_factory=dict)


class Target:
    """Anything the harness can attack."""

    name = "base"

    def ask(self, query, context=None):
        """Answer ``query``. ``context`` is an optional dict of attack setup.

        Returns a ``TargetResponse`` (or a plain string, which is coerced).
        """
        raise NotImplementedError


def coerce_response(resp):
    if isinstance(resp, TargetResponse):
        return resp
    return TargetResponse(text=str(resp))


class CallableTarget(Target):
    """Wrap a plain callable ``fn(query, context)`` as a target."""

    def __init__(self, fn, name="callable"):
        self._fn = fn
        self.name = name

    def ask(self, query, context=None):
        return coerce_response(self._fn(query, context or {}))


class HttpTarget(Target):
    """Attack a RAG app over HTTP.

    POSTs ``{"query": query, "context": context}`` as JSON. Expects a JSON
    body with at least ``{"text": "..."}``; ``decision``, ``citations``
    and ``score`` are picked up when present.
    """

    def __init__(self, url, name=None, timeout=60):
        self.url = url
        self.name = name or f"http:{url}"
        self.timeout = timeout

    def ask(self, query, context=None):
        body = json.dumps({"query": query, "context": context or {}}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        return TargetResponse(
            text=data.get("text", ""),
            decision=data.get("decision", "unknown"),
            citations=data.get("citations", []),
            score=data.get("score"),
        )
