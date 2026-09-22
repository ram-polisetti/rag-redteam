# Limitations

What this harness does **not** do. Read this before citing a pass rate.

1. **Pattern-based judging, not semantic understanding.** The judge looks
   for canaries, marker phrases, refusal phrasing, and word overlap.
   Adversarial paraphrase can evade every layer here — a `failed` verdict
   means *this* phrasing bounced off, not that the attack class is
   defeated.
2. **`failed` ≠ defended.** An extractive backend "passes" injection
   probes trivially because it cannot follow instructions at all. The
   report separates `blocked` from `failed` for exactly this reason; a
   pass rate built on `failed` verdicts is thin.
3. **Fixed attack corpus.** 49 hand-written cases. Real attackers adapt.
   The harness measures the target against a baseline battery, not
   against an adaptive adversary.
4. **No multi-turn attacks.** Each case is a single prompt. Attacks that
   build context over a conversation (gradual jailbreaks, multi-step
   exfiltration) are out of scope.
5. **Poisoned chunks are planted post-ingest.** The indirect-injection
   module bypasses the target's ingest pipeline by design, simulating a
   chunk that evaded ingest scanning. It does not test the ingest scanner
   itself.
6. **Refusal quality is shallow.** Graded on surface features (refusal
   phrasing, alternative offered). It does not assess whether the refusal
   leaked partial instructions.
7. **Citation check is lexical.** The faithfulness judge uses content-word
   overlap (≥50%), not entailment. A cleverly reworded hallucination with
   high word overlap could pass; a correctly paraphrased answer with low
   overlap could fail.
8. **Fixture targets are not security claims.** `mock-hardened` passes
   because it was written alongside the attacks. It validates the
   harness, not a real defense posture.
9. **The demo target uses the stub backend.** `rag-demo` runs
   `rag-governance-demo` with its extractive `StubBackend`, not an LLM.
   Findings transfer to the LLM-backed configuration only insofar as the
   gate layers (query screen, quarantine policy, output check) are shared.
10. **Not legal or compliance advice.** A high attack-pass rate is not a
    safety certification.
