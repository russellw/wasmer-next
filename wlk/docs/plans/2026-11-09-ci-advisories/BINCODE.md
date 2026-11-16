# Retained bincode maintenance risk

WLK intentionally retains registry `bincode =2.0.1` for the current remote wire
protocol. [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141.html)
classifies bincode as unmaintained and lists no patched version. This is an open
maintenance follow-up, not a vulnerability claimed fixed by a normal update.
No audit suppression or deny-policy change accompanies this decision; a denied
unmaintained warning remains a failing audit gate.

The two active edges are `wasixv2-vnet`'s public provider encode/decode functions
and `wasixv2-vnet-web`'s classic websocket protocol adapter. Both use Serde with
little-endian, fixed-width `config::legacy()`. Current message limits, complete
consumption/trailing-byte checks, and `EINVAL`/`EPROTO`/`EMSGSIZE` mappings remain
unchanged. Retiring the old runtime does not remove these active wire protocols.

The maintained-fork candidate bincode-next 3.1.1 was evaluated and rejected;
it was not adopted or renamed into the production dependency. Its registry
archive SHA256 is
`1d6626829353ae29293be5c86f42de5f0468bc758af074b0c7d08f07e538ccbc`.
Independent source review found incompatible malformed-input behavior in its
[Serde sequence decoder](https://github.com/Apich-Organization/bincode/blob/v3.1.1/src/features/serde/de_borrowed.rs):
an element's `UnexpectedEnd` becomes successful sequence termination, whereas
unchanged bincode 2.0.1 propagates the error. For the actual provider type
`Reply::Acquired(Vec<IpAddr>)`, source-derived bytes
`010000000100000000000000` declare one element but contain none. The fork can
accept an empty vector after consuming all twelve bytes; the original rejects
it. The existing trailing-byte check therefore cannot repair the difference.
This is a source finding, not a claimed executed oracle comparison.

The fork also omits the original primitive-reader byte-limit accounting on the
selected decoding path: a boolean byte with a zero decoding limit can succeed
where the original reports a limit error. WLK's public pre-decode maximum input
length checks remain present; this finding does not claim those checks are bypassed.

A future replacement must preserve exact public bytes and both-direction decoding
against the unchanged original/classic oracle, including malformed, truncated,
oversized, forged-length and trailing data, with matching error behavior and
bounded resource use. No new codec framework, journal format, silently relaxed
assertion, or superficial package rename is authorized by this maintenance note.
The retained dependency still carries the risk of receiving no future fixes.

OpenAI Codex recorded this explicit integration policy and rejected alternative.
Human maintainers remain responsible for the retained maintenance risk.
