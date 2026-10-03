# Preserved aborted INF-036 baseline

Source: `5e7dfa8eebf4b58f018ded097f8d5c20613a3a92`. All 42 rate cases ran; 41 passed independent raw audits. The last case retains raw outcomes and a failed campaign record. Profiling cases did not run. Owned children and Redis were removed.

Gateway runs had sporadic admission_unavailable responses even at 100 req/s. At 3200 req/s the gateway p99 was 515-518ms, both gateways used about two CPU cores, and gateway_capacity rejections dominated; direct-to-fake completed with p99 20-22ms. At 6400, the third gateway case suffered generator/client transport collapse (44,211 not dispatched, 28,461 failed, 10 partial, 4,118 complete). This is not an attributable gateway-only capacity result.

The final assertion compared gateway successful-write completion with client receipt completion, including warmup: 5,916 versus 5,864. Under transport failures these observer counts need not agree. The 52 excess server completions cannot be joined to individual clients in this original capture and are explicitly indeterminate. Headline completion requires exact content, finish, usage, DONE and EOF at the client; failed/partial rows stay failures. A corrected accounting guard and a fresh full baseline are required. No capacity or upper-bound claim is accepted from this failed campaign.

The original source summary for that final case was not exported before the assertion. `aborted-case-audit.json` is a separately labeled raw recount, not a recovered accepted run. Checksums cover all retained artifacts; fixtures contain no real tenant data or credentials.
