# Registered supplementary matched-dispatch check

Source 07c1723. Fixed 400/800/1600/3200, three alternating paired blocks, 2s excluded warmup plus 12s measurement, no profiles; explicit busy-wait dispatcher, other conditions recorded in environment.json. This condition is separate from the primary before/after optimization comparison. All 24 cases, raw audits, zero global/tenant reservations and release-failure deltas, and owned cleanup passed.

All three 1600 pairs qualify: each mode completed 57600 measurement streams with zero failed/partial/not-dispatched. Added per-run p50 differences 2.9872/2.4582/2.8004ms; p99 differences 4.9120/5.5053/4.8533ms. Both direct/gateway dispatch p99 lag <1ms. The observed upper bound is 2.9872ms p50 and 5.5053ms p99 at this tested rate, not a population confidence bound or a range-wide/GPU guarantee. Generator CPU is 1.30-1.41 cores direct and 1.56-1.66 gateway at this point; include this explicit cost of busy waiting.

3200 p99 is 130.4010/55.3902/358.5747ms gateway versus 6.8368/6.6325/6.6223ms direct; every gateway repeat crosses the registered knee. Only block3 fails requests (89 gateway_capacity, no partials). Thus error-free runs can still be unsustainable by the latency criterion. 400 and 800 retain unqualified control scheduling tails; no retry or reclassification. These runs do not isolate or quantify a pre/post code speedup.

Independent recount, histograms and all five-longest lists: ../matched-analysis.json. Final interpretation: ../README.md. Reproduce with scripts/inf036.ps1 -MatchedDispatchCheck and a fresh output directory; review with scripts/inf036_review.py --capture <directory> --output <new-analysis.json>.
