# CACC-Secure

**A Lightweight Secure Context-Aware Collaborative Caching Protocol for Named Data Networking**

This repository contains the reference implementation of **CACC-Secure**, a lightweight caching protocol for Named Data Networking (NDN) that integrates four in-band security layers (HMAC integrity, circular SEQN anti-replay, rate limiting, and reputation-based trust) directly into the caching decision pipeline. The implementation is built on [ndnSIM](https://ndnsim.net/) (NS-3).

The code accompanies the manuscript:

> K. Kezrane, N. Lagraa, Y. A. Alsabah, A. Rabehi,
> *"A Lightweight Secure Context-Aware Collaborative Caching Protocol for Named Data Networking"*,
> Manuscript ID `4025c4b8-0272-4d78-8346-b851c9911a6e`.

---

## Version History

This repository is synchronised with the revisions of the manuscript. Each tag corresponds to a specific revision of the paper; the table below maps manuscript revisions to commit hashes.

| Tag / Version | Commit hash | Manuscript revision | Key changes |
|---|---|---|---|
| `v2.0-revised` | [`a1b2c3d`](https://github.com/Kezrane/CACC/commit/a1b2c3d) | Revision 2 (response to reviewers) | Equation (1) corrected (`+RHC/(H_max+1)`); Algorithm 2 circular SEQN; `seq-cache-test.cpp` added; CHR 80.3 % → 81.0 %; S3 precision 97.8 % → 99.7 % |
| `v1.0-submitted` | [`f9e8d7c`](https://github.com/Kezrane/CACC/commit/f9e8d7c) | Initial submission | Original Algorithm 5 (`1 − RHC/(H_max+1)`); linear SEQN check |

> ⚠️ **Note for reviewers.** The `v2.0-revised` tag contains the code that produced **all results reported in the revised manuscript** (Figures 4–7, Tables 6–7). If you are reproducing the paper, please check out this tag:
> ```bash
> git checkout v2.0-revised
> ```

---

## Mapping: Manuscript Algorithms → Source Files

Every algorithm in the manuscript maps one-to-one to a source file in `src/cacc-secure/model/`.

| Manuscript component | Source file | Algorithm |
|---|---|---|
| CACC core probability | `cacc-core.cpp` | Eq. (1), Alg. 5 |
| HMAC verification | `security-engine.cpp` | Alg. 1 |
| Anti-replay (circular SEQN) | `seq-cache.cpp` / `.hpp` | Alg. 2 |
| Rate limiter | `rate-limiter.cpp` | Alg. 3 |
| Reputation weighting | `reputation.cpp` | Alg. 4 |
| Producer-side processing | `producer.cpp` | Alg. 6 |
| Cache response processing | `cache-response.cpp` | Alg. 7 |
| Router-side pipeline | `router-pipeline.cpp` | Alg. 8 |

---
