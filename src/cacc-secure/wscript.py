# -*- coding: utf-8 -*-
"""
wscript for the CACC-Secure module (src/cacc-secure/).

Declares:
  - the main library `cacc-secure` (all model + helper sources)
  - the public headers (model/*.hpp, helper/*.hpp)
  - the unit-test module for `seq-cache-test.cpp` (only if --enable-tests)

The library is consumed by:
  - the simulation scenarios in `scripts/` (see the root wscript)
  - the unit tests (`build/unit-tests/seq-cache-test`)
"""

import os

# ---------------------------------------------------------------------------
# Module definition
# ---------------------------------------------------------------------------
def build(bld):
    # -----------------------------------------------------------------------
    # Main library: cacc-secure
    # -----------------------------------------------------------------------
    module = bld.create_ns3_module('cacc-secure', ['ndnSIM', 'ndn-cxx'])

    module.source = [
        # --- Model (Algorithms 1..8) --------------------------------------
        'model/security-engine.cpp',    # Alg. 1 — HMAC
        'model/seq-cache.cpp',          # Alg. 2 — circular SEQN
        'model/rate-limiter.cpp',       # Alg. 3 — rate limiting
        'model/reputation.cpp',         # Alg. 4 — reputation
        'model/cacc-core.cpp',          # Eq. (1), Alg. 5 — CACC core
        'model/producer.cpp',           # Alg. 6 — producer-side
        'model/cache-response.cpp',     # Alg. 7 — cache response
        'model/router-pipeline.cpp',    # Alg. 8 — full pipeline
        # --- Helper -------------------------------------------------------
        'helper/cacc-secure-helper.cpp',
    ]

    # Public headers (installed under build/ns3/ for downstream modules)
    module.headers = bld.path.ant_glob('model/*.hpp') + \
                     bld.path.ant_glob('helper/*.hpp')

    # Dependencies
    module.use = 'ndnSIM ndn-cxx'

    # -----------------------------------------------------------------------
    # Unit tests (only if --enable-tests was passed to ./waf configure)
    # -----------------------------------------------------------------------
    if bld.env.ENABLE_TESTS:
        test_module = bld.create_ns3_module_test_library('cacc-secure')
        test_module.source = [
            'model/seq-cache-test.cpp',   # 21 assertions on Alg. 2
            # (add more test files here if you extend the test suite)
        ]
        test_module.use = 'cacc-secure'


# ---------------------------------------------------------------------------
# Configure (optional: explicit feature flag for clarity)
# ---------------------------------------------------------------------------
def configure(conf):
    # --enable-tests is already handled by NS-3; we do not override it.
    # This hook is kept for future custom feature checks.
    pass


# ---------------------------------------------------------------------------
# Options (none custom; NS-3 provides --enable-tests)
# ---------------------------------------------------------------------------
def options(opt):
    pass