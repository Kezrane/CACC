# -*- coding: utf-8 -*-
"""
Root wscript for the CACC-Secure project.

This file is integrated into the ndnSIM/ns-3 build system. It:
  1. builds the `cacc-secure` module (delegated to src/cacc-secure/wscript)
  2. builds all simulation scenarios in `scripts/`:
       - standard scenarios (attack-free): geant, iot, vanet
       - attack scenarios S1..S6
  3. optionally builds the unit tests (if --enable-tests)

Layout assumed:
  .
  ├── wscript                      (this file)
  ├── src/
  │   └── cacc-secure/
  │       ├── wscript              (module wscript)
  │       ├── model/               (Algorithms 1..8 + test)
  │       └── helper/              (CaccSecureHelper)
  ├── scripts/
  │   ├── geant-23-nodes.cc
  │   ├── iot-mesh-36-nodes.cc
  │   ├── vanet-50-nodes.cc
  │   ├── attack-s1-ph-tampering.cc
  │   ├── attack-s2-rhc-tampering.cc
  │   ├── attack-s3-replay.cc
  │   ├── attack-s4-ph-inflation.cc
  │   ├── attack-s5-byzantine.cc
  │   └── attack-s6-hybrid.cc
  └── topologies/
      ├── geant-23-nodes.txt
      ├── iot-mesh-36-nodes.txt
      └── vanet-50-nodes.txt
"""

import os

# ---------------------------------------------------------------------------
# Simulation scenarios (name -> source file in scripts/)
# ---------------------------------------------------------------------------
SCENARIOS = [
    # --- Standard scenarios (attack-free) --------------------------------
    'geant-23-nodes',
    'iot-mesh-36-nodes',
    'vanet-50-nodes',
    # --- Attack scenarios (S1..S6) ---------------------------------------
    'attack-s1-ph-tampering',
    'attack-s2-rhc-tampering',
    'attack-s3-replay',
    'attack-s4-ph-inflation',
    'attack-s5-byzantine',
    'attack-s6-hybrid',
]

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(bld):
    # -----------------------------------------------------------------------
    # 1. The cacc-secure module is built by src/cacc-secure/wscript.
    #    NS-3's waf automatically descends into src/ and builds all modules
    #    declared there. We do not need to do anything here, but we add a
    #    sanity check to fail early if the module is missing.
    # -----------------------------------------------------------------------
    module_path = os.path.join('src', 'cacc-secure', 'wscript')
    if not os.path.exists(module_path):
        bld.fatal('CACC-Secure module wscript not found at: ' + module_path)

    # -----------------------------------------------------------------------
    # 2. Build the simulation scenarios
    # -----------------------------------------------------------------------
    for name in SCENARIOS:
        source = os.path.join('scripts', name + '.cc')
        if not os.path.exists(source):
            bld.fatal('Scenario source not found: ' + source)

        program = bld.create_ns3_program(name, ['cacc-secure'])
        program.source = [source]

        # Allow the simulation scripts to find the topology files
        # (AnnotatedTopologyReader uses a relative path by default; we
        #  expose the project root via an environment variable so the
        #  scripts can resolve "topologies/..." robustly).
        program.env.append_value('CACC_PROJECT_ROOT', os.path.abspath('.'))

    # -----------------------------------------------------------------------
    # 3. Unit tests (delegated to src/cacc-secure/wscript)
    # -----------------------------------------------------------------------
    # Nothing to do here: the test module is declared in the module wscript
    # and built automatically when --enable-tests is passed.


# ---------------------------------------------------------------------------
# Configure
# ---------------------------------------------------------------------------
def configure(conf):
    """
    The CACC-Secure project does not require any custom feature check.
    The standard NS-3 features (ndnSIM, ndn-cxx, tests) are already
    configured by the host build system.

    We only verify that the required topology files exist, to fail early
    with a clear error message if the user forgot to copy them.
    """
    required_topologies = [
        'topologies/geant-23-nodes.txt',
        'topologies/iot-mesh-36-nodes.txt',
        'topologies/vanet-50-nodes.txt',
    ]
    for path in required_topologies:
        if not os.path.exists(path):
            conf.fatal('Required topology file missing: ' + path)

    # Check for OpenSSL (used by security-engine.cpp for HMAC-SHA256)
    conf.check_cfg(package='openssl',
                   args=['--cflags', '--libs'],
                   uselib_store='OPENSSL',
                   mandatory=False)
    if not conf.env.HAVE_OPENSSL:
        conf.msg('OpenSSL', 'not found (HMAC-SHA256 may fail to link)', 'YELLOW')
    else:
        conf.msg('OpenSSL', 'found', 'GREEN')


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
def options(opt):
    """
    No custom options. Standard NS-3 options apply:
      ./waf configure --enable-tests
      ./waf configure --enable-examples
      ./waf configure --enable-modules=...
    """
    pass