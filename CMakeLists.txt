cmake_minimum_required(VERSION 3.16)
project(ns3-cacc-secure CXX)

# Find ns-3 core dependencies
find_package(ns3 REQUIRED COMPONENTS core network internet ndnSIM)

# Find OpenSSL for HMAC verification operations
find_package(OpenSSL REQUIRED)

# Module source definitions
set(cacc_sources
    src/cacc-secure/model/cacc-header.cpp
    src/cacc-secure/model/rate-limiter.cpp
    src/cacc-secure/model/seq-cache.cpp
    src/cacc-secure/model/reputation.cpp
    src/cacc-secure/model/cacc-core.cpp
    src/cacc-secure/helper/cacc-secure-helper.cpp
)

set(cacc_headers
    src/cacc-secure/model/cacc-header.hpp
    src/cacc-secure/model/rate-limiter.hpp
    src/cacc-secure/model/seq-cache.hpp
    src/cacc-secure/model/reputation.hpp
    src/cacc-secure/model/cacc-core.hpp
    src/cacc-secure/helper/cacc-secure-helper.hpp
)

# Define the module library
add_library(cacc-secure SHARED ${cacc_sources})
target_include_directories(cacc-secure PUBLIC src/cacc-secure/model src/cacc-secure/helper)
target_link_libraries(cacc-secure PUBLIC 
    ns3::core 
    ns3::network 
    ns3::internet 
    ns3::ndnSIM
    OpenSSL::Crypto
)

# Scenario executable targets
add_executable(cacc-geant-scenario scenarios/cacc-geant-scenario.cpp)
target_link_libraries(cacc-geant-scenario PRIVATE cacc-secure)

add_executable(cacc-iot-scenario scenarios/cacc-iot-scenario.cpp)
target_link_libraries(cacc-iot-scenario PRIVATE cacc-secure)