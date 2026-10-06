# Out-of-tree checks for the HF14 port (#117, tracking issue #116).
# Deliberately NOT wired into the main build: configure the tree once, build
# it, then point this at the build directory and run the binaries.
#
#   cmake -S contrib/hf14checks -B contrib/hf14checks/build \
#         -DNERVA_BUILD=/path/to/nerva/build
#   cmake --build contrib/hf14checks/build
#   ctest --test-dir contrib/hf14checks/build --output-on-failure
cmake_minimum_required(VERSION 3.10)
project(hf14checks C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

# Without this CMake picks no build type at all, which means no -O flag, which
# means -O0. The correctness checks do not care, but the benchmarks compare
# code compiled here against code linked in from libcncrypto.a, which the main
# build compiles at -O2. Measuring one against the other at -O0 makes anything
# built here look several times more expensive than it is.
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif ()

get_filename_component(NERVA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(NERVA_BUILD "${NERVA_ROOT}/build" CACHE PATH "A configured and built nerva build directory")

if (NOT EXISTS "${NERVA_BUILD}/src/crypto/libcncrypto.a")
  message(FATAL_ERROR "NERVA_BUILD=${NERVA_BUILD} does not look like a built tree (build the daemon first)")
endif ()

include_directories(
  "${NERVA_ROOT}/src"
  # t_v8_chain.c includes "hash-ops.h" the way the crypto sources do, rather
  # than "crypto/hash-ops.h". Without this the target does not compile, which
  # is how it sat from the commit that registered it until this one: a test
  # that cannot build reports nothing and looks like a test that passes.
  "${NERVA_ROOT}/src/crypto"
  "${NERVA_ROOT}/contrib/epee/include"
  "${NERVA_ROOT}/external/easylogging++"
  "${NERVA_ROOT}/external"
  "${NERVA_ROOT}/external/rapidjson/include")

find_package(Boost REQUIRED COMPONENTS serialization thread chrono system filesystem regex)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set(NERVA_LIBS
  "${NERVA_BUILD}/src/ringct/libringct.a"
  "${NERVA_BUILD}/src/ringct/libringct_basic.a"
  "${NERVA_BUILD}/src/cryptonote_basic/libcryptonote_basic.a"
  "${NERVA_BUILD}/src/serialization/libserialization.a"
  "${NERVA_BUILD}/src/device/libdevice.a"
  "${NERVA_BUILD}/src/crypto/libcncrypto.a"
  "${NERVA_BUILD}/src/common/libcommon.a"
  "${NERVA_BUILD}/contrib/epee/src/libepee.a"
  "${NERVA_BUILD}/external/easylogging++/libeasylogging.a")

enable_testing()

function(hf14check name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name}
    -Wl,--start-group ${NERVA_LIBS} -Wl,--end-group
    ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto
    sodium unbound Threads::Threads ${CMAKE_DL_LIBS})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

hf14check(t_bp_plus t_bp_plus.cpp)
hf14check(t_clsag t_clsag.cpp)
hf14check(t_serialization t_serialization.cpp)
hf14check(t_fee_weight t_fee_weight.cpp)
hf14check(t_ring_size t_ring_size.cpp)
# The consensus entry for v8. Nothing else reaches it: HF14 is not active, so
# no daemon calls cn_slow_hash_v14_chain yet. PLAN-v8 Phase 6 B2.
hf14check(t_v8_chain t_v8_chain.c)
# The resized v5 compilations are only comparable to the shipped v5/v6/v7 in
# libcncrypto.a if they are built the same way. These are the crypto flags the
# main build uses for slow-hash-hw.c, taken from its flags.make.
# -fno-strict-aliasing is not optional: slow-hash type-puns the scratchpad.
set_source_files_properties(
  v5pad025.c v5pad05.c v5pad1.c v5pad1_25.c v5pad1_5.c v5pad2.c v5pad4.c v5pad8.c
  PROPERTIES COMPILE_OPTIONS "-O2;-DNDEBUG;-maes;-march=x86-64;-fno-strict-aliasing")
hf14check(t_bench_v5v6 "t_bench_v5v6.cpp;v5pad025.c;v5pad05.c;v5pad1.c;v5pad1_25.c;v5pad1_5.c;v5pad2.c;v5pad4.c;v5pad8.c")
