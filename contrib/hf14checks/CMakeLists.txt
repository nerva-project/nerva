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

get_filename_component(NERVA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(NERVA_BUILD "${NERVA_ROOT}/build" CACHE PATH "A configured and built nerva build directory")

if (NOT EXISTS "${NERVA_BUILD}/src/crypto/libcncrypto.a")
  message(FATAL_ERROR "NERVA_BUILD=${NERVA_BUILD} does not look like a built tree (build the daemon first)")
endif ()

include_directories(
  "${NERVA_ROOT}/src"
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
hf14check(t_cna_v7 t_cna_v7.cpp)
