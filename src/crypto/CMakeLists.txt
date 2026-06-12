# Copyright (c) 2018-2024, The Nerva Project
# Copyright (c) 2014-2024, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(crypto_sources
  aesb.c
  blake256.c
  chacha.c
  crypto-ops-data.c
  crypto-ops.c
  crypto.cpp
  groestl.c
  hash-extra-blake.c
  hash-extra-groestl.c
  hash-extra-jh.c
  hash-extra-skein.c
  hash.c
  hc128.c
  hmac-keccak.c
  jh.c
  keccak.c
  oaes_lib.c
  random.c
  skein.c
  slow-hash.c
  slow-hash-sw.c
  tree-hash.c)

set(crypto_headers)

set(crypto_private_headers
  blake256.h
  chacha.h
  crypto-ops.h
  crypto.h
  generic-ops.h
  groestl.h
  groestl_tables.h
  hash-ops.h
  hash.h
  hc128.h
  hmac-keccak.h
  initializer.h
  jh.h
  keccak.h
  oaes_config.h
  oaes_lib.h
  random.h
  skein.h
  skein_port.h
  slow-hash.h
  slow-hash-impl.h)

# A separate translation unit with the hardware-AES path. Compiled with
# +crypto (ARMv8) or the inherited -maes (x86) so the rest of the binary
# stays at the baseline ISA and still loads on AES-less CPUs. The runtime
# dispatcher in slow-hash.c picks _hw or _sw based on getauxval(AT_HWCAP)
# on Linux/Android and the existing cpuid path on x86.
set(_slow_hash_hw_supported FALSE)
if (NOT NO_AES)
  if (ARM8 AND CN_ARM_CRYPTO_FLAG)
    set(_slow_hash_hw_supported TRUE)
    list(APPEND crypto_sources slow-hash-hw.c)
    set_source_files_properties(slow-hash-hw.c PROPERTIES
      COMPILE_FLAGS "${CN_ARM_CRYPTO_FLAG}")
  elseif (BUILD_64 AND NOT ARM AND NOT PPC64LE AND NOT PPC64 AND NOT PPC AND NOT S390X AND NOT RISCV AND NOT LOONGARCH)
    # 64-bit x86 only. slow-hash.h's HW gate is __x86_64__ / _WIN64, so on
    # i686 the TU would compile as the SW-path body anyway and never be
    # called by detect_hardware_aes(). Skip it to avoid the duplicate.
    set(_slow_hash_hw_supported TRUE)
    list(APPEND crypto_sources slow-hash-hw.c)
    # -maes is already on CMAKE_C_FLAGS / CMAKE_CXX_FLAGS for x86.
  endif ()
endif ()

monero_private_headers(cncrypto
  ${crypto_private_headers})
monero_add_library(cncrypto
  ${crypto_sources}
  ${crypto_headers}
  ${crypto_private_headers})
target_link_libraries(cncrypto
  PUBLIC
    epee
    ${Boost_SYSTEM_LIBRARY}
    ${SODIUM_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})

if (_slow_hash_hw_supported)
  set_property(SOURCE slow-hash.c slow-hash-hw.c APPEND
    PROPERTY COMPILE_DEFINITIONS SLOW_HASH_HW_AES_BUILT=1)
endif ()

if (ARM)
  option(NO_OPTIMIZED_MULTIPLY_ON_ARM
	   "Compute multiply using generic C implementation instead of ARM ASM" OFF)
  if(NO_OPTIMIZED_MULTIPLY_ON_ARM)
    message(STATUS "Using generic C implementation for multiply")
    set_property(SOURCE slow-hash.c slow-hash-sw.c
      APPEND PROPERTY COMPILE_DEFINITIONS "NO_OPTIMIZED_MULTIPLY_ON_ARM")
    if (_slow_hash_hw_supported)
      set_property(SOURCE slow-hash-hw.c APPEND
        PROPERTY COMPILE_DEFINITIONS "NO_OPTIMIZED_MULTIPLY_ON_ARM")
    endif()
  endif()
endif()

# Because of the way Qt works on android with JNI, the code does not live in the main android thread
# So this code runs with a 1 MB default stack size. 
# This will force the use of the heap for the allocation of the scratchpad
if (ANDROID OR IOS)
  if( BUILD_GUI_DEPS )
    add_definitions(-DFORCE_USE_HEAP=1)
  endif()
endif()

# cheat because cmake and ccache hate each other
set_property(SOURCE CryptonightR_template.S PROPERTY LANGUAGE C)
set_property(SOURCE CryptonightR_template.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)
