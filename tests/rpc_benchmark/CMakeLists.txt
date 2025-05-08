# Copyright (c) 2014-2023, The Monero Project
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

set(rpc_benchmark_sources
  rpc_benchmark.cpp)

set(rpc_benchmark_headers
  rpc_benchmark.h)

monero_add_minimal_executable(rpc_benchmark
  ${rpc_benchmark_sources}
  ${rpc_benchmark_headers})

target_include_directories(rpc_benchmark 
  PUBLIC
    ${Boost_INCLUDE_DIRS})  
target_link_libraries(rpc_benchmark
  PRIVATE
    cryptonote_protocol
    cryptonote_core
    daemon_messages
    daemon_rpc_server
    blockchain_db
    lmdb_lib
    rpc
    net
    serialization
    seraphis_crypto
    wallet
    p2p
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})
set_property(TARGET rpc_benchmark
  PROPERTY
    FOLDER "tests")

if (NOT MSVC)
  set_property(TARGET rpc_benchmark
    APPEND_STRING
    PROPERTY
      COMPILE_FLAGS " -Wno-undef -Wno-sign-compare")
endif ()

add_test(
  NAME    rpc_benchmark
  COMMAND rpc_benchmark --data-dir "${TEST_DATA_DIR}")
