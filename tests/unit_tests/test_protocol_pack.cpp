// Copyright (c) 2014-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "include_base_utils.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "storages/portable_storage_template_helper.h"

TEST(protocol_pack, protocol_pack_command) 
{
  epee::byte_slice buff;
  cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
  r.start_height = 1;
  r.total_height = 3;
  for(int i = 1; i < 10000; i += i*10)
  {
    r.m_block_ids.resize(i, crypto::hash{});
    bool res = epee::serialization::store_t_to_binary(r, buff);
    ASSERT_TRUE(res);

    cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request r2;
    res = epee::serialization::load_t_from_binary(r2, epee::to_span(buff));
    ASSERT_TRUE(res);
    ASSERT_TRUE(r.m_block_ids.size() == i);
    ASSERT_TRUE(r.start_height == 1);
    ASSERT_TRUE(r.total_height == 3);
  }
}

std::string gen_random_string2(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}


namespace
{
  static const constexpr epee::serialization::portable_storage::limits_t default_levin_limits = {
    8192, // objects
    16384, // fields
    16384, // strings
  };
}

TEST(protocol_pack, torture_number)
{

  std::vector<std::string> vinput;

  for(size_t j = 0; j < (16386); j++) {
    vinput.push_back(gen_random_string2(4));
  }

  epee::byte_slice buff;
  cryptonote::TORTURE_ENTRY::request r;
  r.torture_field = vinput;
  bool res = epee::serialization::store_t_to_binary(r, buff);
  ASSERT_TRUE(res);

  cryptonote::TORTURE_ENTRY::request r2;
  res = epee::serialization::load_t_from_binary(r2, epee::to_span(buff), &default_levin_limits);
  ASSERT_TRUE(res);
  EXPECT_EQ(r.torture_field, r2.torture_field);

}
