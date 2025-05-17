// Copyright (c) 2014-2025, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//

#ifndef CRYPTONOTE_PROTOCOL_REQUEST_MANAGER_H
#define CRYPTONOTE_PROTOCOL_REQUEST_MANAGER_H

#include "crypto/hash.h"
#include "string_tools.h"
#include "txrequestqueue.h"
#include <boost/functional/hash.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

class request_manager {

  using rw_lock = std::shared_timed_mutex;
  using read_lock = std::shared_lock<rw_lock>;
  using write_lock = std::unique_lock<rw_lock>;

private:
  // Track requested transactions
  std::unordered_map<crypto::hash, tx_request_queue> m_requested_txs;
  mutable rw_lock m_lock;

  request_manager &operator=(const request_manager &other) = delete;
  request_manager(const request_manager &other) = delete;
  bool operator>(const request_manager &other) const = delete;
  bool operator<(const request_manager &other) const = delete;

public:
  request_manager() : m_requested_txs(), m_lock() {}

  bool remove_transaction(const crypto::hash &tx_hash) {
    MINFO("Removing transaction: " << epee::string_tools::pod_to_hex(tx_hash));
    write_lock w_lock(m_lock);
    auto it = m_requested_txs.find(tx_hash);
    if (it != m_requested_txs.end()) {
      m_requested_txs.erase(it);
      return true;
    }
    return false;
  }

  bool already_requested_tx(const crypto::hash &tx_hash) const {
    read_lock r_lock(m_lock);
    return m_requested_txs.find(tx_hash) != m_requested_txs.end();
  }

  void initial_add(const crypto::hash &tx_hash, const boost::uuids::uuid &id,
                   std::time_t first_seen) {
    MINFO("Initial add of transaction: "
          << epee::string_tools::pod_to_hex(tx_hash)
          << ", from peer: " << epee::string_tools::pod_to_hex(id)
          << ", first seen: " << first_seen);
    write_lock w_lock(m_lock);
    m_requested_txs.emplace(tx_hash, tx_request_queue(id, first_seen));
  }

  void add_peer(const crypto::hash &tx_hash, const boost::uuids::uuid &id,
                std::time_t first_seen) {
    MINFO("Adding peer: " << epee::string_tools::pod_to_hex(id)
                          << " to transaction: "
                          << epee::string_tools::pod_to_hex(tx_hash)
                          << ", first seen: " << first_seen);
    write_lock w_lock(m_lock);
    auto it = m_requested_txs.find(tx_hash);
    if (it != m_requested_txs.end()) {
      it->second.add_peer(id, first_seen);
    }
  }

  bool add_transaction(const crypto::hash &tx_hash,
                       const boost::uuids::uuid &id, std::time_t first_seen) {
    MINFO("Adding transaction: " << epee::string_tools::pod_to_hex(tx_hash)
                                 << ", from peer: "
                                 << epee::string_tools::pod_to_hex(id)
                                 << ", first seen: " << first_seen);
    if (!already_requested_tx(tx_hash)) {
      // This tx has not been requested yet; mark it.
      initial_add(tx_hash, id, first_seen);
      return true;
    } else {
      // already requested from other peer, keep the peer in request queue
      add_peer(tx_hash, id, first_seen);
      return false;
    }
  }

  void
  for_each_request(std::function<void(const crypto::hash &tx_hash,
                                      tx_request_queue &request_queue,
                                      const std::time_t request_deadline)> &f,
                   const std::time_t m_request_deadline) {
    MINFO("Iterating over requested transactions for deadline: "
          << m_request_deadline);
    read_lock r_lock(m_lock);
    for (auto &pair : m_requested_txs) {
      f(pair.first, pair.second, m_request_deadline);
    }
  }
};

#endif // CRYPTONOTE_PROTOCOL_REQUEST_MANAGER_H