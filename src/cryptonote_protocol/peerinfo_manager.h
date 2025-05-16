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

#ifndef CRYPTONOTE_PROTOCOL_PEERINFO_MANAGER_H
#define CRYPTONOTE_PROTOCOL_PEERINFO_MANAGER_H

#include <boost/functional/hash.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_set>

#include "crypto/hash.h"
#include "misc_log_ex.h"
#include "string_tools.h"

class peer_info_manager {

  constexpr static size_t FAILURE_THRESHOLD_PERCENTAGE = 70;

public:
  class peer_info {
    using rw_lock = std::shared_timed_mutex;
    using read_lock = std::shared_lock<rw_lock>;
    using write_lock = std::unique_lock<rw_lock>;

  private:
    boost::uuids::uuid m_connection_id;
    std::unordered_set<crypto::hash> m_announcements;
    size_t m_received = 0;
    size_t m_requested_from_me = 0;
    size_t m_requested_from_peer = 0;
    size_t m_sent = 0;
    size_t m_missed = 0;
    mutable rw_lock m_lock;

  public:
    peer_info(const boost::uuids::uuid &id)
        : m_connection_id(id), m_announcements(0), m_received(0),
          m_requested_from_me(0), m_requested_from_peer(0), m_sent(0),
          m_missed(0), m_lock() {}

    peer_info(peer_info &&other) noexcept
        : m_connection_id(other.m_connection_id),
          m_announcements(other.m_announcements), m_received(other.m_received),
          m_requested_from_me(other.m_requested_from_me),
          m_requested_from_peer(other.m_requested_from_peer),
          m_sent(other.m_sent), m_missed(other.m_missed) {
      // The lock is not moved. Each moved-to object gets its own
    }

    struct hash {
      std::size_t operator()(const peer_info &p) const {
        // We don't care about the bool value, so we only hash the UUID
        return boost::hash<boost::uuids::uuid>()(p.get_connection_id());
      }
    };

    peer_info &operator=(const peer_info &other) = delete;
    peer_info(const peer_info &other) = delete;
    bool operator>(const peer_info &other) const = delete;
    bool operator<(const peer_info &other) const = delete;

    bool operator==(const peer_info &other) const {
      read_lock r_lock(m_lock);
      return m_connection_id == other.get_connection_id();
    }

    bool operator!=(const peer_info &other) const {
      read_lock r_lock(m_lock);
      return m_connection_id != other.get_connection_id();
    }

    void reset() {
      write_lock w_lock(m_lock);
      m_announcements.clear();
      m_received = 0;
      m_requested_from_me = 0;
      m_sent = 0;
    }

    void add_announcement(const crypto::hash &tx_hash) {
      write_lock w_lock(m_lock);
      m_announcements.insert(tx_hash);
    }

    void add_received() {
      write_lock w_lock(m_lock);
      ++m_received;
    }

    void add_requested_from_me() {
      write_lock w_lock(m_lock);
      ++m_requested_from_me;
    }

    void add_requested_from_peer() {
      write_lock w_lock(m_lock);
      ++m_requested_from_peer;
    }

    void add_sent() {
      write_lock w_lock(m_lock);
      ++m_sent;
    }

    void add_missed() {
      write_lock w_lock(m_lock);
      ++m_missed;
    }

    size_t get_announcement_size() const {
      read_lock r_lock(m_lock);
      return m_announcements.size();
    }

    size_t get_received() const {
      read_lock r_lock(m_lock);
      return m_received;
    }

    size_t get_requested_from_me() const {
      read_lock r_lock(m_lock);
      return m_requested_from_me;
    }

    size_t get_requested_from_peer() const {
      read_lock r_lock(m_lock);
      return m_requested_from_peer;
    }

    size_t get_sent() const {
      read_lock r_lock(m_lock);
      return m_sent;
    }

    const boost::uuids::uuid &get_connection_id() const {
      return m_connection_id;
    }

    size_t get_total() const {
      read_lock r_lock(m_lock);
      return m_announcements.size() + m_received + m_requested_from_me +
             m_requested_from_peer + m_sent;
    }

    size_t get_missed() const {
      read_lock r_lock(m_lock);
      return m_missed;
    }

    std::string get_info() const {
      read_lock r_lock(m_lock);

      std::ostringstream oss;
      oss << "Peer ID: " << epee::string_tools::pod_to_hex(m_connection_id)
          << ", Announcements size: " << m_announcements.size()
          << ", Received: " << m_received
          << ", Requested from me : " << m_requested_from_me
          << ", Requested from peer: " << m_requested_from_peer
          << ", Sent: " << m_sent << ", Missed: " << m_missed;
      return oss.str();
    }
  };

private:
  std::unordered_set<peer_info, peer_info::hash> m_peer_info;

public:
  peer_info_manager() = default;

  void add_peer(const boost::uuids::uuid &id) { m_peer_info.emplace(id); }

  void remove_peer(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      m_peer_info.erase(it);
    }
  }

  std::string get_peer_info(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_info();
    }
    return std::string();
  }

  std::string get_all_peers_info() const {
    std::ostringstream oss;
    oss << "Total Peers: " << m_peer_info.size() << std::endl;
    oss << "Peer Information:" << std::endl;
    for (const auto &peer : m_peer_info) {
      oss << peer.get_info() << std::endl;
    }
    return oss.str();
  }

  void reset_peer_info(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      // We need to cast away constness, since we don't change hash of the
      // object
      const_cast<peer_info &>(*it).reset();
    }
  }

  void add_announcement(const boost::uuids::uuid &id,
                        const crypto::hash &tx_hash) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_announcement(tx_hash);
    } else {
      peer_info new_peer(id);
      new_peer.add_announcement(tx_hash);
      m_peer_info.emplace(std::move(new_peer));
    }
  }

  void add_received(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_received();
    } else {
      peer_info new_peer(id);
      new_peer.add_received();
      m_peer_info.emplace(std::move(new_peer));
    }
  }

  void add_requested_from_me(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_requested_from_me();
    } else {
      peer_info new_peer(id);
      new_peer.add_requested_from_me();
      m_peer_info.emplace(std::move(new_peer));
    }
  }

  void add_requested_from_peer(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_requested_from_peer();
    } else {
      peer_info new_peer(id);
      new_peer.add_requested_from_peer();
      m_peer_info.emplace(std::move(new_peer));
    }
  }

  void add_sent(const boost::uuids::uuid &id) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_sent();
    } else {
      peer_info new_peer(id);
      new_peer.add_sent();
      m_peer_info.emplace(std::move(new_peer));
    }
  }

  size_t get_announcement(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_announcement_size();
    }
    return 0;
  }

  size_t get_received(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_received();
    }
    return 0;
  }

  size_t get_requested_from_me(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_requested_from_me();
    }
    return 0;
  }

  size_t get_requested_from_peer(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_requested_from_peer();
    }
    return 0;
  }

  size_t get_sent(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_sent();
    }
    return 0;
  }

  size_t get_total(const boost::uuids::uuid &id) const {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      return it->get_total();
    }
    return 0;
  }

  bool missed_announced_tx(const boost::uuids::uuid &id,
                           const crypto::hash &tx_hash) {
    auto it = std::find_if(m_peer_info.begin(), m_peer_info.end(),
                           [&id](const peer_info &peer) {
                             return peer.get_connection_id() == id;
                           });
    if (it != m_peer_info.end()) {
      const_cast<peer_info &>(*it).add_missed();
      // FAILURE_THRESHOLD_PERCENTAGE% of the announcements are missed
      return (it->get_missed() * 100 / it->get_announcement_size()) >
             FAILURE_THRESHOLD_PERCENTAGE;
    } else {
      MWARNING("Peer not found: " << epee::string_tools::pod_to_hex(id)
                                  << ", tx: "
                                  << epee::string_tools::pod_to_hex(tx_hash)
                                  << ", cannot check missed announcements");
    }
    return false;
  }
};

#endif // CRYPTONOTE_PROTOCOL_PEERINFO_MANAGER_H