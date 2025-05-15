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

#ifndef CRYPTONOTE_PROTOCOL_TXREQUESTQUEUE_H
#define CRYPTONOTE_PROTOCOL_TXREQUESTQUEUE_H

#include <boost/functional/hash.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <mutex>
#include <set>
#include <shared_mutex>

#include "misc_log_ex.h"
#include "string_tools.h"

/**
 * \brief A queue of requests. The front of the queue shows the current request.
 *
 * This queue holds peers that have the requested transaction and keeps
 * track of the time the last request was made. It provides capabilities
 * to add a new peer and to retrieve the next peer that hasn't been requested.
 */
class TxRequestQueue {
  using RWLock = std::shared_timed_mutex;
  using ReadLock = std::shared_lock<RWLock>;
  using WriteLock = std::unique_lock<RWLock>;

private:
  /**
   * \brief Represents a request that we have sent to a peer.
   *
   * Contains the peer's connection UUID, the request status, and the time
   * the requested tx was first seen.
   */
  class TxRequest {
    const boost::uuids::uuid from_connection_id;
    const std::time_t first_seen;
    std::time_t request_time;

    TxRequest &operator=(const TxRequest &other) = delete;
    TxRequest(const TxRequest &other) = delete;
    bool operator>(const TxRequest &other) const = delete;
    bool operator<(const TxRequest &other) const = delete;

  public:
    struct Order {
      bool operator()(const TxRequest &lhs, const TxRequest &rhs) const {
        return lhs.from_connection_id != rhs.from_connection_id &&
               lhs.first_seen < rhs.first_seen;
      }
    };

    TxRequest(const boost::uuids::uuid &id, std::time_t s)
        : from_connection_id(id), first_seen(s), request_time(0) {}

    TxRequest(TxRequest &&other) noexcept
        : from_connection_id(other.from_connection_id),
          first_seen(other.first_seen), request_time(other.request_time) {}

    bool operator==(const TxRequest &other) const {
      return from_connection_id == other.get_connection_id();
    }
    bool operator!=(const TxRequest &other) const {
      return from_connection_id != other.get_connection_id();
    }

    const boost::uuids::uuid &get_connection_id() const {
      return from_connection_id;
    }
    bool is_request_submitted() const { return !request_time; }
    void submit_request(std::time_t request_time) {
      this->request_time = request_time;
    }
    std::time_t get_first_seen() const { return first_seen; }
    std::time_t get_request_time() const { return request_time; }
    void set_request_time(std::time_t time) { request_time = time; }
  };

  mutable RWLock lock;
  std::set<TxRequest, TxRequest::Order> request_queue;

  TxRequestQueue &operator=(const TxRequestQueue &other) = delete;
  TxRequestQueue(const TxRequestQueue &other) = delete;
  bool operator>(const TxRequestQueue &other) const = delete;
  bool operator<(const TxRequestQueue &other) const = delete;

public:
  // Constructor that takes the first peer
  TxRequestQueue(const boost::uuids::uuid &id, std::time_t first_seen) {
    MINFO("Creating request queue with ID: "
          << epee::string_tools::pod_to_hex(id)
          << ", first seen: " << first_seen);
    WriteLock w_lock(lock);
    TxRequest request(id, first_seen);
    request.submit_request(first_seen);
    request_queue.emplace(std::move(request));
  }

  TxRequestQueue(TxRequestQueue &&other) noexcept
      : request_queue(std::move(other.request_queue)) {
    // No need to lock the mutex here, as the other object is being moved
    // and will not be used anymore.
    // The mutex is not moved, so it will be destructed when the other
    // object goes out of scope.
  }

  // Add a peer to the queue; updates request_time if it was requested
  void add_peer(const boost::uuids::uuid &id, std::time_t first_seen) {
    MINFO("Adding " << epee::string_tools::pod_to_hex(id)
                    << " to request queue "
                    << epee::string_tools::pod_to_hex(first_seen));
    WriteLock w_lock(lock);
    TxRequest request(id, first_seen);
    // only add if it is not already in the queue
    if (request_queue.find(request) == request_queue.end()) {
      request_queue.insert(std::move(request));
    }
  }

  std::time_t get_request_time() const {
    MINFO("Getting request time");
    ReadLock r_lock(lock);
    if (!request_queue.empty()) {
      MINFO("Connection ID: " << epee::string_tools::pod_to_hex(
                                     request_queue.begin()->get_connection_id())
                              << ", request time: "
                              << request_queue.begin()->get_request_time());
      return request_queue.begin()->get_request_time();
    }
    return 0;
  }

  // Get the next peer that we haven’t requested from yet.
  // If the front has already been requested and we consider it failed, pop it.
  boost::uuids::uuid request_from_next_peer(std::time_t now) {
    MINFO("Requesting from next peer");
    WriteLock w_lock(lock);
    while (!request_queue.empty()) {
      // Get the front of the queue, and strip constness
      // Since we don't modify data which would change the order
      TxRequest &front = const_cast<TxRequest &>(*request_queue.begin());
      if (!front.is_request_submitted()) // not requested yet
      {
        front.submit_request(now);
        MINFO("Requesting from peer: "
              << epee::string_tools::pod_to_hex(front.get_connection_id()));
        return front.get_connection_id();
      }
      // already requested and considered stale, pop first
      request_queue.erase(request_queue.begin());
    }
    MINFO("No peers available to request from");
    return boost::uuids::nil_uuid();
  }
};

#endif // CRYPTONOTE_PROTOCOL_TXREQUESTQUEUE_H