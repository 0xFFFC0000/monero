// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 




#ifndef __WINH_OBJ_H__
#define __WINH_OBJ_H__

#include <boost/chrono/duration.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>
#include <misc_log_ex.h>

namespace epee
{

  namespace debug
  {
    inline unsigned int &g_test_dbg_lock_sleep()
    {
      static unsigned int value = 0;
      return value;
    }
  }
  
  struct simple_event
  {
    simple_event() : m_rised(false)
    {
    }

    void raise()
    {
      boost::unique_lock<boost::mutex> lock(m_mx);
      m_rised = true;
      m_cond_var.notify_one();
    }

    void wait()
    {
      boost::unique_lock<boost::mutex> lock(m_mx);
      while (!m_rised) 
        m_cond_var.wait(lock);
      m_rised = false;
    }

  private:
    boost::mutex m_mx;
    boost::condition_variable m_cond_var;
    bool m_rised;
  };

  class critical_region;

  class critical_section
  {
    boost::recursive_mutex m_section;

  public:
    //to make copy fake!
    critical_section(const critical_section& section)
    {
    }

    critical_section()
    {
    }

    ~critical_section()
    {
    }

    void lock()
    {
      m_section.lock();
      //EnterCriticalSection( &m_section );
    }

    void unlock()
    {
      m_section.unlock();
    }

    bool tryLock()
    {
      return m_section.try_lock();
    }

    // to make copy fake
    critical_section& operator=(const critical_section& section)
    {
      return *this;
    }
  };


  template<class t_lock>
  class critical_region_t
  {
    t_lock&	m_locker;
    bool m_unlocked;

    critical_region_t(const critical_region_t&) {}

  public:
    critical_region_t(t_lock& cs): m_locker(cs), m_unlocked(false)
    {
      m_locker.lock();
    }

    ~critical_region_t()
    {
      unlock();
    }

    void unlock()
    {
      if (!m_unlocked)
      {
        m_locker.unlock();
        m_unlocked = true;
      }
    }
  };
  

  struct reader_writer_lock {

    static const std::unique_ptr<reader_writer_lock> 
    createReader(boost::shared_mutex& read_write_mutex) noexcept {
      auto r_lock = std::make_unique<reader_writer_lock>(read_write_mutex);
      r_lock->start_read();
      return r_lock;
    }

    static const std::unique_ptr<reader_writer_lock> 
    createWriter(boost::shared_mutex& read_write_mutex) noexcept {
      auto rw_lock = std::make_unique<reader_writer_lock>(read_write_mutex);
      rw_lock->start_write();
      return rw_lock;
    }

    ~reader_writer_lock() noexcept {
      if (write_lock.owns_lock()) {
        write_lock.release();
      }      
      else if (read_lock.owns_lock()) {
        read_lock.release();
      }
    };

    void start_read() noexcept {
      read_lock.lock();
    }

    void end_read() noexcept {
      read_lock.unlock();
      condition.notify_all();
    }

    void start_write() noexcept {
      lock();
    }

    void end_write() noexcept {
      write_lock.unlock();
      condition.notify_all();
    }

    bool is_read_locked() noexcept {
      return read_lock.owns_lock() || write_lock.owns_lock();
    }

    bool is_write_locked() noexcept {
      return write_lock.owns_lock();
    }

    reader_writer_lock(boost::shared_mutex& read_write_mutex) noexcept :
    read_lock(read_write_mutex, boost::defer_lock),
    write_lock(read_write_mutex, boost::defer_lock) {}

    reader_writer_lock(reader_writer_lock&) = delete;
    reader_writer_lock operator=(reader_writer_lock&) = delete;

  private:

    void lock() noexcept {
      do {  
        boost::unique_lock<boost::mutex> lock(t_mutex);
        try {
          if(write_lock.try_lock()) {
            return; 
          }
        } catch (std::system_error& se) {
          MDEBUG("Failed to lock : " << se.what());
        }
        condition.wait(lock);
      } while(true);
    }

    boost::shared_lock<boost::shared_mutex> read_lock;
    boost::unique_lock<boost::shared_mutex> write_lock;
    boost::mutex t_mutex; // write_lock and owner_id should always be consistent
    boost::condition_variable_any condition;

  };


#define  CRITICAL_REGION_LOCAL(x) {} epee::critical_region_t<decltype(x)>   critical_region_var(x)
#define  CRITICAL_REGION_BEGIN(x) { boost::this_thread::sleep_for(boost::chrono::milliseconds(epee::debug::g_test_dbg_lock_sleep())); epee::critical_region_t<decltype(x)>   critical_region_var(x)
#define  CRITICAL_REGION_LOCAL1(x) {boost::this_thread::sleep_for(boost::chrono::milliseconds(epee::debug::g_test_dbg_lock_sleep()));} epee::critical_region_t<decltype(x)>   critical_region_var1(x)
#define  CRITICAL_REGION_BEGIN1(x) {  boost::this_thread::sleep_for(boost::chrono::milliseconds(epee::debug::g_test_dbg_lock_sleep())); epee::critical_region_t<decltype(x)>   critical_region_var1(x)

#define  CRITICAL_REGION_END() }

}

#endif
