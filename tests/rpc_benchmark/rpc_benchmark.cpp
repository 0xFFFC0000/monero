// Copyright (c) 2020-2023, The Monero Project

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

#include <boost/chrono/duration.hpp>
#include <boost/exception/exception.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/process.hpp>
#include <boost/process/search_path.hpp>
#include <boost/process/spawn.hpp>
#include <boost/program_options.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/lock_types.hpp>
#include <boost/thread/pthread/condition_variable_fwd.hpp>
#include <boost/thread/pthread/shared_mutex.hpp>
#include <boost/thread/pthread/thread_data.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "daemon/command_server.h"
#include "misc_log_ex.h"
#include "net/http_client.h"
#include "net/net_utils_base.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/rpc_args.h"
#include "serialization/keyvalue_serialization.h"
#include "span.h"
#include "storages/http_abstract_invoke.h"
#include "storages/portable_storage.h"
#include "storages/portable_storage_template_helper.h"
#include "wallet/wallet_rpc_server_commands_defs.h"

namespace process = boost::process;
namespace filesystem = boost::filesystem;
namespace po = boost::program_options;

// LTRACE( "A trace severity message";
// LDEBUG << "A debug severity message";
// // LINFO( "An informational severity message";
// LWARNING << "A warning severity message";
// LERROR << "An error severity message";
// LFATAL( "A fatal severity message";

#define LTRACE(x) LOG_PRINT_L4(x)
#define LDEBUG(x) LOG_PRINT_L3(x)
#define LINFO(x) LOG_PRINT_L0(x)
#define LWARNING(x) LOG_PRINT_L1(x)
#define LERROR(x) LOG_PRINT_L0(x)
#define LFATAL(x) LOG_ERROR(x)

#define LDIE(msg, err)                                                        \
  {                                                                           \
    LFATAL(                                                                   \
        (msg) << " : " << __LINE__ << " : " << __FUNCTION__ << ". exiting."); \
    exit(err);                                                                \
  }

// Root directory containing all tests
std::string test_root;

// Numbers of wallets to run
uint32_t number_of_wallets;

// how long it should mine
uint32_t mine_time;

// how many times a cycle (open_wallet / refresh / close) should run.
uint32_t benchmark_iteration;

#define MAX_NUMBER_OF_WALLETS (1024 << 2)
#define MAX_MINE_TIME (1024 << 2)
#define MAX_BENCHMARK_ITERATION_TIME (1024 << 8)
#define MAX_NUMBER_OF_BLOCKS 50000

namespace WalletRPC
{

std::mutex address_wallet_mutex;
std::map<size_t, std::string> address_wallet;

const int RPC_BASE_PORT = 20048;
const std::string RPC_DEFAULT_IP = "127.0.0.1";

const std::string EXEC_NAME = "monero-wallet-rpc";
filesystem::path EXEC_PATH;

const std::string MAINNET{"--mainnet"};
const std::string NO_INITIAL_SYNC{"--no-initial-sync"};
const std::string TESTNET{"--testnet"};
const std::string REGTEST{"--regtest"};
const std::string DAEMON_SSL_ALLOW_ANY_CERT{"--daemon-ssl-allow-any-cert"};
const std::string DISABLE_RPC_LOGIN{"--disable-rpc-login"};
const std::string NON_INTERACTIVE{"--non-interactive"};
const boost::format RPC_SSL_CONTAINER{"--rpc-ssl=%s"};
const boost::format DAEMON_SSL_CONTAINER{"--daemon-ssl=%s"};
const boost::format RPC_BIND_IP_CINTAINER{"--rpc-bind-ip=%s"};
const boost::format RPC_BIND_PORT_CONTAINER{"--rpc-bind-port=%s"};
const boost::format MAX_CONCURRENCY_CONTAINER{"--max-concurrency=%s"};
const boost::format DAEMON_ADDRESS_CONTAINER{"--daemon-address=%s:%s"};
const boost::format WALLET_DIR_CONTAINER{"--wallet-dir=%s"};
const boost::format PASSWORD_CONTAINER{"--password=%s"};
const boost::format LOG_LEVEL_CONTAINER{"--log-level=%s"};
const boost::format SHARED_RINGDB_DIR_CONTAINER{"--shared-ringdb-dir=%s"};

struct walletrpc
{
  std::string ip_address = RPC_DEFAULT_IP;

  size_t rpc_port;
  size_t max_concurrency = 128;
  std::string daemon_ip_address;
  size_t daemon_port;
  std::string wallet_dir;
  std::string password;
  int log_level = 0;
  std::string shared_ringdb_dir;
};
std::string Default_wallet_location()
{
  return test_root + filesystem::path::preferred_separator + "wallets";
}

std::string get_wallet_name_for_ith(int index)
{
  return "Wallet_" + std::to_string(index);
}

}  // namespace WalletRPC

namespace Daemon
{
const std::string& EXEC_NAME = "monerod";
filesystem::path TEST_EXEC_PATH;
filesystem::path MASTER_EXEC_PATH;

const int RPC_BASE_PORT = 4096;
const int P2P_BASE_PORT = 28081;
const std::string RPC_DEFAULT_IP = "127.0.0.1";

const std::string NO_SYNC{"--no-sync"};
const std::string NO_ZMQ{"--no-zmq"};
const std::string OFFLINE{"--offline"};
const std::string TESTNET{"--testnet"};
const std::string REGTEST{"--regtest"};
const std::string MAINNET{"--mainnet"};
const std::string NON_INTERACTIVE{"--non-interactive"};
const std::string CONFIRM_EXTERNAL_BIND{"--confirm-external-bind"};
const std::string ALLOW_LOCAL_IP{"--allow-local-ip"};
const std::string DISABLE_RPC_BAN{"--disable-rpc-ban"};
const std::string NO_IGD{"--no-igd"};
const std::string HIDE_MY_PORT{"--hide-my-port"};
const std::string RPC_SSL_ALLOW_ANY_CERT{"--rpc-ssl-allow-any-cert"};
const std::string DISABLE_DNS_CHECKPOINTS{"--disable-dns-checkpoints"};
const boost::format RPC_SSL_CONTAINER{"--rpc-ssl=%s"};
const boost::format RPC_BIND_PORT_CONTAINER{"--rpc-bind-port=%s"};
const boost::format RPC_BIND_IP_CONTAINER{"--rpc-bind-ip=%s"};
const boost::format P2P_BIND_IP_CONTAINER{"--p2p-bind-ip=%s"};
const boost::format P2P_BIND_PORT_CONTAINER{"--p2p-bind-port=%s"};
const boost::format DATA_DIR_CONTAINER{"--data-dir=%s"};
const boost::format ADD_EXCLUSIVE_NODE_CONTAINER{"--add-exclusive-node=%s:%s"};
const boost::format DIFFICULTY_CONTAINER{"--fixed-difficulty=%s"};
const boost::format MAX_CONCURRENCY_CONTAINER{"--max-concurrency=%s"};
const boost::format LOG_LEVEL_CONTAINER{"--log-level=%s"};
const boost::format START_MINING_CONTAINER{"--start-mining=%s"};
const boost::format MAX_CONNECTIONS_PER_IP{"--max-connections-per-ip=%s"};
const boost::format MINING_THREADS{"--mining-threads=%s"};
const boost::format BLOCK_SYNC_SIZE_CONTAINER{"--block-sync-size=%s"};
const boost::format LIMIT_RATE_UP_CONTAINER{"--limit-rate-up=%s"};
const boost::format LIMIT_RATE_DOWN_CONTAINER{"--limit-rate-down=%s"};
// Temporary
// constexpr const char CONFIG_FILE_CONTAINER[] = "--config-file=%s";

struct daemon
{
  filesystem::path exec_path;
  std::string ip_address = RPC_DEFAULT_IP;
  int log_level = 0;
  size_t max_concurrency = 128;
  size_t max_connections_per_ip = 2048;
  size_t block_sync_size = 2048 << 16;
  size_t p2p_port;
  size_t mining_threads = 2;
  size_t rpc_port;
  size_t difficulty;
  std::string p2p_ip;
  std::string data_dir;
  std::vector<std::string> exclusive_nodes;
};

std::string Default_daemon_location(int index)
{
  return test_root + filesystem::path::preferred_separator + "daemons"
         + filesystem::path::preferred_separator + std::to_string(index);
}
}  // namespace Daemon

void run_wallet_rpc(
    WalletRPC::walletrpc& walletrpc,
    boost::condition_variable& terminator)
{
  process::ipstream pipe_stream;
  process::child wallet_rpc_process(
      WalletRPC::EXEC_PATH,
      WalletRPC::NO_INITIAL_SYNC,
      WalletRPC::TESTNET,
      WalletRPC::DAEMON_SSL_ALLOW_ANY_CERT,
      WalletRPC::DISABLE_RPC_LOGIN,
      WalletRPC::NON_INTERACTIVE,
      (boost::format(WalletRPC::RPC_SSL_CONTAINER) % std::string("disabled")).str(),
      (boost::format(WalletRPC::DAEMON_SSL_CONTAINER) % std::string("disabled")).str(),
      (boost::format(WalletRPC::DAEMON_ADDRESS_CONTAINER) % walletrpc.daemon_ip_address % std::to_string(walletrpc.daemon_port)).str(),
      (boost::format(WalletRPC::WALLET_DIR_CONTAINER) % walletrpc.wallet_dir).str(),
      (boost::format(WalletRPC::RPC_BIND_PORT_CONTAINER) % std::to_string(walletrpc.rpc_port)).str(),
      (boost::format(WalletRPC::LOG_LEVEL_CONTAINER) % std::to_string(walletrpc.log_level)).str(),
      (boost::format(WalletRPC::SHARED_RINGDB_DIR_CONTAINER) % walletrpc.shared_ringdb_dir).str(),
      (boost::format(WalletRPC::MAX_CONCURRENCY_CONTAINER) % std::to_string(walletrpc.max_concurrency)).str(),
      process::std_out > pipe_stream);

  std::string line;

  // wait for signal
  boost::mutex mutex;
  boost::unique_lock<boost::mutex> lock(mutex);
  terminator.wait(lock);

  LTRACE("Terminating wallet.");
  wallet_rpc_process.terminate();
  // if (wallet_rpc_process.joinable())
  //   wallet_rpc_process.join();
  return;
}

void create_offline_daemon(
    Daemon::daemon& daemon,
    boost::condition_variable& terminator)
{
  if (!filesystem::exists(daemon.exec_path))
    {
      LDIE(daemon.exec_path.string() + " does not exist.", -1);
    }

  process::ipstream pipe_stream;

  process::child daemon_process(
      daemon.exec_path,
      Daemon::NO_SYNC,
      Daemon::OFFLINE,
      // Daemon::TESTNET,
      Daemon::NO_IGD,
      Daemon::HIDE_MY_PORT,
      Daemon::DISABLE_RPC_BAN,      
      Daemon::NON_INTERACTIVE,
      Daemon::NO_ZMQ,
      (boost::format(Daemon::RPC_SSL_CONTAINER) % "disabled").str(),
      (boost::format(Daemon::P2P_BIND_IP_CONTAINER) % daemon.p2p_ip).str(),
      (boost::format(Daemon::P2P_BIND_PORT_CONTAINER) % std::to_string(daemon.p2p_port)).str(),
      (boost::format(Daemon::RPC_BIND_PORT_CONTAINER) % std::to_string(daemon.rpc_port)).str(),
      (boost::format(Daemon::MAX_CONCURRENCY_CONTAINER) % std::to_string(daemon.max_concurrency)).str(),
      (boost::format(Daemon::LIMIT_RATE_UP_CONTAINER) % std::to_string(std::numeric_limits<uint32_t>::max())).str(),
      (boost::format(Daemon::LIMIT_RATE_DOWN_CONTAINER) % std::to_string(std::numeric_limits<uint32_t>::max())).str(),      
      // (boost::format(Daemon::DATA_DIR_CONTAINER) % daemon.data_dir).str(),
      (boost::format(Daemon::LOG_LEVEL_CONTAINER) % std::to_string(daemon.log_level)).str(),
      process::std_out > pipe_stream);

  std::string line;

  // wait for signal
  boost::mutex mutex;
  boost::unique_lock<boost::mutex> lock(mutex);
  terminator.wait(lock);

  LTRACE("Terminating daemon.");
  daemon_process.terminate();
  if (daemon_process.joinable())
    daemon_process.join();
  return;
}

void parse_and_validate(int argc, char** argv)
{
  po::options_description desc("Allowed options");

  desc.add_options()(
      "test_builddir",
      po::value<std::string>(),
      "A directory that cointains test monero executables.");

  desc.add_options()(
      "master_builddir",
      po::value<std::string>(),
      "A directory that cointains master (vanilla) monero executables.");

  desc.add_options()(
      "test_root",
      po::value<std::string>(),
      "A directory that will contain all the blockchains and wallets.");

  desc.add_options()(
      "number_of_wallets",
      po::value<uint32_t>(),
      "Number of wallets that should be generated.");

  desc.add_options()(
      "mine_time", po::value<uint32_t>(), "How long it should mine.");

  desc.add_options()(
      "benchmark_iteration",
      po::value<uint32_t>(),
      "How mnay times cycle (open_wallet / refresh / close) should run.");

  desc.add_options()(
      "log_level",
      po::value<int>(),
      "Log level. can be: 4 (trace), 3 (debug), 1 (info), 0 (warning).");

  desc.add_options()("help", "Print usage.");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help"))
    {
      std::cout << "Usage: " << argv[0]
                << " [options] <description of positional 1> <description of "
                   "positional 2> ...\n";
      std::cout << desc;
      exit(0);
    }

  std::string test_builddir;
  if (vm.count("test_builddir"))
    {
      test_builddir = vm["test_builddir"].as<std::string>();
      if (!test_builddir.empty() && filesystem::exists(test_builddir)
          && filesystem::is_directory(test_builddir))
        {
          // LINFO( "test_builddir is " << test_builddir;
          Daemon::TEST_EXEC_PATH = test_builddir
                                   + filesystem::path::preferred_separator
                                   + Daemon::EXEC_NAME;
        }
    }
  else
    {
      LDIE("test_builddir is not defined.", -1);
    }

  std::string master_builddir;
  if (vm.count("master_builddir"))
    {
      master_builddir = vm["master_builddir"].as<std::string>();
      if (!master_builddir.empty() && filesystem::exists(master_builddir)
          && filesystem::is_directory(master_builddir))
        {
          // LINFO( "master_builddir is " << master_builddir;
          WalletRPC::EXEC_PATH = master_builddir
                                 + filesystem::path::preferred_separator
                                 + WalletRPC::EXEC_NAME;
          Daemon::MASTER_EXEC_PATH = master_builddir
                                     + filesystem::path::preferred_separator
                                     + Daemon::EXEC_NAME;
        }
    }
  else
    {
      LFATAL(
          "master_builddir is not defined. using default monero intalled file");
      WalletRPC::EXEC_PATH = process::search_path(WalletRPC::EXEC_NAME);
      Daemon::MASTER_EXEC_PATH = process::search_path(Daemon::EXEC_NAME);
      if (WalletRPC::EXEC_PATH.string().empty()
          || Daemon::MASTER_EXEC_PATH.string().empty())
        {
          LDIE("Cannot find monero-wallet-rpc and/or monerod executable.", -1);
        }
      LFATAL("Will use " << WalletRPC::EXEC_PATH << " as monero-wallet-rpc.");
      LFATAL("Will use " << Daemon::MASTER_EXEC_PATH << " as monerod.");
    }

  test_root = filesystem::path(getenv("HOME")).string()
              + filesystem::path::preferred_separator + "testnet";
  if (vm.count("test_root"))
    {
      test_root = vm["test_root"].as<std::string>();
      if (!test_root.empty() && filesystem::exists(test_root)
          && filesystem::is_directory(test_root))
        {
          // LINFO( "test_root is " << test_root;
        }
      else if (!test_root.empty() && !filesystem::exists(test_root))
        {
          filesystem::create_directory(test_root);
          // LINFO( "test_root is " << test_root;
        }
    }
  else
    {
      LFATAL("test_root is not defined.");
      LFATAL("Will use " << test_root << " as test root directory.");
    }

  number_of_wallets = 12;
  if (vm.count("number_of_wallets"))
    {
      if (vm["number_of_wallets"].as<uint32_t>() < MAX_NUMBER_OF_WALLETS)
        {
          number_of_wallets = vm["number_of_wallets"].as<uint32_t>();
        }
      else
        {
          LDIE("number_of_wallets is invalid.", -1);
        }
    }

  mine_time = 30;
  if (vm.count("mine_time"))
    {
      if (vm["mine_time"].as<uint32_t>() < MAX_MINE_TIME)
        {
          mine_time = vm["mine_time"].as<uint32_t>();
        }
      else
        {
          LDIE("mine_time is invalid.", -1);
        }
    }

  benchmark_iteration = 10;
  if (vm.count("benchmark_iteration"))
    {
      if (vm["benchmark_iteration"].as<uint32_t>()
          < MAX_BENCHMARK_ITERATION_TIME)
        {
          benchmark_iteration = vm["benchmark_iteration"].as<uint32_t>();
        }
      else
        {
          LDIE("benchmark_iteration is invalid.", -1);
        }
    }

  if (vm.count("log_level"))
    {
      mlog_set_log_level(vm["log_level"].as<int>());
      // set_log_level(vm["log_level"].as<std::string>());
    }
  else
    {
      mlog_set_log_level(1);
      // set_log_level("info"); // default log level
    }

  LINFO("mine_time is " << mine_time);
  LINFO("number_of_wallets is " << number_of_wallets);
  LINFO("benchmark_iteration is " << benchmark_iteration);
}

void generate_create_wallet_request(int index, tools::wallet_rpc::COMMAND_RPC_CREATE_WALLET::request& request)
{
  request.filename = "Wallet_" + std::to_string(index);
  request.password = "''";
  request.language = "English";
  return;
}

void generate_get_address_request(int index, tools::wallet_rpc::COMMAND_RPC_GET_ADDRESS::request& request)
{
  request.account_index = 0;
  request.address_index = {0};
  return;
}

void create_n_wallets()
{
  Daemon::daemon daemon;
  daemon.ip_address = daemon.p2p_ip = Daemon::RPC_DEFAULT_IP;
  daemon.p2p_port = Daemon::P2P_BASE_PORT;
  daemon.rpc_port = Daemon::RPC_BASE_PORT;
  daemon.data_dir = Daemon::Default_daemon_location(1);
  daemon.log_level = 0;
  daemon.exec_path = Daemon::MASTER_EXEC_PATH;
  boost::condition_variable daemon_terminator;
  std::thread daemon_thread(
      create_offline_daemon, std::ref(daemon), std::ref(daemon_terminator));

  if (!filesystem::exists(WalletRPC::EXEC_PATH))
    {
      LDIE(WalletRPC::EXEC_PATH.string() + " does not exist.", -1);
    }

  if (filesystem::exists(WalletRPC::Default_wallet_location()))
    {
      try
        {
          filesystem::remove(WalletRPC::Default_wallet_location());
        }
      catch (boost::filesystem::filesystem_error fe)
        {
          LDIE(fe.what(), -1);
        }
    }

  filesystem::create_directory(WalletRPC::Default_wallet_location());

  boost::condition_variable wallet_terminator;
  auto wallet_rpc_creator = [&wallet_terminator](int index) {
    WalletRPC::walletrpc walletrpc;
    walletrpc.rpc_port = WalletRPC::RPC_BASE_PORT + index;
    walletrpc.password = "''";
    walletrpc.daemon_port = Daemon::RPC_BASE_PORT;
    walletrpc.ip_address = walletrpc.daemon_ip_address =
        WalletRPC::RPC_DEFAULT_IP;
    walletrpc.log_level = 0;
    walletrpc.max_concurrency = 128;
    walletrpc.wallet_dir = WalletRPC::Default_wallet_location();
    walletrpc.shared_ringdb_dir = WalletRPC::Default_wallet_location();
    std::thread wallet_rpc_thread(
        run_wallet_rpc, std::ref(walletrpc), std::ref(wallet_terminator));
    if (wallet_rpc_thread.joinable())
      wallet_rpc_thread.join();
  };

  std::vector<std::thread> wallet_rpc_jobs;
  for (int index = 0; index < number_of_wallets; ++index)
    {
      wallet_rpc_jobs.push_back(std::thread(wallet_rpc_creator, index));
    }

  // std::this_thread::sleep_for(std::chrono::seconds(number_of_wallets > 10 ? number_of_wallets : 10));
  std::this_thread::sleep_for(std::chrono::seconds(10));

  auto wallet_creater_call = [&](int index) {
      epee::net_utils::http::http_simple_client http_simple_client{};
      http_simple_client.set_server(WalletRPC::RPC_DEFAULT_IP, std::to_string(WalletRPC::RPC_BASE_PORT + index), boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled);

      // Create Wallet
      {
        tools::wallet_rpc::COMMAND_RPC_CREATE_WALLET::request request;
        tools::wallet_rpc::COMMAND_RPC_CREATE_WALLET::response response;
        generate_create_wallet_request(index, request);
        bool result = epee::net_utils::invoke_http_json_rpc("/json_rpc", "create_wallet", request, response, http_simple_client);
      }

      // Get Address
      {
        tools::wallet_rpc::COMMAND_RPC_GET_ADDRESS::request request;
        tools::wallet_rpc::COMMAND_RPC_GET_ADDRESS::response response;
        generate_get_address_request(index, request);
        bool result = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_address", request, response, http_simple_client);
        LTRACE( index << " : response.addresses.size() : " << response.addresses.size() );
        LTRACE( index << " : response.address : " << response.address << std::endl );
        std::lock_guard<std::mutex> lock(WalletRPC::address_wallet_mutex);
        WalletRPC::address_wallet.insert(std::make_pair(index, response.address));
      }
      http_simple_client.disconnect();
  };

  std::vector<std::thread> wallet_creator_jobs;
  wallet_creator_jobs.clear();
  for (int index = 0; index < number_of_wallets; ++index) {
      wallet_creator_jobs.push_back(std::thread(wallet_creater_call, index));
  }

  for (int index = 0; index < number_of_wallets; ++index) {
      if (wallet_creator_jobs.at(index).joinable())
          wallet_creator_jobs.at(index).join();
  }

  wallet_terminator.notify_all();
  daemon_terminator.notify_all();

  for (int index = 0; index < number_of_wallets; ++index) {
      if (wallet_rpc_jobs.at(index).joinable())
          wallet_rpc_jobs.at(index).join();
  }

  if (daemon_thread.joinable())
      daemon_thread.join();
}

void run_miner(Daemon::daemon& daemon, int index, int seconds)
{
  process::ipstream pipe_stream;

  std::vector<std::string> exclusive_nodes;

  for (int i = 0; i < number_of_wallets; ++i)
    {
      if (i == index)
        continue;
      exclusive_nodes.push_back(
        (boost::format(Daemon::ADD_EXCLUSIVE_NODE_CONTAINER)
         % daemon.ip_address
         % std::to_string(Daemon::P2P_BASE_PORT + i)).str()
      );
    }

  process::child daemon_process(
      daemon.exec_path,
      Daemon::NON_INTERACTIVE,
      Daemon::RPC_SSL_ALLOW_ANY_CERT,
      Daemon::TESTNET,
      Daemon::ALLOW_LOCAL_IP,
      Daemon::NO_ZMQ,
      Daemon::NO_IGD,
      Daemon::HIDE_MY_PORT,
      Daemon::DISABLE_RPC_BAN,
      Daemon::CONFIRM_EXTERNAL_BIND,
      Daemon::DISABLE_DNS_CHECKPOINTS,
      (boost::format(Daemon::RPC_SSL_CONTAINER) % "disabled").str(),
      (boost::format(Daemon::MAX_CONNECTIONS_PER_IP) % std::to_string(daemon.max_connections_per_ip)).str(),
      (boost::format(Daemon::RPC_BIND_IP_CONTAINER) % daemon.ip_address).str(),
      (boost::format(Daemon::BLOCK_SYNC_SIZE_CONTAINER) % std::to_string(daemon.block_sync_size)).str(),
      (boost::format(Daemon::MINING_THREADS) % std::to_string(daemon.mining_threads)).str(),
      (boost::format(Daemon::P2P_BIND_IP_CONTAINER) % daemon.p2p_ip).str(),
      (boost::format(Daemon::DIFFICULTY_CONTAINER) % std::to_string(daemon.difficulty)).str(),
      (boost::format(Daemon::P2P_BIND_PORT_CONTAINER) % std::to_string(daemon.p2p_port)).str(),
      (boost::format(Daemon::RPC_BIND_PORT_CONTAINER) % std::to_string(daemon.rpc_port)).str(),
      (boost::format(Daemon::MAX_CONCURRENCY_CONTAINER) % std::to_string(daemon.max_concurrency)).str(),
      (boost::format(Daemon::LIMIT_RATE_UP_CONTAINER) % std::to_string(std::numeric_limits<uint32_t>::max())).str(),
      (boost::format(Daemon::LIMIT_RATE_DOWN_CONTAINER) % std::to_string(std::numeric_limits<uint32_t>::max())).str(),
      (boost::format(Daemon::DATA_DIR_CONTAINER) % daemon.data_dir).str(),
      (boost::format(Daemon::LOG_LEVEL_CONTAINER) % std::to_string(daemon.log_level)).str(),
      (boost::format(Daemon::START_MINING_CONTAINER) % WalletRPC::address_wallet.at(index)).str(),
      exclusive_nodes,
      process::std_out > pipe_stream);

  // wait for signal
  std::this_thread::sleep_for(std::chrono::seconds(seconds));

  daemon_process.terminate();
  if (daemon_process.joinable())
    daemon_process.join();
  return;
}

void mine()
{
  auto miner_creator = [&](int index) {
    Daemon::daemon daemon;
    daemon.p2p_port = Daemon::P2P_BASE_PORT + index;
    daemon.rpc_port = Daemon::RPC_BASE_PORT + index;
    daemon.difficulty = 100 + index;
    daemon.ip_address = daemon.p2p_ip = Daemon::RPC_DEFAULT_IP;
    daemon.log_level = 0;
    daemon.data_dir = Daemon::Default_daemon_location(index);
    daemon.exec_path = Daemon::MASTER_EXEC_PATH;
    std::thread daemon_thread(run_miner, std::ref(daemon), index, mine_time);
    if (daemon_thread.joinable())
      daemon_thread.join();
  };

  std::vector<std::thread> daemon_miner_jobs;
  for (int index = 0; index < number_of_wallets; ++index)
    {
      daemon_miner_jobs.push_back(std::thread(miner_creator, index));
    }

  for (int index = 0; index < number_of_wallets; ++index)
    {
      if (daemon_miner_jobs.at(index).joinable())
        daemon_miner_jobs.at(index).join();
    }
}

struct RandomBlockNumberGenerator
{
public:
  RandomBlockNumberGenerator(uint64_t max_value) : max_value(max_value) {};
  using result_type = uint64_t;
  result_type min() { return 1; }
  result_type max() { return max_value; }
  result_type operator()() { return rand() % max_value; }
  result_type max_value;
};  

std::chrono::milliseconds do_benchmark(filesystem::path daemon_exec_path)
{
  Daemon::daemon daemon;
  daemon.ip_address = daemon.p2p_ip = Daemon::RPC_DEFAULT_IP;
  daemon.p2p_port = Daemon::P2P_BASE_PORT;
  daemon.rpc_port = Daemon::RPC_BASE_PORT;
  // daemon.data_dir = Daemon::Default_daemon_location(0);
  // daemon.data_dir = Daemon::Default_daemon_location(0);
  daemon.exec_path = daemon_exec_path;
  daemon.log_level = 0;
  boost::condition_variable daemon_terminator;
  std::thread daemon_thread(
      create_offline_daemon, std::ref(daemon), std::ref(daemon_terminator));

  if (!filesystem::exists(WalletRPC::EXEC_PATH)) {
      LDIE(WalletRPC::EXEC_PATH.string() + " does not exist.", -1);
  }

  std::this_thread::sleep_for(std::chrono::seconds(10));

  auto rpc_call_to_daemon = [&](int max_iter, int index) {
    uint64_t height = 0;
    static constexpr const std::chrono::seconds rpc_timeout =
        std::chrono::minutes(3) + std::chrono::seconds(30);

    epee::net_utils::http::http_simple_client http_simple_client{};
    http_simple_client.set_server(
        Daemon::RPC_DEFAULT_IP,
        std::to_string(Daemon::RPC_BASE_PORT),
        boost::none,
        epee::net_utils::ssl_support_t::e_ssl_support_disabled);        

    // Get Height
    http_simple_client.connect(std::chrono::milliseconds(3000));
    cryptonote::COMMAND_RPC_GET_HEIGHT::request request;
    cryptonote::COMMAND_RPC_GET_HEIGHT::response response;
    bool result = epee::net_utils::invoke_http_json("/get_height", request, response, http_simple_client, rpc_timeout);
    height = response.height;
    uint64_t max_number_of_blocks = MAX_NUMBER_OF_BLOCKS > height ? (height - 1) : MAX_NUMBER_OF_BLOCKS;
    RandomBlockNumberGenerator randomBlockNumberGenerator(MAX_NUMBER_OF_BLOCKS);
    // LTRACE("RPC get_height return : " << result);
    // LTRACE("RPC height : " << height);
    // LTRACE("RPC status : " << response.status);
    // LTRACE("RPC top_hash : " << response.hash);

    for (int iter = 0; iter < max_iter; ++iter)
      {
        cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request request;
        cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response response;
        request.heights.resize(max_number_of_blocks);
        std::generate(request.heights.begin(), request.heights.end(), randomBlockNumberGenerator);
        bool r = epee::net_utils::invoke_http_bin(
            "/get_blocks_by_height.bin",
            request,
            response,
            http_simple_client,
            rpc_timeout);
        // LTRACE("RPC getblocks_by_height return : " << r << " by thread " << index);
        // LTRACE("response.blocks.size() : " << response.blocks.size() << " by thread " << index);
        // LTRACE("response.status : " << response.status << " by thread " << index);
      }
      http_simple_client.disconnect();
  };

  // warm up
  rpc_call_to_daemon(1, 0);

  std::this_thread::sleep_for(std::chrono::seconds(10));

  auto start = std::chrono::steady_clock::now();
  LINFO("Run benchmarks...");

  std::vector<std::thread> benchmark_jobs;
  uint32_t number_benchmark_jobs = (number_of_wallets * 3);
  benchmark_jobs.clear();
  for (int index = 0; index < number_of_wallets; ++index)
    {
      benchmark_jobs.push_back(
          std::thread(rpc_call_to_daemon, benchmark_iteration, index));
    }

  for (int index = 0; index < number_of_wallets; ++index)
    {
      if (benchmark_jobs.at(index).joinable())
        benchmark_jobs.at(index).join();
    }

  daemon_terminator.notify_all();

  auto end = std::chrono::steady_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  int benchmark_seconds = (elapsed / 1000).count();
  int benchmark_miliseconds = (elapsed % 1000).count();
  LINFO(
      ">>> Total elapsed time for running the benchmark: "
      << benchmark_seconds << "." << benchmark_miliseconds);

  if (daemon_thread.joinable())
    daemon_thread.join();
  return elapsed;
}

int main(int argc, char** argv)
{
  parse_and_validate(argc, argv);

  // create_n_wallets();

  // std::for_each(
  //     begin(WalletRPC::address_wallet),
  //     end(WalletRPC::address_wallet),
  //     [&](const std::pair<int, std::string>& item) {
  //       LTRACE("Wallet " << item.first << " : " << item.second);
  //     });

  // LINFO( "Start mining...");
  // mine();

  // do benchmark with master
  LINFO( "Start benchmarking with master...");
  auto master_duration = do_benchmark(Daemon::MASTER_EXEC_PATH);

  // do benchmark with test
  LINFO( "Start benchmarking with test...");
  auto test_duration = do_benchmark(Daemon::TEST_EXEC_PATH);

  if((test_duration / 1000).count() != (master_duration / 1000).count()) {
      if (test_duration.count() < master_duration.count()) {
          LINFO( "PR (test) was faster.");
      } else {
          LINFO( "master was faster.");
      }
  }

  return 0;
}
