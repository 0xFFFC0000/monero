
#include <benchmark/benchmark.h>
#include <gperftools/malloc_hook.h>  // link tcmalloc

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>  // malloc
#include <limits>
#include <string>

#include "benchmark/benchmark.h"  // link benchmark
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "include_base_utils.h"
#include "storages/portable_storage_template_helper.h"

benchmark::IterationCount g_num_new = 0;
benchmark::IterationCount g_sum_size_new = 0;
benchmark::IterationCount g_max_size_new = 0;
benchmark::IterationCount g_min_size_new = -1;
auto new_hook = [](const void*, size_t size) {
  ++g_num_new;
  g_sum_size_new += size;
  g_max_size_new = std::max((int64_t)g_max_size_new, (int64_t)size);
  g_min_size_new = std::min((int64_t)g_min_size_new, (int64_t)size);
};
#define BEFORE_TEST                                        \
  benchmark::IterationCount num_new = g_num_new;           \
  benchmark::IterationCount sum_size_new = g_sum_size_new; \
  g_max_size_new = 0;                                      \
  g_min_size_new = -1;                                     \
  MallocHook::AddNewHook(new_hook);

#define AFTER_TEST                                                      \
  MallocHook::RemoveNewHook(new_hook);                                  \
  auto iter = state.iterations();                                       \
  state.counters["#new"] = (g_num_new - num_new) / iter;                \
  state.counters["sum_new_allocated"] = (g_sum_size_new - sum_size_new) / iter; \
  state.counters["avg_new_allocated"] =                                         \
      (g_sum_size_new - sum_size_new) / (g_num_new - num_new);          \
  state.counters["max_new_allocated"] = g_max_size_new;                         \
  if (((benchmark::IterationCount) - 1) != g_min_size_new)              \
    {                                                                   \
      state.counters["min_new_allocated"] = g_min_size_new;                     \
    }

std::string gen_random_string2(const int len)
{
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (int i = 0; i < len; ++i)
    {
      tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

  return tmp_s;
}

static void tiny_4_string_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      size_t max_strings = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          8192,  // objects
          16384,  // fields
          max_strings,  // strings
      };
      std::vector<std::string> small_strings;

#define TINY_STRING_SIZE 4
      size_t len_size = TINY_STRING_SIZE * max_strings;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_strings - 1); j++)
        {
          small_strings.push_back(gen_random_string2(TINY_STRING_SIZE));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_field = small_strings;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_string_test");
            exit(1);
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_string_test");
            exit(1);
          }
      }
    }
  AFTER_TEST
}

static void small_128_string_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      size_t max_strings = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          8192,  // objects
          16384,  // fields
          max_strings,  // strings
      };
      std::vector<std::string> small_strings;

#define SMALL_STRING_SIZE 128
      size_t len_size = SMALL_STRING_SIZE * max_strings;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_strings - 1); j++)
        {
          small_strings.push_back(gen_random_string2(SMALL_STRING_SIZE));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_field = small_strings;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_string_test");
            exit(1);
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_string_test");
            exit(1);
          }
      }
    }
  AFTER_TEST
}

static void medium_1024_string_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      size_t max_strings = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          8192,  // objects
          16384,  // fields
          max_strings,  // strings
      };
      std::vector<std::string> small_strings;

#define MEDIUM_STRING_SIZE 1024
      size_t len_size = MEDIUM_STRING_SIZE * max_strings;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_strings - 1); j++)
        {
          small_strings.push_back(gen_random_string2(MEDIUM_STRING_SIZE));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_field = small_strings;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_string_test");
            exit(1);
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_string_test");
            exit(1);
          }
      }
    }
  AFTER_TEST
}

static void large_16384_string_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      size_t max_strings = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          8192,  // objects
          16384,  // fields
          max_strings,  // strings
      };
      std::vector<std::string> small_strings;

#define LARGE_STRING_SIZE (16384)
      size_t len_size = LARGE_STRING_SIZE * max_strings;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_strings - 1); j++)
        {
          small_strings.push_back(gen_random_string2(LARGE_STRING_SIZE));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_field = small_strings;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_string_test");
            exit(1);
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_string_test");
            exit(1);
          }
      }
    }
  AFTER_TEST
}

static void big_262144_string_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      size_t max_strings = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          8192,  // objects
          16384,  // fields
          max_strings,  // strings
      };
      std::vector<std::string> big_strings;

#define BIG_STRING_SIZE (262144)
      size_t len_size = BIG_STRING_SIZE * max_strings;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_strings - 1); j++)
        {
          big_strings.push_back(gen_random_string2(BIG_STRING_SIZE));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_field = big_strings;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at big_string_test");
            exit(1);
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at big_string_test");
            exit(1);
          }
      }
    }
  AFTER_TEST
}

static void tiny_4_object_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      std::random_device device;
      std::mt19937 rengine(device());
      std::uniform_int_distribution<std::mt19937::result_type> generator(
          1, std::numeric_limits<std::uint32_t>::max());

      size_t max_bytes = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          max_bytes,  // objects
          16384 * 1024 * 32,  // fields
          16384 * 1024 * 32,  // bytes
      };
      std::vector<cryptonote::tx_blob_entry> small_bytes;

#define TINY_STRING_SIZE 4
      size_t len_size = TINY_STRING_SIZE * max_bytes;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_bytes - 1); j++)
        {
          std::uint32_t r = generator(rengine);
          crypto::hash t_hash;
          cn_fast_hash(&r, sizeof(r), t_hash);
          small_bytes.push_back(cryptonote::tx_blob_entry(
              gen_random_string2(TINY_STRING_SIZE), t_hash));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_txs = small_bytes;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_byte_test");
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_byte_test");
          }
      }
    }
  AFTER_TEST
}

static void small_128_object_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      std::random_device device;
      std::mt19937 rengine(device());
      std::uniform_int_distribution<std::mt19937::result_type> generator(
          1, std::numeric_limits<std::uint32_t>::max());

      size_t max_bytes = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          max_bytes,  // objects
          16384 * 1024 * 32,  // fields
          16384 * 1024 * 32,  // bytes
      };
      std::vector<cryptonote::tx_blob_entry> small_bytes;

#define SMALL_STRING_SIZE 128
      size_t len_size = SMALL_STRING_SIZE * max_bytes;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_bytes - 1); j++)
        {
          std::uint32_t r = generator(rengine);
          crypto::hash t_hash;
          cn_fast_hash(&r, sizeof(r), t_hash);
          small_bytes.push_back(cryptonote::tx_blob_entry(
              gen_random_string2(SMALL_STRING_SIZE), t_hash));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_txs = small_bytes;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_object_test");
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_object_test");
          }
      }
    }
  AFTER_TEST
}

static void medium_1024_object_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      std::random_device device;
      std::mt19937 rengine(device());
      std::uniform_int_distribution<std::mt19937::result_type> generator(
          1, std::numeric_limits<std::uint32_t>::max());

      size_t max_bytes = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          max_bytes,  // objects
          16384 * 1024 * 32,  // fields
          16384 * 1024 * 32,  // bytes
      };
      std::vector<cryptonote::tx_blob_entry> small_bytes;

#define MEDIUM_STRING_SIZE 1024
      size_t len_size = MEDIUM_STRING_SIZE * max_bytes;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_bytes - 1); j++)
        {
          std::uint32_t r = generator(rengine);
          crypto::hash t_hash;
          cn_fast_hash(&r, sizeof(r), t_hash);
          small_bytes.push_back(cryptonote::tx_blob_entry(
              gen_random_string2(MEDIUM_STRING_SIZE), t_hash));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_txs = small_bytes;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_object_test");
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_object_test");
          }
      }
    }
  AFTER_TEST
}

static void large_16384_object_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      std::random_device device;
      std::mt19937 rengine(device());
      std::uniform_int_distribution<std::mt19937::result_type> generator(
          1, std::numeric_limits<std::uint32_t>::max());

      size_t max_bytes = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          max_bytes,  // objects
          16384 * 1024 * 32,  // fields
          16384 * 1024 * 32,  // bytes
      };
      std::vector<cryptonote::tx_blob_entry> small_bytes;

#define LARGE_STRING_SIZE (16384)
      size_t len_size = LARGE_STRING_SIZE * max_bytes;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_bytes - 1); j++)
        {
          std::uint32_t r = generator(rengine);
          crypto::hash t_hash;
          cn_fast_hash(&r, sizeof(r), t_hash);
          small_bytes.push_back(cryptonote::tx_blob_entry(
              gen_random_string2(LARGE_STRING_SIZE), t_hash));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_txs = small_bytes;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_object_test");
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_object_test");
          }
      }
    }
  AFTER_TEST
}

static void big_262144_object_test(benchmark::State& state)
{
  BEFORE_TEST
  for (auto _ : state)
    {
      state.PauseTiming();
      std::random_device device;
      std::mt19937 rengine(device());
      std::uniform_int_distribution<std::mt19937::result_type> generator(
          1, std::numeric_limits<std::uint32_t>::max());

      size_t max_bytes = state.range(0);
      epee::serialization::portable_storage::limits_t default_levin_limits = {
          max_bytes,  // objects
          16384 * 1024 * 32,  // fields
          16384 * 1024 * 32,  // bytes
      };
      std::vector<cryptonote::tx_blob_entry> small_bytes;

#define BIG_STRING_SIZE (262144)
      size_t len_size = BIG_STRING_SIZE * max_bytes;
      if (len_size > 100000000)
        state.SkipWithError("Bigger than max 100MB allowed by network packet.");
      state.counters["Data"] = len_size;
      for (size_t j = 0; j < (max_bytes - 1); j++)
        {
          std::uint32_t r = generator(rengine);
          crypto::hash t_hash;
          cn_fast_hash(&r, sizeof(r), t_hash);
          small_bytes.push_back(cryptonote::tx_blob_entry(
              gen_random_string2(BIG_STRING_SIZE), t_hash));
        }
      state.ResumeTiming();
      {
        epee::byte_slice buff;
        cryptonote::TORTURE_ENTRY::request r;
        r.torture_txs = small_bytes;
        bool res = epee::serialization::store_t_to_binary(r, buff);
        if (!res)
          {
            state.SkipWithError(
                "Error to store_t_from_binary at small_object_test");
          }

        cryptonote::TORTURE_ENTRY::request r2;
        res = epee::serialization::load_t_from_binary(
            r2, epee::to_span(buff), &default_levin_limits);
        if (!res)
          {
            state.SkipWithError(
                "Error to load_t_from_binary at small_object_test");
          }
      }
    }
  AFTER_TEST
}

#define START_SIZE 32

BENCHMARK(tiny_4_object_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 22)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(small_128_object_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 17)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(medium_1024_object_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 14)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(large_16384_object_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 10)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(big_262144_object_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 7)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.

BENCHMARK(tiny_4_string_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 22)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(small_128_string_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 17)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(medium_1024_string_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 14)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(large_16384_string_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 10)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.
BENCHMARK(big_262144_string_test)
    ->RangeMultiplier(2)
    ->Range(START_SIZE, 8 << 6)
    ->Unit(benchmark::kMillisecond)
    ->MinWarmUpTime(
        1);  // ->Complexity();; // complexity not working right now.

BENCHMARK_MAIN();