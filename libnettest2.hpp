// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBNETTEST2_HPP
#define MEASUREMENT_KIT_LIBNETTEST2_HPP

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <ctype.h>
#include <limits.h>
#ifndef _WIN32
#include <netdb.h>
#endif
#include <stdint.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <maxminddb.h>

// TODO(bassosimone): add documentation and restructure code such that what
// does not need to be documented and processed by a user lies below a specific
// line like we currently do for libndt.

// TODO(bassosimone): add support for telling cURL which CA to use. We will
// need this when we use this code with the mobile apps.

// Check dependencies
// ``````````````````

// TODO(bassosimone): make sure we can serialize a JSON. Specifically, there
// may be cases where the JSON input is not UTF-8 and, in such cases, the JSON
// library that we use will throw an exception.

#ifndef NLOHMANN_JSON_HPP
#error "Please include nlohmann/json before including this header"
#endif  // !NLOHMANN_JSON_HPP

#ifndef DATE_H
#error "Please include HowardHinnant/date before including this header"
#endif  // !DATE_H

namespace measurement_kit {
namespace libnettest2 {

constexpr const char *default_engine_name() noexcept {
  return "libnettest2";
}

// Versioning
// ``````````

/// Type containing a version number.
using Version = unsigned int;

/// Major API version number of measurement-kit/libnettest2.
constexpr Version version_major = Version{0};

/// Minor API version number of measurement-kit/libnettest2.
constexpr Version version_minor = Version{5};

/// Patch API version number of measurement-kit/libnettest2.
constexpr Version version_patch = Version{0};

/// Returns a string reresentation of the version
inline std::string version() noexcept {
  std::stringstream ss;
  ss << version_major << "." << version_minor << "." << version_patch;
  return ss.str();
}

// Timeout
// ```````

using Timeout = double;
constexpr Timeout TimeoutMax = 90.0;

// Log level
// `````````

using LogLevel = unsigned int;
constexpr LogLevel log_quiet = LogLevel{0};
constexpr LogLevel log_warning = LogLevel{1};
constexpr LogLevel log_info = LogLevel{2};
constexpr LogLevel log_debug = LogLevel{3};

// Errors
// ``````

class ErrContext {
 public:
  int64_t code = 1; // Set to nonzero because often zero means success
  std::string library_name;
  std::string library_version;
  std::string reason;
};

// Implementation note: PLEASE NEVER REMOVE LINES SUCH THAT WE CAN KEEP A
// STABLE ERROR RELATED ABI FOREVER WITH ZERO MAINTENANCE COSTS.
#define LIBNETTEST2_ENUM_OWN_ERRORS(XX) \
  XX(none)                              \
  XX(mmdb_enoent)                       \
  XX(mmdb_enodatafortype)

// Inherit from int64_t such that we can safely cast to int64_t when we
// are using a value of this enum to initialize a ErrContext::value.
enum class Errors : int64_t {
#define XX(e_) e_,
  LIBNETTEST2_ENUM_OWN_ERRORS(XX)
#undef XX
};

const char *libnettest2_strerror(Errors n) noexcept;

// Settings
// ````````

// TODO(bassosimone): add possibility to initialize from JSON.
class Settings {
 public:
  std::map<std::string, std::string> annotations;
  std::string bouncer_base_url = "https://bouncer.ooni.io";
  std::string collector_base_url;
  std::string engine_name = default_engine_name();
  std::string engine_version = version();
  std::string geoip_asn_path;
  std::string geoip_country_path;
  std::vector<std::string> inputs;
  bool no_bouncer = false;
  bool no_collector = false;
  bool no_asn_lookup = false;
  bool no_cc_lookup = false;
  bool no_ip_lookup = false;
  bool no_resolver_lookup = false;
  uint8_t parallelism = 0;
  std::string probe_ip;
  std::string probe_asn;
  std::string probe_network_name;
  std::string probe_cc;
  bool randomize_input = true;
  bool save_real_probe_asn = true;
  bool save_real_probe_ip = false;
  bool save_real_probe_cc = true;
  bool save_real_resolver_ip = true;
  std::string software_name = default_engine_name();
  std::string software_version = version();
  Timeout max_runtime = TimeoutMax;
  LogLevel log_level = log_quiet;
};

// EndpointInfo
// ````````````

using EndpointType = uint8_t;
constexpr EndpointType endpoint_type_none = EndpointType{0};
constexpr EndpointType endpoint_type_onion = EndpointType{1};
constexpr EndpointType endpoint_type_cloudfront = EndpointType{2};
constexpr EndpointType endpoint_type_https = EndpointType{3};

class EndpointInfo {
 public:
  EndpointType type = endpoint_type_none;
  std::string address;
  std::string front;  // Only valid for endpoint_type_cloudfront
};

// Nettest context
// ```````````````

class NettestContext {
 public:
  std::vector<EndpointInfo> collectors;
  std::string probe_asn;
  std::string probe_cc;
  std::string probe_ip;
  std::string probe_network_name;
  std::string report_id;
  std::string resolver_ip;
  std::map<std::string, std::vector<EndpointInfo>> test_helpers;
};

// Nettest
// ```````

class BytesInfo {
 public:
  // Implementation note: we use unsigned arithmetic here and accept the
  // fact that, if we transfer a very huge amount of data (unlikely for
  // all our tests), we will wrap around. Signed types are guaranteed to
  // wrap around. See <https://stackoverflow.com/a/10011488/4354461>.
  std::atomic<uint64_t> bytes_down{0};
  std::atomic<uint64_t> bytes_up{0};
};

class Nettest {
 public:
  virtual std::string name() const noexcept;

  virtual std::vector<std::string> test_helpers() const noexcept;

  virtual std::string version() const noexcept;

  virtual bool needs_input() const noexcept;

  virtual bool run(const Settings &settings,
                   const NettestContext &context,
                   std::string input,
                   nlohmann::json *test_keys,
                   BytesInfo *info) noexcept;

  virtual ~Nettest() noexcept;
};

// Runner
// ``````

class Runner {
 public:
  Runner(const Settings &settings, Nettest &nettest) noexcept;

  Runner(const Runner &) noexcept = delete;
  Runner &operator=(const Runner &) noexcept = delete;
  Runner(Runner &&) noexcept = delete;
  Runner &operator=(Runner &&) noexcept = delete;

  virtual ~Runner() noexcept;

  bool run() noexcept;

  void interrupt() noexcept;

  LogLevel get_log_level() const noexcept;

 protected:
  // Methods you typically want to override
  // ``````````````````````````````````````
  // The on_event() method is called when a event occurs. Note that this
  // method MAY be called from another thread context.

  virtual void on_event(const nlohmann::json &event) const noexcept;

  // Methods you generally DON'T want to override
  // ````````````````````````````````````````````
  // You may want to override them in unit tests, however.

 public:
  virtual void emit_ev(std::string key, nlohmann::json value) const noexcept;

  class BytesInfoWrapper {
   public:
    const Runner *owner = nullptr;
    BytesInfo *info = nullptr;
  };

 protected:
  virtual bool run_with_index32(
      const std::chrono::time_point<std::chrono::steady_clock> &begin,
      const std::string &test_start_time,
      const std::vector<std::string> &inputs, const NettestContext &ctx,
      const std::string &collector_base_url, uint32_t i,
      BytesInfo *info) const noexcept;

  virtual bool query_bouncer(std::string nettest_name,
                             std::vector<std::string> nettest_helper_names,
                             std::string nettest_version,
                             std::vector<EndpointInfo> *collectors,
                             std::map<std::string,
                               std::vector<EndpointInfo>> *helpers,
                             BytesInfo *info,
                             ErrContext *err) noexcept;

  virtual bool lookup_ip(std::string *ip, BytesInfo *info,
                         ErrContext *err) noexcept;

  virtual bool lookup_resolver_ip(std::string *ip, BytesInfo *info,
                                  ErrContext *err) noexcept;

  virtual bool open_report(const std::string &collector_base_url,
                           const std::string &test_start_time,
                           const NettestContext &context,
                           std::string *report_id,
                           BytesInfo *info, ErrContext *err) noexcept;

  virtual bool update_report(const std::string &collector_base_url,
                             const std::string &report_id,
                             const std::string &json_str,
                             BytesInfo *info, ErrContext *err) const noexcept;

  virtual bool close_report(const std::string &collector_base_url,
                            const std::string &report_id,
                            BytesInfo *info, ErrContext *err) noexcept;

  // MaxMindDB code
  // ``````````````

  virtual bool lookup_asn(const std::string &dbpath, const std::string &ip,
                          std::string *asn, std::string *network_name,
                          ErrContext *err) noexcept;

  virtual bool lookup_cc(const std::string &dbpath, const std::string &probe_ip,
                         std::string *cc, ErrContext *err) noexcept;

  // cURL code
  // `````````

  class CurlxDeleter {
   public:
    void operator()(CURL *handle) noexcept;
  };
  using UniqueCurlx = std::unique_ptr<CURL, CurlxDeleter>;

  virtual bool curlx_post_json(std::string url,
                               std::string requestbody,
                               long timeout,
                               std::string *responsebody,
                               BytesInfo *info,
                               ErrContext *err) const noexcept;

  virtual bool curlx_get(std::string url,
                         long timeout,
                         std::string *responsebody,
                         BytesInfo *info,
                         ErrContext *err) noexcept;

  virtual bool curlx_common(UniqueCurlx &handle,
                            std::string url,
                            long timeout,
                            std::string *responsebody,
                            BytesInfo *info,
                            ErrContext *err) const noexcept;

 private:
  // Private attributes
  // ``````````````````

  std::atomic_bool interrupted_{false};

  Nettest &nettest_;

  const Settings &settings_;
};

// Implementation section
// ``````````````````````
// This is a single header library. In some use cases you may want to split
// the interface and implementation using LIBNETTEST2_NO_INLINE_IMPL.
#ifndef LIBNETTEST2_NO_INLINE_IMPL

// Errors
// ``````

const char *libnettest2_strerror(Errors n) noexcept {
#define XX(e_) case Errors::e_: return #e_;
  switch (n) {
    LIBNETTEST2_ENUM_OWN_ERRORS(XX)
  }
#undef XX
  return "invalid_argument";
}

// UUID4 code
// ``````````
// Derivative work of r-lyeh/sole@c61c49f10d.
/*-
 * Portions Copyright (c) 2015 r-lyeh (https://github.com/r-lyeh)
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 * claim that you wrote the original software. If you use this software
 * in a product, an acknowledgment in the product documentation would be
 * appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 */
namespace sole {

class uuid {
  public:
    std::string str();
    uint64_t ab;
    uint64_t cd;
};

uuid uuid4();

std::string uuid::str() {
  std::stringstream ss;
  ss << std::hex << std::nouppercase << std::setfill('0');

  uint32_t a = (ab >> 32);
  uint32_t b = (ab & 0xFFFFFFFF);
  uint32_t c = (cd >> 32);
  uint32_t d = (cd & 0xFFFFFFFF);

  ss << std::setw(8) << (a) << '-';
  ss << std::setw(4) << (b >> 16) << '-';
  ss << std::setw(4) << (b & 0xFFFF) << '-';
  ss << std::setw(4) << (c >> 16) << '-';
  ss << std::setw(4) << (c & 0xFFFF);
  ss << std::setw(8) << d;

  return ss.str();
}

uuid uuid4() {
  std::random_device rd;
  std::uniform_int_distribution<uint64_t> dist(0, (uint64_t)(~0));
  uuid my;

  my.ab = dist(rd);
  my.cd = dist(rd);

  /* The version 4 UUID is meant for generating UUIDs from truly-random or
     pseudo-random numbers.

     The algorithm is as follows:

     o  Set the four most significant bits (bits 12 through 15) of the
        time_hi_and_version field to the 4-bit version number from
        Section 4.1.3.

     o  Set the two most significant bits (bits 6 and 7) of the
        clock_seq_hi_and_reserved to zero and one, respectively.

     o  Set all the other bits to randomly (or pseudo-randomly) chosen
        values.

     See <https://tools.ietf.org/html/rfc4122#section-4.4>. */
  my.ab = (my.ab & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
  my.cd = (my.cd & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

  return my;
}

}  // namespace sole

/*
 * Guess the platform in which we are.
 *
 * See: <https://sourceforge.net/p/predef/wiki/OperatingSystems/>
 *      <http://stackoverflow.com/a/18729350>
 */
#if defined __ANDROID__
#  define LIBNETTEST2_PLATFORM "android"
#elif defined __linux__
#  define LIBNETTEST2_PLATFORM "linux"
#elif defined _WIN32
#  define LIBNETTEST2_PLATFORM "windows"
#elif defined __APPLE__
#  include <TargetConditionals.h>
#  if TARGET_OS_IPHONE
#    define LIBNETTEST2_PLATFORM "ios"
#  else
#    define LIBNETTEST2_PLATFORM "macos"
#  endif
#else
#  define LIBNETTEST2_PLATFORM "unknown"
#endif

#define LIBNETTEST2_EMIT_LOG(self, level, uppercase_level, statements) \
  do {                                                                 \
    if (self->get_log_level() >= log_##level) {                        \
      std::stringstream ss;                                            \
      ss << "libnettest2: " << statements;                             \
      nlohmann::json value;                                            \
      value["log_level"] = #uppercase_level;                           \
      value["message"] = ss.str();                                     \
      self->emit_ev("log", std::move(value));                          \
    }                                                                  \
  } while (0)

#define LIBNETTEST2_EMIT_WARNING_EX(self, statements) \
  LIBNETTEST2_EMIT_LOG(self, warning, WARNING, statements)

#define LIBNETTEST2_EMIT_INFO_EX(self, statements) \
  LIBNETTEST2_EMIT_LOG(self, info, INFO, statements)

#define LIBNETTEST2_EMIT_DEBUG_EX(self, statements) \
  LIBNETTEST2_EMIT_LOG(self, debug, DEBUG, statements)

#define LIBNETTEST2_EMIT_WARNING(statements) \
  LIBNETTEST2_EMIT_WARNING_EX(this, statements)

#define LIBNETTEST2_EMIT_INFO(statements) \
  LIBNETTEST2_EMIT_INFO_EX(this, statements)

#define LIBNETTEST2_EMIT_DEBUG(statements) \
  LIBNETTEST2_EMIT_DEBUG_EX(this, statements)

// Nettest
// ```````

std::string Nettest::name() const noexcept { return ""; }

std::vector<std::string> Nettest::test_helpers() const noexcept { return {}; }

std::string Nettest::version() const noexcept { return "0.0.1"; }

bool Nettest::needs_input() const noexcept { return false; }

bool Nettest::run(const Settings &, const NettestContext &,
                  std::string, nlohmann::json *, BytesInfo *) noexcept {
  // Do nothing for two seconds, for testing
  std::this_thread::sleep_for(std::chrono::seconds(2));
  return true;
}

Nettest::~Nettest() noexcept {}

// Runner API
// ``````````

Runner::Runner(const Settings &settings, Nettest &nettest) noexcept
    : nettest_{nettest}, settings_{settings} {}

Runner::~Runner() noexcept {}

static std::mutex &global_mutex() noexcept {
  static std::mutex mtx;
  return mtx;
}

static std::string format_system_clock_now() noexcept {
  // Implementation note: to avoid using the C standard library that has
  // given us many headaches on Windows because of parameter validation we
  // go for a fully C++11 solution based on <chrono> and on the C++11
  // HowardInnant/date library, which will be available as part of the
  // C++ standard library starting from C++20.
  //
  // Explanation of the algorithm:
  //
  // 1. get the current system time
  // 2. round the time point obtained in the previous step to an integral
  //    number of seconds since the EPOCH used by the system clock
  // 3. create a system clock time point from the integral number of seconds
  // 4. convert the previous result to string using HowardInnant/date
  // 5. if there is a decimal component (there should be one given how the
  //    library we use works) remove it, because OONI doesn't like it
  //
  // (There was another way to deal with fractionary seconds, i.e. using '%OS',
  //  but this solution seems better to me because it's less obscure.)
  using namespace std::chrono;
  constexpr auto fmt = "%Y-%m-%d %H:%M:%S";
  auto sys_point = system_clock::now();                                    // 1
  auto as_seconds = duration_cast<seconds>(sys_point.time_since_epoch());  // 2
  auto back_as_sys_point = system_clock::time_point(as_seconds);           // 3
  auto s = date::format(fmt, back_as_sys_point);                           // 4
  if (s.find(".") != std::string::npos) s = s.substr(0, s.find("."));      // 5
  return s;
}

static void to_json(nlohmann::json &j, const ErrContext &ec) noexcept {
  j = nlohmann::json{{"code", ec.code},
                     {"library_name", ec.library_name},
                     {"library_version", ec.library_version},
                     {"reason", ec.reason}};
}

bool Runner::run() noexcept {
  BytesInfo info{};
  emit_ev("status.queued", nlohmann::json::object());
  // The following guarantees that just a single test may be active at any
  // given time. Note that we cannot guarantee FIFO queuing.
  std::unique_lock<std::mutex> _{global_mutex()};
  NettestContext ctx;
  emit_ev("status.started", nlohmann::json::object());
  {
    if (!settings_.no_bouncer) {
      ErrContext err{};
      if (!query_bouncer(nettest_.name(), nettest_.test_helpers(),
                         nettest_.version(), &ctx.collectors,
                         &ctx.test_helpers, &info, &err)) {
        LIBNETTEST2_EMIT_WARNING("run: query_bouncer() failed");
        // TODO(bassosimone): shouldn't we introduce failure.query_bouncer?
        // FALLTHROUGH
      }
    }
  }
  emit_ev("status.progress", {{"percentage", 0.1},
                              {"message", "contact bouncer"}});
  {
    if (settings_.probe_ip == "") {
      if (!settings_.no_ip_lookup) {
        ErrContext err{};
        if (!lookup_ip(&ctx.probe_ip, &info, &err)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_ip() failed");
          emit_ev("failure.ip_lookup", {
              {"failure", "library_error"},
              {"library_error_context", err},
          });
        }
      }
    } else {
      ctx.probe_ip = settings_.probe_ip;
    }
    LIBNETTEST2_EMIT_DEBUG("probe_ip: " << ctx.probe_ip);
  }
  {
    // Implementation detail: if probe_asn is empty then we will also overwrite
    // the value inside of probe_network_name even if it's non-empty.
    if (settings_.probe_asn == "") {
      if (!settings_.no_asn_lookup) {
        ErrContext err{};
        if (!lookup_asn(settings_.geoip_asn_path, ctx.probe_ip, &ctx.probe_asn,
                        &ctx.probe_network_name, &err)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_asn() failed");
          emit_ev("failure.asn_lookup", {
              {"failure", "library_error"},
              {"library_error_context", err},
          });
        }
      }
    } else {
      ctx.probe_network_name = settings_.probe_network_name;
      ctx.probe_asn = settings_.probe_asn;
    }
    LIBNETTEST2_EMIT_DEBUG("probe_asn: " << ctx.probe_asn);
    LIBNETTEST2_EMIT_DEBUG("probe_network_name: " << ctx.probe_network_name);
  }
  {
    if (settings_.probe_cc == "") {
      if (!settings_.no_cc_lookup) {
        ErrContext err{};
        if (!lookup_cc(settings_.geoip_country_path, ctx.probe_ip,
                       &ctx.probe_cc, &err)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_cc() failed");
          emit_ev("failure.cc_lookup", {
              {"failure", "library_error"},
              {"library_error_context", err},
          });
        }
      }
    } else {
      ctx.probe_cc = settings_.probe_cc;
    }
    LIBNETTEST2_EMIT_DEBUG("probe_cc: " << ctx.probe_cc);
  }
  emit_ev("status.progress", {{"percentage", 0.2},
                              {"message", "geoip lookup"}});
  // TODO(bassosimone): make sure that passing empty strings here is
  // preferrable than passing conventional values like 127.0.0.1. This
  // has been prompted by a discussion with @lorenzoPrimi and I guess
  // it needs to be also discussed with @hellais.
  emit_ev("status.geoip_lookup", {
                                     {"probe_cc", ctx.probe_cc},
                                     {"probe_asn", ctx.probe_asn},
                                     {"probe_ip", ctx.probe_ip},
                                     {"probe_network_name", ctx.probe_network_name},
                                 });
  {
    if (!settings_.no_resolver_lookup) {
      ErrContext err{};
      if (!lookup_resolver_ip(&ctx.resolver_ip, &info, &err)) {
        LIBNETTEST2_EMIT_WARNING("run: lookup_resolver_ip() failed");
        emit_ev("failure.resolver_lookup", {
            {"failure", "library_error"},
            {"library_error_context", err},
        });
      }
    }
    LIBNETTEST2_EMIT_DEBUG("resolver_ip: " << ctx.resolver_ip);
  }
  emit_ev("status.progress", {{"percentage", 0.3},
                              {"message", "resolver lookup"}});
  emit_ev("status.resolver_lookup", {{"resolver_ip", ctx.resolver_ip}});
  auto test_start_time = format_system_clock_now();
  std::string collector_base_url;
  if (!settings_.no_collector) {
    if (settings_.collector_base_url == "") {
      // TODO(bassosimone): here the algorithm for selecting a collector
      // is very basic but mirrors the one in MK. We should probably make
      // the code better to use cloudfronted and/or Tor if needed.
      for (auto &epnt : ctx.collectors) {
        if (epnt.type == endpoint_type_https) {
          collector_base_url = epnt.address;
          break;
        }
      }
      ErrContext err{};
      if (!open_report(collector_base_url, test_start_time, ctx,
                       &ctx.report_id, &info, &err)) {
        LIBNETTEST2_EMIT_WARNING("run: open_report() failed");
        emit_ev("failure.report_create", {
            {"failure", "library_error"},
            {"library_error_context", err},
        });
      } else {
        LIBNETTEST2_EMIT_DEBUG("report_id: " << ctx.report_id);
        emit_ev("status.report_create", {{"report_id", ctx.report_id}});
      }
    } else {
      collector_base_url = settings_.collector_base_url;
    }
  }
  emit_ev("status.progress", {{"percentage", 0.4}, {"message", "open report"}});
  do {
    if (nettest_.needs_input() && settings_.inputs.empty()) {
      LIBNETTEST2_EMIT_WARNING("run: no input provided");
      break;
    }
    // Note: the specification modifies settings_.inputs in place but here
    // settings_ are immutable, so we actually fill a inputs vector using
    // the settings_ when we expect input. Otherwise we ignore settings_.inputs.
    std::vector<std::string> inputs;
    if (nettest_.needs_input()) {
      inputs.insert(inputs.end(), settings_.inputs.begin(),
                    settings_.inputs.end());
    } else {
      if (!settings_.inputs.empty()) {
        LIBNETTEST2_EMIT_WARNING("run: got unexpected input; ignoring it");
        // Note: ignoring settings_.inputs in this case
      }
      inputs.push_back("");  // just one entry
    }
    if (settings_.randomize_input) {
      std::random_device random_device;
      std::mt19937 mt19937{random_device()};
      std::shuffle(inputs.begin(), inputs.end(), mt19937);
    }
    // Implementation note: here we create a bunch of constant variables for
    // the lambda to access shared stuff in a thread safe way
    constexpr uint8_t default_parallelism = 3;
    uint8_t parallelism = ((nettest_.needs_input() == false)  //
                                     ? (uint8_t)1
                                     : ((settings_.parallelism > 0)  //
                                            ? settings_.parallelism
                                            : default_parallelism));
    std::atomic<uint8_t> active{0};
    auto begin = std::chrono::steady_clock::now();
    const std::chrono::time_point<std::chrono::steady_clock> &cbegin = begin;
    const std::string &ccollector_base_url = collector_base_url;
    const NettestContext &cctx = ctx;
    const std::vector<std::string> &cinputs = inputs;
    const Runner *cthis = this;
    std::atomic<uint64_t> i{0};
    std::mutex mutex;
    const std::string &ctest_start_time = test_start_time;
    auto pinfo = &info;
    for (uint8_t j = 0; j < parallelism; ++j) {
      // Implementation note: make sure this lambda has only access to either
      // constant stuff or to stuff that it's thread safe.
      auto main = [
        &active,               // atomic
        &cbegin,               // const ref
        &ccollector_base_url,  // const ref
        &cctx,                 // const ref
        &cinputs,              // const ref
        &ctest_start_time,     // const ref
        &cthis,                // const pointer
        &i,                    // atomic
        &mutex,                // thread safe
        pinfo                  // ptr to struct w/ only atomic fields
      ]() noexcept {
        active += 1;
        // TODO(bassosimone): more work is required to actually interrupt
        // "long" tests like NDT that take several seconds to complete. This
        // is actually broken also in Measurement Kit, where we cannot stop
        // the reactor easily because of the thread pool. So, it does not
        // matter much that we're shipping this sub-library with the interrupt
        // nettest functionality that is not fully functional.
        while (!cthis->interrupted_) {
          uint32_t idx = 0;
          {
            std::unique_lock<std::mutex> _{mutex};
            // Implementation note: we currently limit the maximum value of
            // the index to UINT32_MAX on the grounds that in Java it's painful
            // to deal with unsigned 64 bit integers.
            if (i > UINT32_MAX || i >= cinputs.size()) {
              break;
            }
            idx = (uint32_t)i;
            i += 1;
          }
          if (!cthis->run_with_index32(cbegin, ctest_start_time, cinputs, cctx,
                                       ccollector_base_url, idx, pinfo)) {
            break;
          }
        }
        active -= 1;
      };
      std::thread thread{std::move(main)};
      thread.detach();
    }
    while (active > 0) {
      constexpr auto msec = 250;
      std::this_thread::sleep_for(std::chrono::milliseconds(msec));
    }
    emit_ev("status.progress", {{"percentage", 0.9},
                                {"message", "measurement complete"}});
    // If the report ID is empty, it means we could not open the report for
    // some reason earlier. In such case, it does not make any sense to attempt
    // to close a report. It will only create noise in the backend logs.
    if (!settings_.no_collector && !ctx.report_id.empty()) {
      ErrContext err{};
      if (!close_report(collector_base_url, ctx.report_id, &info, &err)) {
        LIBNETTEST2_EMIT_WARNING("run: close_report() failed");
        emit_ev("failure.report_close", {
            {"failure", "library_error"},
            {"library_error_context", err},
        });
      } else {
        emit_ev("status.report_close", {{"report_id", ctx.report_id}});
      }
    }
    emit_ev("status.progress", {{"percentage", 1.0},
                                {"message", "report close"}});
  } while (0);
  // TODO(bassosimone): decide whether it makes sense to have an overall
  // precise error code in this context (it seems not so easy). For now just
  // always report success, which is what also legacy MK code does.
  emit_ev("status.end", {{"failure", ""},
                         {"downloaded_kb", info.bytes_down.load() / 1024.0},
                         {"uploaded_kb", info.bytes_up.load() / 1024.0}});
  return true;
}

void Runner::interrupt() noexcept { interrupted_ = true; }

LogLevel Runner::get_log_level() const noexcept { return settings_.log_level; }

// Methods you typically want to override
// ``````````````````````````````````````

void Runner::on_event(const nlohmann::json &event) const noexcept {
  // When running with -fsanitize=thread enable on macOS, a data race in
  // accessing std::clog is reported. Attempt to avoid that.
  static std::mutex no_data_race;
  std::unique_lock<std::mutex> _{no_data_race};
  std::clog << event.dump() << std::endl;
}

// Methods you generally DON'T want to override
// ````````````````````````````````````````````

void Runner::emit_ev(std::string key, nlohmann::json value) const noexcept {
  assert(value.is_object());
  on_event({{"key", std::move(key)}, {"value", std::move(value)}});
}

bool Runner::run_with_index32(
    const std::chrono::time_point<std::chrono::steady_clock> &begin,
    const std::string &test_start_time,
    const std::vector<std::string> &inputs, const NettestContext &ctx,
    const std::string &collector_base_url, uint32_t i,
    BytesInfo *info) const noexcept {
  if (info == nullptr) return false;
  {
    auto current_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = current_time - begin;
    // We call a nettest done when we reach 90% of the expected runtime. This
    // accounts for possible errors and for the time for closing the report.
    if (settings_.max_runtime >= 0 &&
        elapsed.count() >= settings_.max_runtime * 0.9) {
      LIBNETTEST2_EMIT_INFO("exceeded max runtime");
      return false;
    }
  }
  emit_ev("status.measurement_start", {{"idx", i}, {"input", inputs[i]}});
  nlohmann::json measurement;
  measurement["annotations"] = settings_.annotations;
  measurement["annotations"]["engine_name"] = settings_.engine_name;
  measurement["annotations"]["engine_version"] = settings_.engine_version;
  measurement["annotations"]["engine_version_full"] = settings_.engine_version;
  measurement["annotations"]["platform"] = LIBNETTEST2_PLATFORM;
  measurement["annotations"]["probe_network_name"] =
      settings_.save_real_probe_asn
          ? ctx.probe_network_name
          : "";
  measurement["id"] = sole::uuid4().str();
  measurement["input"] = inputs[i];
  measurement["input_hashes"] = nlohmann::json::array();
  measurement["measurement_start_time"] = format_system_clock_now();
  measurement["options"] = nlohmann::json::array();
  measurement["probe_asn"] = settings_.save_real_probe_asn ? ctx.probe_asn : "";
  measurement["probe_cc"] = settings_.save_real_probe_cc ? ctx.probe_cc : "";
  measurement["probe_ip"] = settings_.save_real_probe_ip ? ctx.probe_ip : "";
  measurement["report_id"] = ctx.report_id;
  measurement["sotfware_name"] = settings_.software_name;
  measurement["sotfware_version"] = settings_.software_version;
  {
    measurement["test_helpers"] = nlohmann::json::object();
    // TODO(bassosimone): make sure this is exactly what we should send as
    // I'm quite sure that MK sends less info than this.
    for (auto &pair : ctx.test_helpers) {
      auto &key = pair.first;
      auto &values = pair.second;
      for (auto &epnt : values) {
        measurement["test_helpers"][key] = nlohmann::json::object();
        measurement["test_helpers"][key]["address"] = epnt.address;
        if (epnt.type == endpoint_type_onion) {
          measurement["test_helpers"][key]["type"] = "onion";
        } else if (epnt.type == endpoint_type_https) {
          measurement["test_helpers"][key]["type"] = "https";
        } else if (epnt.type == endpoint_type_cloudfront) {
          measurement["test_helpers"][key]["type"] = "cloudfront";
          measurement["test_helpers"][key]["front"] = epnt.front;
        } else {
          // NOTHING
        }
      }
    }
  }
  measurement["test_name"] = nettest_.name();
  measurement["test_start_time"] = test_start_time;
  measurement["test_version"] = nettest_.version();
  nlohmann::json test_keys;
  auto measurement_start = std::chrono::steady_clock::now();
  // TODO(bassosimone): make sure we correctly pass downstream the probe_ip
  // such that the consumer tests could use it to scrub the IP. Currently the
  // nettest with this requirements is WebConnectivity.
  auto rv = nettest_.run(settings_, ctx, inputs[i], &test_keys, info);
  {
    auto current_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = current_time - measurement_start;
    measurement["test_runtime"] = elapsed.count();
  }
  // We fill the resolver_ip after the measurement. Doing that before may allow
  // the nettest to overwrite the resolver_ip field set by us.
  measurement["test_keys"] = test_keys;
  measurement["test_keys"]["resolver_ip"] = settings_.save_real_resolver_ip
                                                ? ctx.resolver_ip
                                                : "";
  if (!rv) {
    // TODO(bassosimone): we should standardize the errors we emit. We can
    // probably emit something along the lines of library_error.
    emit_ev("failure.measurement", {
        {"failure", "generic_error"},
        {"idx", i},
    });
  }
  do {
    std::string str;
    try {
      str = measurement.dump();
    } catch (const std::exception &e) {
      LIBNETTEST2_EMIT_WARNING("run: cannot serialize JSON: " << e.what());
      // TODO(bassosimone): This is MK passing us an invalid JSON. Should we
      // submit something nonetheless as a form of telemetry? This is something
      // I should probably discuss with @hellais and/or @darkk.
      break;
    }
    // When the report ID is empty, do not bother with closing the report as
    // it means we could not open it for some reason. An empty str instead
    // indicates a bug where we could not serialize a JSON.
    if (!settings_.no_collector && !ctx.report_id.empty() && !str.empty()) {
      ErrContext err{};
      if (!update_report(collector_base_url, ctx.report_id, str, info, &err)) {
        LIBNETTEST2_EMIT_WARNING("run: update_report() failed");
        emit_ev("failure.measurement_submission", {
            {"failure", "library_error"},
            {"library_error_context", err},
            {"idx", i},
            {"json_str", str},
        });
      } else {
        emit_ev("status.measurement_submission", {{"idx", i}});
      }
    }
    if (!str.empty()) {
      // According to several discussions with @lorenzoPrimi, it is much better
      // for this event to be emitted AFTER submitting the report.
      emit_ev("measurement", {{"idx", i}, {"json_str", std::move(str)}});
    }
  } while (0);
  emit_ev("status.measurement_done", {{"idx", i}});
  return true;
}

// TODO(bassosimone): we should _probably_ make this configurable. One way to
// do that MAY be to use the net/timeout setting.
constexpr long curl_timeout = 5;

static std::string without_final_slash(std::string src) noexcept {
  while (src.size() > 0 && src[src.size() - 1] == '/') {
    src = src.substr(0, src.size() - 1);
  }
  return src;
}

static std::string nlohmann_json_version() noexcept {
  std::stringstream ss;
#ifdef NLOHMANN_JSON_VERSION_MAJOR
  ss << NLOHMANN_JSON_VERSION_MAJOR << "." << NLOHMANN_JSON_VERSION_MINOR
     << "." << NLOHMANN_JSON_VERSION_PATCH;
#else
  ss << "unknown";
#endif
  return ss.str();
}

bool Runner::query_bouncer(std::string nettest_name,
                           std::vector<std::string> nettest_helper_names,
                           std::string nettest_version,
                           std::vector<EndpointInfo> *collectors,
                           std::map<std::string,
                             std::vector<EndpointInfo>> *test_helpers,
                           BytesInfo *info, ErrContext *err) noexcept {
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: nettest_name: " << nettest_name);
  for (auto &helper : nettest_helper_names) {
    LIBNETTEST2_EMIT_DEBUG("query_bouncer: helper: - " << helper);
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: nettest_version: " << nettest_version);
  if (collectors == nullptr || test_helpers == nullptr ||
      info == nullptr || err == nullptr) {
    LIBNETTEST2_EMIT_WARNING("query_bouncer: passed null pointers");
    return false;
  }
  test_helpers->clear();
  collectors->clear();
  std::string requestbody;
  try {
    nlohmann::json doc;
    doc["net-tests"] = nlohmann::json::array();
    doc["net-tests"][0] = nlohmann::json::object();
    doc["net-tests"][0]["input-hashes"] = nullptr;
    doc["net-tests"][0]["name"] = nettest_name;
    doc["net-tests"][0]["test-helpers"] = nettest_helper_names;
    doc["net-tests"][0]["version"] = nettest_version;
    requestbody = doc.dump();
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("query_bouncer: cannot serialize request");
    err->reason = 1;
    err->library_name = "nlohmann/json";
    err->library_version = nlohmann_json_version();
    err->reason = exc.what();
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: JSON request: " << requestbody);
  std::string responsebody;
  // TODO(bassosimone): we should probably discuss with @hellais whether we
  // like that currently we do not have a cloudfronted bouncer fallback. This
  // is to be done later since I want to reach feature parity with MK legacy
  // codebase first, and focus on perks later.
  std::string url = without_final_slash(settings_.bouncer_base_url);
  url += "/bouncer/net-tests";
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody, info, err)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: JSON reply: " << responsebody);
  try {
    // TODO(bassosimone): make processing more flexible and robust? Here we
    // are making strong assumptions on the returned object type. This is
    // also something that we can defer to the future.
    auto doc = nlohmann::json::parse(responsebody);
    for (auto &entry : doc.at("net-tests")) {
      {
        EndpointInfo info;
        info.type = endpoint_type_onion;
        info.address = entry.at("collector");
        collectors->push_back(std::move(info));
      }
      for (auto &entry : entry.at("collector-alternate")) {
        EndpointInfo info;
        if (entry.at("type") == "https") {
          info.type = endpoint_type_https;
          info.address = entry.at("address");
        } else if (entry.at("type") == "cloudfront") {
          info.type = endpoint_type_cloudfront;
          info.address = entry.at("address");
          info.front = entry.at("front");
        } else {
          continue;
        }
        collectors->push_back(std::move(info));
      }
#ifdef NLOHMANN_JSON_VERSION_MAJOR  // >= v3.0.0
      for (auto &entry : entry.at("test-helpers").items()) {
#else
      for (auto &entry : nlohmann::json::iterator_wrapper(entry.at("test-helpers"))) {
#endif
        std::string key = entry.key();
        EndpointInfo info;
        info.type = endpoint_type_onion;
        info.address = entry.value();
        (*test_helpers)[key].push_back(std::move(info));
      }
#ifdef NLOHMANN_JSON_VERSION_MAJOR  // >= v3.0.0
      for (auto &entry : entry.at("test-helpers-alternate").items()) {
#else
      for (auto &entry : nlohmann::json::iterator_wrapper(entry.at("test-helpers-alternate"))) {
#endif
        std::string key = entry.key();
        for (auto &entry : entry.value()) {
          EndpointInfo info;
          if (entry.at("type") == "https") {
            info.type = endpoint_type_https;
            info.address = entry.at("address");
          } else if (entry.at("type") == "cloudfront") {
            info.type = endpoint_type_cloudfront;
            info.address = entry.at("address");
            info.front = entry.at("front");
          } else {
            continue;
          }
          (*test_helpers)[key].push_back(std::move(info));
        }
      }
    }
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("query_bouncer: cannot process response: "
                             << exc.what());
    err->reason = 1;
    err->library_name = "nlohmann/json";
    err->library_version = nlohmann_json_version();
    err->reason = exc.what();
    return false;
  }
  for (auto &info : *collectors) {
    LIBNETTEST2_EMIT_DEBUG("query_bouncer: collector: address='"
      << info.address << "' type=" << (uint32_t)info.type
      << " front='" << info.front << "'");
  }
  for (auto &pair : *test_helpers) {
    auto &values = pair.second;
    auto &key = pair.first;
    for (auto &info : values) {
      LIBNETTEST2_EMIT_DEBUG("query_bouncer: test_helper: key='" << key
        << "' address='" << info.address << "' type=" << (uint32_t)info.type
        << " front='" << info.front << "'");
    }
  }
  return true;
}

static bool xml_extract(std::string input, std::string open_tag,
                        std::string close_tag, std::string *result) noexcept {
  if (result == nullptr) return false;
  auto pos = input.find(open_tag);
  if (pos == std::string::npos) return false;
  input = input.substr(pos + open_tag.size());
  pos = input.find(close_tag);
  if (pos == std::string::npos) return false;
  input = input.substr(0, pos);
  for (auto ch : input) {
    if (isspace(ch)) continue;
    // TODO(bassosimone): perhaps reject input that is not printable? This is
    // something that I may want to discuss with @hellais or @darkk.
    *result += tolower(ch);
  }
  return true;
}

bool Runner::lookup_ip(std::string *ip, BytesInfo *info,
                       ErrContext *err) noexcept {
  if (ip == nullptr || info == nullptr || err == nullptr) return false;
  ip->clear();
  std::string responsebody;
  // TODO(bassosimone): as discussed several time with @hellais, here we
  // should use other services for getting the probe's IP address. Let us
  // reach feature parity first and then we can work on this.
  std::string url = "https://geoip.ubuntu.com/lookup";
  LIBNETTEST2_EMIT_DEBUG("lookup_ip: URL: " << url);
  if (!curlx_get(std::move(url), curl_timeout, &responsebody, info, err)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("lookup_ip: response: " << responsebody);
  return xml_extract(responsebody, "<Ip>", "</Ip>", ip);
}

bool Runner::lookup_resolver_ip(
    std::string *ip, BytesInfo *info, ErrContext *err) noexcept {
  if (ip == nullptr || info == nullptr || err == nullptr) return false;
  ip->clear();
  // TODO(bassosimone): so, here we use getaddrinfo() because we want to know
  // what resolver has the user configured by default. However, the nettest
  // MAY use another resolver. It's important to decide whether this would be
  // a problem or not. There is also a _third_ case, i.e. the Vodafone-like
  // case where there is a transparent DNS proxy.
  //
  // TODO(bassosimone): currently we're using A only because we're doing what
  // MK does but we should consider doing a AAAA query as well.
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_flags |= AI_NUMERICSERV;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *rp = nullptr;
  {
    // Upper bound estimate: assume that the AF_INET query takes a maximum
    // size IP datagram (i.e. 512 bytes according to <arpa/nameser.h>)
    info->bytes_up += 512;
    info->bytes_down += 512;
  }
  auto rv = ::getaddrinfo("whoami.akamai.net", "443", &hints, &rp);
  if (rv != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_resolver_ip: " << gai_strerror(rv));
    err->code = rv;
    err->library_name = "libc/getaddrinfo";
    err->library_version = "";
    err->reason = gai_strerror(rv);
    return false;
  }
  for (auto ai = rp; ai != nullptr && ip->empty(); ai = ai->ai_next) {
    char host[NI_MAXHOST];
    if (::getnameinfo(ai->ai_addr, ai->ai_addrlen, host, NI_MAXHOST, nullptr,
                      0, NI_NUMERICHOST) != 0) {
      LIBNETTEST2_EMIT_WARNING("lookup_resolver_ip: getnameinfo() failed");
      break;  // This should not happen in a sane system
    }
    *ip = host;
  }
  ::freeaddrinfo(rp);
  return !ip->empty();
}

bool Runner::open_report(const std::string &collector_base_url,
                         const std::string &test_start_time,
                         const NettestContext &context,
                         std::string *report_id,
                         BytesInfo *info,
                         ErrContext *err) noexcept {
  if (report_id == nullptr || info == nullptr || err == nullptr) return false;
  report_id->clear();
  std::string requestbody;
  try {
    nlohmann::json doc;
    doc["data_format_version"] = "0.2.0";
    doc["format"] = "json";
    doc["input_hashes"] = nlohmann::json::array();
    doc["probe_asn"] = context.probe_asn;
    doc["probe_cc"] = context.probe_cc;
    doc["software_name"] = settings_.software_name;
    doc["software_version"] = settings_.software_version;
    doc["test_name"] = nettest_.name();
    doc["test_start_time"] = test_start_time,
    doc["test_version"] = nettest_.version();
    requestbody = doc.dump();
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("open_report: cannot serialize JSON");
    err->reason = 1;
    err->library_name = "nlohmann/json";
    err->library_version = nlohmann_json_version();
    err->reason = exc.what();
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("open_report: JSON request: " << requestbody);
  std::string responsebody;
  std::string url = without_final_slash(collector_base_url);
  url += "/report";
  LIBNETTEST2_EMIT_DEBUG("open_report: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody, info, err)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("open_report: JSON reply: " << responsebody);
  try {
    auto doc = nlohmann::json::parse(responsebody);
    *report_id = doc.at("report_id");
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("open_report: can't parse reply: " << exc.what());
    err->reason = 1;
    err->library_name = "nlohmann/json";
    err->library_version = nlohmann_json_version();
    err->reason = exc.what();
    return false;
  }
  return true;
}

bool Runner::update_report(const std::string &collector_base_url,
                           const std::string &report_id,
                           const std::string &json_str,
                           BytesInfo *info,
                           ErrContext *err) const noexcept {
  if (info == nullptr || err == nullptr) return false;
  std::string responsebody;
  std::string url = without_final_slash(collector_base_url);
  url += "/report/";
  url += report_id;
  nlohmann::json message;
  message["content"] = json_str;
  message["format"] = "json";
  std::string requestbody;
  try {
    requestbody = message.dump();
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("update_report: cannot serialize request");
    err->reason = 1;
    err->library_name = "nlohmann/json";
    err->library_version = nlohmann_json_version();
    err->reason = exc.what();
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("update_report: JSON request: " << requestbody);
  LIBNETTEST2_EMIT_DEBUG("update_report: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody, info, err)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("update_report: JSON reply: " << responsebody);
  return true;
}

bool Runner::close_report(const std::string &collector_base_url,
                          const std::string &report_id,
                          BytesInfo *info,
                          ErrContext *err) noexcept {
  if (info == nullptr || err == nullptr) return false;
  std::string responsebody;
  std::string url = without_final_slash(collector_base_url);
  url += "/report/" + report_id + "/close";
  LIBNETTEST2_EMIT_DEBUG("close_report: URL: " << url);
  if (!curlx_post_json(std::move(url), "", curl_timeout,
                       &responsebody, info, err)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("close_report: response body: " << responsebody);
  return true;
}

// MaxMindDB code
// ``````````````

bool Runner::lookup_asn(const std::string &dbpath,
                        const std::string &probe_ip,
                        std::string *asn,
                        std::string *probe_network_name,
                        ErrContext *err) noexcept {
  if (asn == nullptr || probe_network_name == nullptr || err == nullptr) {
    return false;
  }
  asn->clear();
  probe_network_name->clear();
  // TODO(bassosimone): there is a great deal of duplication of basically equal
  // MMDB code here that can be solved by refactoring common code.
  MMDB_s mmdb{};
  auto mmdb_error = ::MMDB_open(dbpath.data(), MMDB_MODE_MMAP, &mmdb);
  if (mmdb_error != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
    err->code = mmdb_error;
    err->library_name = "libmaxminddb/MMDB_open";
    err->library_version = MMDB_lib_version();
    err->reason = MMDB_strerror(mmdb_error);
    return false;
  }
  auto rv = false;
  do {
    auto gai_error = 0;
    mmdb_error = 0;
    auto record = MMDB_lookup_string(&mmdb, probe_ip.data(),
                                     &gai_error, &mmdb_error);
    if (gai_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_asn: " << gai_strerror(gai_error));
      // Note: MMDB_lookup_string() calls getaddrinfo() and the reported
      // gai_error error code originates from getaddrinfo().
      err->code = gai_error;
      err->library_name = "libc/getaddrinfo";
      err->library_version = "";
      err->reason = gai_strerror(gai_error);
      break;
    }
    if (mmdb_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
      err->code = mmdb_error;
      err->library_name = "libmaxminddb/MMDB_lookup_string";
      err->library_version = MMDB_lib_version();
      err->reason = MMDB_strerror(mmdb_error);
      break;
    }
    if (!record.found_entry) {
      LIBNETTEST2_EMIT_WARNING("lookup_asn: no entry for: " << probe_ip);
      auto e = Errors::mmdb_enoent;
      err->code = (int64_t)e;
      err->library_name = default_engine_name();
      err->library_version = version();
      err->reason = libnettest2_strerror(e);
      break;
    }
    {
      MMDB_entry_data_s entry{};
      mmdb_error = MMDB_get_value(
          &record.entry, &entry, "autonomous_system_number", nullptr);
      if (mmdb_error != 0) {
        LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
        err->code = mmdb_error;
        err->library_name = "libmaxminddb/MMDB_get_value";
        err->library_version = MMDB_lib_version();
        err->reason = MMDB_strerror(mmdb_error);
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UINT32) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
        auto e = Errors::mmdb_enodatafortype;
        err->code = (int64_t)e;
        err->library_name = default_engine_name();
        err->library_version = version();
        err->reason = libnettest2_strerror(e);
        break;
      }
      *asn = std::string{"AS"} + std::to_string(entry.uint32);
    }
    {
      MMDB_entry_data_s entry{};
      mmdb_error = MMDB_get_value(
          &record.entry, &entry, "autonomous_system_organization", nullptr);
      if (mmdb_error != 0) {
        LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
        err->code = mmdb_error;
        err->library_name = "libmaxminddb/MMDB_get_value";
        err->library_version = MMDB_lib_version();
        err->reason = MMDB_strerror(mmdb_error);
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
        auto e = Errors::mmdb_enodatafortype;
        err->code = (int64_t)e;
        err->library_name = default_engine_name();
        err->library_version = version();
        err->reason = libnettest2_strerror(e);
        break;
      }
      *probe_network_name = std::string{entry.utf8_string, entry.data_size};
    }
    rv = true;
  } while (false);
  MMDB_close(&mmdb);
  return rv;
}

bool Runner::lookup_cc(const std::string &dbpath, const std::string &probe_ip,
                       std::string *cc, ErrContext *err) noexcept {
  if (cc == nullptr || err == nullptr) return false;
  cc->clear();
  MMDB_s mmdb{};
  auto mmdb_error = ::MMDB_open(dbpath.data(), MMDB_MODE_MMAP, &mmdb);
  if (mmdb_error != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
    err->code = mmdb_error;
    err->library_name = "libmaxminddb/MMDB_open";
    err->library_version = MMDB_lib_version();
    err->reason = MMDB_strerror(mmdb_error);
    return false;
  }
  auto rv = false;
  do {
    auto gai_error = 0;
    mmdb_error = 0;
    auto record = MMDB_lookup_string(&mmdb, probe_ip.data(),
                                     &gai_error, &mmdb_error);
    if (gai_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_cc: " << gai_strerror(gai_error));
      // Note: MMDB_lookup_string() calls getaddrinfo() and the reported
      // gai_error error code originates from getaddrinfo().
      err->code = gai_error;
      err->library_name = "libc/getaddrinfo";
      err->library_version = "";
      err->reason = gai_strerror(gai_error);
      break;
    }
    if (mmdb_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
      err->code = mmdb_error;
      err->library_name = "libmaxminddb/MMDB_lookup_string";
      err->library_version = MMDB_lib_version();
      err->reason = MMDB_strerror(mmdb_error);
      break;
    }
    if (!record.found_entry) {
      LIBNETTEST2_EMIT_WARNING("lookup_cc: no entry for: " << probe_ip);
      auto e = Errors::mmdb_enoent;
      err->code = (int64_t)e;
      err->library_name = default_engine_name();
      err->library_version = version();
      err->reason = libnettest2_strerror(e);
      break;
    }
    {
      MMDB_entry_data_s entry{};
      mmdb_error = MMDB_get_value(
          &record.entry, &entry, "registered_country", "iso_code", nullptr);
      if (mmdb_error != 0) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
        err->code = mmdb_error;
        err->library_name = "libmaxminddb/MMDB_get_value";
        err->library_version = MMDB_lib_version();
        err->reason = MMDB_strerror(mmdb_error);
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
        auto e = Errors::mmdb_enodatafortype;
        err->code = (int64_t)e;
        err->library_name = default_engine_name();
        err->library_version = version();
        err->reason = libnettest2_strerror(e);
        break;
      }
      *cc = std::string{entry.utf8_string, entry.data_size};
    }
    rv = true;
  } while (false);
  MMDB_close(&mmdb);
  return rv;
}

// cURL code
// `````````

void Runner::CurlxDeleter::operator()(CURL *handle) noexcept {
  curl_easy_cleanup(handle);  // handless null gracefully
}

class CurlxSlist {
 public:
  curl_slist *slist = nullptr;

  CurlxSlist() noexcept = default;
  CurlxSlist(const CurlxSlist &) noexcept = delete;
  CurlxSlist &operator=(const CurlxSlist &) noexcept = delete;
  CurlxSlist(CurlxSlist &&) noexcept = delete;
  CurlxSlist &operator=(CurlxSlist &&) noexcept = delete;

  ~CurlxSlist() noexcept;
};

CurlxSlist::~CurlxSlist() noexcept {
  curl_slist_free_all(slist);  // handles nullptr gracefully
}

bool Runner::curlx_post_json(std::string url,
                             std::string requestbody,
                             long timeout,
                             std::string *responsebody,
                             BytesInfo *info,
                             ErrContext *err) const noexcept {
  if (responsebody == nullptr || info == nullptr || err == nullptr) {
    return false;
  }
  *responsebody = "";
  UniqueCurlx handle;
  handle.reset(::curl_easy_init());
  if (!handle) {
    LIBNETTEST2_EMIT_WARNING("curlx_post_json: curl_easy_init() failed");
    return false;
  }
  CurlxSlist headers;
  // TODO(bassosimone): here we should implement support for Tor and for
  // cloudfronted. Code doing that was implemented by @hellais into the
  // measurement-kit/web-api-client repository. Deferred after we have a
  // status a feature parity with MK.
  if (!requestbody.empty()) {
    {
      if ((headers.slist = curl_slist_append(
               headers.slist, "Content-Type: application/json")) == nullptr) {
        LIBNETTEST2_EMIT_WARNING("curlx_post_json: curl_slist_append() failed");
        return false;
      }
      if (::curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER,
                             headers.slist) != CURLE_OK) {
        LIBNETTEST2_EMIT_WARNING(
            "curlx_post_json: curl_easy_setopt(CURLOPT_HTTPHEADER) failed");
        return false;
      }
    }
    if (::curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS,
                           requestbody.data()) != CURLE_OK) {
      LIBNETTEST2_EMIT_WARNING(
          "curlx_post_json: curl_easy_setopt(CURLOPT_POSTFIELDS) failed");
      return false;
    }
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_POST, 1) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_post_json: curl_easy_setopt(CURLOPT_POST) failed");
    return false;
  }
  return curlx_common(handle, std::move(url), timeout, responsebody, info, err);
}

bool Runner::curlx_get(std::string url,
                       long timeout,
                       std::string *responsebody,
                       BytesInfo *info,
                       ErrContext *err) noexcept {
  if (responsebody == nullptr || info == nullptr || err == nullptr) {
    return false;
  }
  *responsebody = "";
  UniqueCurlx handle;
  handle.reset(::curl_easy_init());
  if (!handle) {
    LIBNETTEST2_EMIT_WARNING("curlx_get: curl_easy_init() failed");
    return false;
  }
  return curlx_common(handle, std::move(url), timeout, responsebody, info, err);
}

}  // namespace libnettest2
}  // namespace measurement_kit
extern "C" {

static size_t libnettest2_curl_stringstream_callback(
    char *ptr, size_t size, size_t nmemb, void *userdata) noexcept {
  if (nmemb <= 0) {
    return 0;  // This means "no body"
  }
  if (size > SIZE_MAX / nmemb) {
    assert(false);  // Also catches case where size is zero
    return 0;
  }
  auto realsiz = size * nmemb;  // Overflow not possible (see above)
  auto ss = static_cast<std::stringstream *>(userdata);
  (*ss) << std::string{ptr, realsiz};
  // From fwrite(3): "[the return value] equals the number of bytes
  // written _only_ when `size` equals `1`". See also
  // https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/iofwrite.c;h=800341b7da546e5b7fd2005c5536f4c90037f50d;hb=HEAD#l29
  return nmemb;
}

static int libnettest2_curl_debugfn(CURL *handle,
                                    curl_infotype type,
                                    char *data,
                                    size_t size,
                                    void *userptr) {
  (void)handle;
  using namespace measurement_kit::libnettest2;
  auto wrapper = static_cast<Runner::BytesInfoWrapper *>(userptr);
  auto info = wrapper->info;
  auto owner = wrapper->owner;
  // Emit debug messages if the log level allows that
  if (owner->get_log_level() >= log_debug) {
    auto log_many_lines = [&](std::string prefix, std::string str) {
      std::stringstream ss;
      ss << str;
      std::string line;
      while (std::getline(ss, line, '\n')) {
        LIBNETTEST2_EMIT_DEBUG_EX(owner, "curl: " << prefix << line);
      }
    };
    switch (type) {
      case CURLINFO_TEXT:
        log_many_lines("", std::string{(char *)data, size});
        break;
      case CURLINFO_HEADER_IN:
        log_many_lines("< ", std::string{(char *)data, size});
        break;
      case CURLINFO_DATA_IN:
        LIBNETTEST2_EMIT_DEBUG_EX(owner, "curl: < data{" << size << "}");
        break;
      case CURLINFO_SSL_DATA_IN:
        LIBNETTEST2_EMIT_DEBUG_EX(owner, "curl: < ssl_data{" << size << "}");
        break;
      case CURLINFO_HEADER_OUT:
        log_many_lines("> ", std::string{(char *)data, size});
        break;
      case CURLINFO_DATA_OUT:
        LIBNETTEST2_EMIT_DEBUG_EX(owner, "curl: > data{" << size << "}");
        break;
      case CURLINFO_SSL_DATA_OUT:
        LIBNETTEST2_EMIT_DEBUG_EX(owner, "curl: > ssl_data{" << size << "}");
        break;
      case CURLINFO_END:
        /* NOTHING */
        break;
    }
  }
  // Note regarding counting TLS data
  // ````````````````````````````````
  //
  // I am using the technique recommended by Stenberg on Stack Overflow [1]. It
  // was initially not clear to me whether cURL using OpenSSL counted the data
  // twice, once encrypted and once in clear text. However, using cURL using
  // OpenSSL on Linux and reading the source code [2] helped me to clarify that
  // it does indeed the right thing [3]. When using other TLS backends, it may
  // be that TLS data is not counted, but that's okay since we tell to users
  // that this is an estimate of the amount of used data.
  //
  // Notes
  // `````
  //
  // .. [1] https://stackoverflow.com/a/26905099
  //
  // .. [2] https://github.com/curl/curl/blob/6684653b/lib/vtls/openssl.c#L2295
  //
  // .. [3] the SSL function used is SSL_CTX_set_msg_callback which "[is] never
  //        [called for] application_data(23) because the callback will only be
  //        called for protocol messages" [4].
  //
  // .. [4] https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_msg_callback.html
  switch (type) {
    case CURLINFO_HEADER_IN:
    case CURLINFO_DATA_IN:
    case CURLINFO_SSL_DATA_IN:
      info->bytes_down += size;
      break;
    case CURLINFO_HEADER_OUT:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_OUT:
      info->bytes_up += size;
      break;
    case CURLINFO_TEXT:
    case CURLINFO_END:
      /* NOTHING */
      break;
  }
  return 0;
}

}  // extern "C"
namespace measurement_kit {
namespace libnettest2 {

bool Runner::curlx_common(UniqueCurlx &handle,
                          std::string url,
                          long timeout,
                          std::string *responsebody,
                          BytesInfo *info,
                          ErrContext *err) const noexcept {
  if (responsebody == nullptr || info == nullptr || err == nullptr) {
    return false;
  }
  *responsebody = "";
  if (::curl_easy_setopt(handle.get(), CURLOPT_URL, url.data()) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_URL) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION,
                         libnettest2_curl_stringstream_callback) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed");
    return false;
  }
  std::stringstream ss;
  if (::curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &ss) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_WRITEDATA) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, timeout) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_TIMEOUT) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_DEBUGFUNCTION,
                         libnettest2_curl_debugfn) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_DEBUGFUNCTION) failed");
    return false;
  }
  BytesInfoWrapper w;
  w.owner = this;
  w.info = info;
  if (::curl_easy_setopt(handle.get(), CURLOPT_DEBUGDATA, &w) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_DEBUGDATA) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_VERBOSE, 1L) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_VERBOSE) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_FAILONERROR, 1L) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_FAILONERROR) failed");
    return false;
  }
  auto curle = ::curl_easy_perform(handle.get());
  if (curle != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING("curlx_common: curl_easy_perform() failed");
    // Here's a reasonable assumption: in general the most likely cURL API that
    // could fail is curl_perform(). So just gather the error in here.
    err->code = curle;
    err->library_name = "libcurl";
    err->library_version = LIBCURL_VERSION;
    err->reason = ::curl_easy_strerror(curle);
    return false;
  }
  *responsebody = ss.str();
  return true;
}

#endif  // LIBNETTEST2_NO_INLINE_IMPL
}  // namespace libnettest2
}  // namespace measurement_kit
#endif
