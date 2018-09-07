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
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <maxminddb.h>

// Check dependencies
// ``````````````````
#ifndef NLOHMANN_JSON_VERSION_MAJOR
#error "Libnettest2 depends on nlohmann/json. Include nlohmann/json before including libnettest2."
#endif  // !NLOHMANN_JSON_VERSION_MAJOR
#if NLOHMANN_JSON_VERSION_MAJOR < 3
#error "Libnettest2 requires nlohmann/json >= 3"
#endif

namespace measurement_kit {
namespace libnettest2 {

constexpr const char *default_engine_name() noexcept {
  return "measurement_kit";
}

// Versioning
// ``````````

/// Type containing a version number.
using Version = unsigned int;

/// Major API version number of measurement-kit/libnettest2.
constexpr Version version_major = Version{0};

/// Minor API version number of measurement-kit/libnettest2.
constexpr Version version_minor = Version{0};

/// Patch API version number of measurement-kit/libnettest2.
constexpr Version version_patch = Version{0};

/// Returns a string reresentation of the version
std::string version() noexcept {
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

// Settings
// ````````

class Settings {
 public:
  std::map<std::string, std::string> annotations;
  std::string bouncer_base_url = "https://bouncer.ooni.io";
  std::string collector_base_url;
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

class Nettest {
 public:
  virtual std::string name() const noexcept;

  virtual std::vector<std::string> test_helpers() const noexcept;

  virtual std::string version() const noexcept;

  virtual bool needs_input() const noexcept;

  virtual bool run(const Settings &settings,
                   const NettestContext &context,
                   std::string input,
                   nlohmann::json *test_keys) noexcept;

  virtual ~Nettest() noexcept;
};

// Events
// ``````

class FailureASNLookup {
 public:
  std::string failure;
};

class FailureCCLookup {
 public:
  std::string failure;
};

class FailureIPLookup {
 public:
  std::string failure;
};

class FailureResolverLookup {
 public:
  std::string failure;
};

class LogEvent {
 public:
  LogLevel log_level = log_quiet;
  std::string message;
};

// Note: better to avoid uint64_t because they translate to big
// integers in Java, if we use SWIG. However this may just be
// a void concern and we can reconsider this decision.

class MeasurementEvent {
 public:
  uint32_t idx = 0;
  std::string json_str;
  std::string input;
};

class StatusGeoipLookupEvent {
 public:
  std::string probe_ip;
  std::string probe_asn;
  std::string probe_cc;
  std::string probe_network_name;
};

class StatusMeasurementDoneEvent {
 public:
  uint32_t idx = 0;
};

class StatusMeasurementStartEvent {
 public:
  uint32_t idx = 0;
  std::string input;
};

class StatusProgressEvent {
 public:
  double percentage = 0.0;
  std::string message;
};

class StatusReportCreateEvent {
 public:
  std::string report_id;
};

class StatusResolverLookupEvent {
 public:
  std::string resolver_ip;
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

 protected:
  // Methods you typically want to override
  // ``````````````````````````````````````
  // They allow you to know when specific events happen.

  // Note: not using noexcept here because of SWIG. Again, if we decide to
  // avoid using SWIG, we can then ignore this concern.
  virtual void on_failure_asn_lookup(FailureASNLookup event);
  virtual void on_failure_cc_lookup(FailureCCLookup event);
  virtual void on_failure_ip_lookup(FailureIPLookup event);
  virtual void on_failure_resolver_lookup(FailureResolverLookup event);

  virtual void on_log(LogEvent event) const;
  virtual void on_measurement(MeasurementEvent event) const;
  virtual void on_status_geoip_lookup(StatusGeoipLookupEvent event);

  virtual void on_status_measurement_done(
      StatusMeasurementDoneEvent event) const;

  virtual void on_status_measurement_start(
      StatusMeasurementStartEvent event) const;

  virtual void on_status_progress(StatusProgressEvent event);
  virtual void on_status_report_create(StatusReportCreateEvent event);
  virtual void on_status_resolver_lookup(StatusResolverLookupEvent event);
  virtual void on_status_started();

  // Methods you generally DON'T want to override
  // ````````````````````````````````````````````
  // You may want to override them in unit tests, however.

  virtual bool run_with_index32(
      const std::chrono::time_point<std::chrono::steady_clock> &begin,
      const std::vector<std::string> &inputs, const NettestContext &ctx,
      const std::string &collector_base_url, uint32_t i) const noexcept;

  virtual bool query_bouncer(std::string nettest_name,
                             std::vector<std::string> nettest_helper_names,
                             std::string nettest_version,
                             std::vector<EndpointInfo> *collectors,
                             std::map<std::string,
                               std::vector<EndpointInfo>> *helpers) noexcept;

  virtual bool lookup_ip(std::string *ip) noexcept;

  virtual bool lookup_resolver_ip(std::string *ip) noexcept;

  virtual bool open_report(const std::string &collector_base_url,
                           const NettestContext &context,
                           std::string *report_id) noexcept;

  virtual bool submit_report(const std::string &collector_base_url,
                             const std::string &report_id,
                             const std::string &json_str) const noexcept;

  virtual bool close_report(const std::string &collector_base_url,
                            const std::string &report_id) noexcept;

  // MaxMindDB code
  // ``````````````

  virtual bool lookup_asn(const std::string &dbpath, const std::string &ip,
                          std::string *asn, std::string *network_name) noexcept;

  virtual bool lookup_cc(const std::string &dbpath, const std::string &probe_ip,
                         std::string *cc) noexcept;

  // cURL code
  // `````````

  class CurlDeleter {
   public:
    void operator()(CURL *handle) noexcept;
  };
  using UniqueCurl = std::unique_ptr<CURL, CurlDeleter>;

  virtual bool curlx_post_json(std::string url,
                               std::string requestbody,
                               long timeout,
                               std::string *responsebody) const noexcept;

  virtual bool curlx_get(std::string url, long timeout,
                std::string *responsebody) noexcept;

  virtual bool curlx_common(UniqueCurl &handle, std::string url, long timeout,
                            std::string *responsebody) const noexcept;

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

#define LIBNETTEST2_EMIT_LOG(level, statements) \
  do {                                          \
    if (settings_.log_level >= log_##level) {   \
      std::stringstream ss;                     \
      ss << statements;                         \
      LogEvent event;                           \
      event.log_level = log_##level;            \
      event.message = ss.str();                 \
      on_log(std::move(event));                 \
    }                                           \
  } while (0)

#define LIBNETTEST2_EMIT_WARNING(statements) \
  LIBNETTEST2_EMIT_LOG(warning, statements)

#define LIBNETTEST2_EMIT_INFO(statements) \
  LIBNETTEST2_EMIT_LOG(info, statements)

#define LIBNETTEST2_EMIT_DEBUG(statements) \
  LIBNETTEST2_EMIT_LOG(debug, statements)

// Nettest
// ```````

std::string Nettest::name() const noexcept { return ""; }

std::vector<std::string> Nettest::test_helpers() const noexcept { return {}; }

std::string Nettest::version() const noexcept { return "0.0.1"; }

bool Nettest::needs_input() const noexcept { return false; }

bool Nettest::run(const Settings &, const NettestContext &,
                  std::string, nlohmann::json *) noexcept {
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

bool Runner::run() noexcept {
  // TODO(bassosimone): we have removed the part where we prevent
  // multiple nettests from running concurrently, is that OK?
  NettestContext ctx;
  on_status_started();
  {
    if (!settings_.no_bouncer) {
      if (!query_bouncer(nettest_.name(), nettest_.test_helpers(),
                         nettest_.version(), &ctx.collectors,
                         &ctx.test_helpers)) {
        LIBNETTEST2_EMIT_WARNING("run: query_bouncer() failed");
        // FALLTHROUGH
      }
    }
  }
  {
    StatusProgressEvent event;
    event.percentage = 0.1;
    event.message = "contact bouncer";
    on_status_progress(std::move(event));
  }
  {
    if (settings_.probe_ip == "") {
      if (!settings_.no_ip_lookup) {
        if (!lookup_ip(&ctx.probe_ip)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_ip() failed");
          {
            FailureIPLookup event;
            // TODO(bassosimone): can we map the cURL error?
            event.failure = "generic_error";
            on_failure_ip_lookup(std::move(event));
          }
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
        if (!lookup_asn(settings_.geoip_asn_path, ctx.probe_ip, &ctx.probe_asn,
                        &ctx.probe_network_name)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_asn() failed");
          {
            // TODO(bassosimone): can we gather the MMDB error?
            FailureASNLookup event;
            event.failure = "generic_error";
          }
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
        if (!lookup_cc(settings_.geoip_country_path, ctx.probe_ip,
                       &ctx.probe_cc)) {
          LIBNETTEST2_EMIT_WARNING("run: lookup_cc() failed");
          {
            FailureCCLookup event;
            // TODO(bassosimone): map the MMDB error.
            event.failure = "generic_error";
            on_failure_cc_lookup(std::move(event));
          }
        }
      }
    } else {
      ctx.probe_cc = settings_.probe_cc;
    }
    LIBNETTEST2_EMIT_DEBUG("probe_cc: " << ctx.probe_cc);
  }
  {
    StatusProgressEvent event;
    event.percentage = 0.2;
    event.message = "geoip lookup";
    on_status_progress(std::move(event));
  }
  {
    StatusGeoipLookupEvent event;
    event.probe_cc = ctx.probe_cc;
    event.probe_asn = ctx.probe_asn;
    event.probe_network_name = ctx.probe_network_name;
    event.probe_ip = ctx.probe_ip;
    on_status_geoip_lookup(std::move(event));
  }
  {
    if (!settings_.no_resolver_lookup) {
      if (!lookup_resolver_ip(&ctx.resolver_ip)) {
        LIBNETTEST2_EMIT_WARNING("run: lookup_resolver_ip() failed");
        {
          // TODO(bassosimone): map getaddrinfo error
          FailureResolverLookup event;
          event.failure = "generic_error";
          on_failure_resolver_lookup(std::move(event));
        }
      }
    }
    LIBNETTEST2_EMIT_DEBUG("resolver_ip: " << ctx.resolver_ip);
  }
  {
    StatusProgressEvent event;
    event.percentage = 0.3;
    event.message = "resolver lookup";
    on_status_progress(std::move(event));
  }
  {
    StatusResolverLookupEvent event;
    event.resolver_ip = ctx.resolver_ip;
    on_status_resolver_lookup(std::move(event));
  }
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
      if (!open_report(collector_base_url, ctx, &ctx.report_id)) {
        LIBNETTEST2_EMIT_WARNING("run: open_report() failed");
        // TODO(bassosimone): here we should emit "failure.report_create"
      }
      LIBNETTEST2_EMIT_DEBUG("report_id: " << ctx.report_id);
    } else {
      collector_base_url = settings_.collector_base_url;
    }
  }
  {
    StatusProgressEvent event;
    event.percentage = 0.4;
    event.message = "open report";
    on_status_progress(std::move(event));
  }
  {
    // TODO(bassosimone): should we emit this event if we do not have a
    // valid report id?
    StatusReportCreateEvent event;
    event.report_id = ctx.report_id;
    on_status_report_create(std::move(event));
  }
  if (nettest_.needs_input() && settings_.inputs.empty()) {
    LIBNETTEST2_EMIT_WARNING("run: no input provided");
    // TODO(bassosimone): according to the spec we should fail the
    // test in this case, however falling through isn't that bad
  } else {
    std::vector<std::string> inputs;
    if (nettest_.needs_input()) {
      inputs.insert(inputs.end(), settings_.inputs.begin(),
                    settings_.inputs.end());
    } else {
      if (!settings_.inputs.empty()) {
        LIBNETTEST2_EMIT_WARNING("run: got unexpected input");
        // TODO(bassosimone): here we should probably clear the input
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
    // TODO(bassosimone): maybe do not spawn too many threads if we do not
    // actually need that because we do not have any input?
    std::atomic<uint8_t> active{(settings_.parallelism > 0)  //
                                    ? settings_.parallelism
                                    : default_parallelism};
    auto begin = std::chrono::steady_clock::now();
    const std::chrono::time_point<std::chrono::steady_clock> &cbegin = begin;
    const std::string &ccollector_base_url = collector_base_url;
    const NettestContext &cctx = ctx;
    const std::vector<std::string> &cinputs = inputs;
    const Runner *cthis = this;
    std::atomic<uint64_t> i{0};
    std::mutex mutex;
    for (uint8_t j = 0; j < active; ++j) {
      // Implementation note: make sure this lambda has only access to either
      // constant stuff or to stuff that it's thread safe.
      auto main = [
        &active,               // atomic
        &cbegin,               // const ref
        &ccollector_base_url,  // const ref
        &cctx,                 // const ref
        &cinputs,              // const ref,
        &cthis,                // const pointer,
        &i,                    // atomic
        &mutex                 // thread safe
      ]() noexcept {
        // TODO(bassosimone): more work is required to actually interrupt
        // "long" tests like NDT that take several seconds to complete
        while (!cthis->interrupted_) {
          uint32_t idx = 0;
          {
            std::unique_lock<std::mutex> _{mutex};
            if (i > UINT32_MAX || i >= cinputs.size()) {
              break;
            }
            idx = (uint32_t)i;
            i += 1;
          }
          if (!cthis->run_with_index32(cbegin, cinputs, cctx,
                                       ccollector_base_url, idx)) {
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
  }
  {
    StatusProgressEvent event;
    event.percentage = 0.9;
    event.message = "measurement complete";
    on_status_progress(std::move(event));
  }
  if (!settings_.no_collector) {
    // TODO(bassosimone): we SHOULD NOT close a report that we could not open
    if (!close_report(collector_base_url, ctx.report_id)) {
      LIBNETTEST2_EMIT_WARNING("run: close_report() failed");
      // TODO(bassosimone): emit failure.close
    } else {
      // TODO(bassosimone): emit status.close
    }
  }
  {
    StatusProgressEvent event;
    event.percentage = 1.0;
    event.message = "report close";
    on_status_progress(std::move(event));
  }
  // TODO(bassosimone): emit status.end
  // TODO(bassosimone): count the number of bytes used by the nettest
  return true;
}

void Runner::interrupt() noexcept { interrupted_ = true; }

// Methods you typically want to override
// ``````````````````````````````````````

void Runner::on_failure_asn_lookup(FailureASNLookup event) {
  LIBNETTEST2_EMIT_WARNING("failure ASN lookup: " << event.failure);
}

void Runner::on_failure_cc_lookup(FailureCCLookup event) {
  LIBNETTEST2_EMIT_WARNING("failure CC lookup: " << event.failure);
}

void Runner::on_failure_ip_lookup(FailureIPLookup event) {
  LIBNETTEST2_EMIT_WARNING("failure IP lookup: " << event.failure);
}

void Runner::on_failure_resolver_lookup(FailureResolverLookup event) {
  LIBNETTEST2_EMIT_WARNING("failure resolver lookup: " << event.failure);
}

void Runner::on_log(LogEvent event) const {
  switch (event.log_level) {
    case log_debug: std::clog << "[D] "; break;
    case log_warning: std::clog << "[W] "; break;
    case log_info: break;
    default:
      assert(false);  // This should not happen
      return;
  }
  std::clog << event.message << std::endl;
}

void Runner::on_measurement(MeasurementEvent event) const {
  LIBNETTEST2_EMIT_INFO("MEASUREMENT: idx=" << event.idx << " input="
                                            << event.input
                                            << "json_str='"
                                            << event.json_str << "'");
}

void Runner::on_status_geoip_lookup(StatusGeoipLookupEvent event) {
  LIBNETTEST2_EMIT_INFO("GEOIP LOOKUP: probe_ip=" << event.probe_ip
      << " probe_asn=" << event.probe_asn << " probe_cc=" << event.probe_cc
      << " probe_network_name='" << event.probe_network_name << "'");
}

void Runner::on_status_measurement_done(
    StatusMeasurementDoneEvent event) const {
  LIBNETTEST2_EMIT_INFO("DONE: idx=" << event.idx);
}

void Runner::on_status_measurement_start(
    StatusMeasurementStartEvent event) const {
  LIBNETTEST2_EMIT_INFO("START: idx=" << event.idx << " input=" << event.input);
}

void Runner::on_status_progress(StatusProgressEvent event) {
  LIBNETTEST2_EMIT_INFO("* " << (uint32_t)(100.0 * event.percentage) << "%: "
                        << event.message);
}

void Runner::on_status_report_create(StatusReportCreateEvent event) {
  LIBNETTEST2_EMIT_INFO("REPORT CREATE: id=" << event.report_id);
}

void Runner::on_status_resolver_lookup(StatusResolverLookupEvent event) {
  LIBNETTEST2_EMIT_INFO("RESOLVER LOOKUP: ip=" << event.resolver_ip);
}

void Runner::on_status_started() { LIBNETTEST2_EMIT_INFO("STARTED"); }

// Methods you generally DON'T want to override
// ````````````````````````````````````````````

bool Runner::run_with_index32(
    const std::chrono::time_point<std::chrono::steady_clock> &begin,
    const std::vector<std::string> &inputs, const NettestContext &ctx,
    const std::string &collector_base_url, uint32_t i) const noexcept {
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
  {
    StatusMeasurementStartEvent event;
    event.idx = i;
    event.input = inputs[i];
    // TODO(bassosimone): the documentation should probably mention that
    // some callbacks are going to be called from a background thread.
    on_status_measurement_start(std::move(event));
  }
  nlohmann::json measurement;
  measurement["annotations"] = settings_.annotations;
  // TODO(bassosimone): it should actually be better to allow the core of
  // MK to override the following three values:
  measurement["annotations"]["engine_name"] = default_engine_name();
  measurement["annotations"]["engine_version"] = version();
  measurement["annotations"]["engine_version_full"] = version();
  measurement["annotations"]["platform"] = LIBNETTEST2_PLATFORM;
  measurement["annotations"]["probe_network_name"] =
      settings_.save_real_probe_asn
          ? ctx.probe_network_name
          : "";
  measurement["id"] = sole::uuid4().str();
  measurement["input"] = inputs[i];
  measurement["input_hashes"] = nlohmann::json::array();
  measurement["measurement_start_time"] = "XXX";  // TODO(bassosimone)
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
  measurement["test_start_time"] = "XXX";  // TODO(bassosimone)
  measurement["test_version"] = nettest_.version();
  nlohmann::json test_keys;
  auto rv = nettest_.run(settings_, ctx, inputs[i], &test_keys);
  {
    // TODO(bassosimone): This seems to be the elapsed time since the begin
    // of the whole test, however that seems to be incorrect.
    auto current_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = current_time - begin;
    measurement["test_runtime"] = elapsed.count();
  }
  // We fill the resolver_ip after the measurement. Doing that before may allow
  // the nettest to overwrite the resolver_ip field set by us.
  measurement["test_keys"] = test_keys;
  measurement["test_keys"]["resolver_ip"] = settings_.save_real_resolver_ip
                                                ? ctx.resolver_ip
                                                : "";
  if (!rv) {
    // TODO(bassosimone): emit "failure.measurement" error.
    // TODO(bassosimone): we should standardize the errors we emit.
  }
  do {
    MeasurementEvent event;
    try {
      event.json_str = measurement.dump();
    } catch (const std::exception &e) {
      LIBNETTEST2_EMIT_WARNING("run: cannot serialize JSON: " << e.what());
      // TODO(bassosimone): This is MK passing us an invalid JSON. Should we
      // submit something nonetheless as a form of telemetry?
      break;
    }
    event.idx = i;
    if (!settings_.no_collector && !event.json_str.empty()) {
      if (!submit_report(collector_base_url, ctx.report_id, event.json_str)) {
        LIBNETTEST2_EMIT_WARNING("run: submit_report() failed");
        // TODO(bassosimone): emit failure.measurement_submission
      } else {
        // TODO(bassosimone): emit status.measurement_submission
      }
    }
    if (!event.json_str.empty()) {
      // According to several discussions with @lorenzoPrimi, it is much better
      // for this event to be emitted AFTER submitting the report.
      on_measurement(std::move(event));
    }
  } while (0);
  {
    StatusMeasurementDoneEvent event;
    event.idx = i;
    on_status_measurement_done(std::move(event));
  }
  return true;
}

// TODO(bassosimone): we should _probably_ make this configurable. One way to
// do that MAY be to use the net/timeout setting.
constexpr long curl_timeout = 5;

bool Runner::query_bouncer(std::string nettest_name,
                           std::vector<std::string> nettest_helper_names,
                           std::string nettest_version,
                           std::vector<EndpointInfo> *collectors,
                           std::map<std::string,
                             std::vector<EndpointInfo>> *test_helpers) noexcept {
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: nettest_name: " << nettest_name);
  for (auto &helper : nettest_helper_names) {
    LIBNETTEST2_EMIT_DEBUG("query_bouncer: helper: - " << helper);
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: nettest_version: " << nettest_version);
  if (collectors == nullptr || test_helpers == nullptr) {
    LIBNETTEST2_EMIT_WARNING("query_bouncer: passed null pointers");
    assert(false);  // See this programmer error
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
  } catch (const std::exception &) {
    LIBNETTEST2_EMIT_WARNING("query_bouncer: cannot serialize request");
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: JSON request: " << requestbody);
  std::string responsebody;
  // TODO(bassosimone): we should probably discuss with @hellais whether we
  // like that currently we do not have a cloudfronted bouncer fallback
  std::string url = settings_.bouncer_base_url;
  url += "/bouncer/net-tests";
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("query_bouncer: JSON reply: " << responsebody);
  try {
    // TODO(bassosimone): make processing more flexible and robust. Here we
    // are making strong assumptions on the returned object type.
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
      for (auto &entry : entry.at("test-helpers").items()) {
        std::string key = entry.key();
        EndpointInfo info;
        info.type = endpoint_type_onion;
        info.address = entry.value();
        (*test_helpers)[key].push_back(std::move(info));
      }
      for (auto &entry : entry.at("test-helpers-alternate").items()) {
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
    // TODO(bassosimone): perhaps reject input that is not printable?
    *result += tolower(ch);
  }
  return true;
}

bool Runner::lookup_ip(std::string *ip) noexcept {
  if (ip == nullptr) return false;
  ip->clear();
  std::string responsebody;
  // TODO(bassosimone): as discussed several time with @hellais, here we can
  // implement other services for getting our own IP address.
  std::string url = "https://geoip.ubuntu.com/lookup";
  LIBNETTEST2_EMIT_DEBUG("lookup_ip: URL: " << url);
  if (!curlx_get(std::move(url), curl_timeout, &responsebody)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("lookup_ip: response: " << responsebody);
  return xml_extract(responsebody, "<Ip>", "</Ip>", ip);
}

bool Runner::lookup_resolver_ip(std::string *ip) noexcept {
  if (ip == nullptr) return false;
  ip->clear();
  // TODO(bassosimone): so, here we use getaddrinfo() because we want to know
  // what resolver has the user configured by default. However, the nettest
  // MAY use another resolver. It's important to decide whether this would be
  // a problem or not. There is also a _third_ case, i.e. the Vodafone-like
  // case where there is a transparent DNS proxy.
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_flags |= AI_NUMERICSERV;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *rp = nullptr;
  auto rv = ::getaddrinfo("whoami.akamai.net", "443", &hints, &rp);
  if (rv != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_resolver_ip: " << gai_strerror(rv));
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

// TODO(bassosimone): in general, when dealing with OONI backends, we SHOULD
// make sure that we remove the final slash from the base URL, if any.

bool Runner::open_report(const std::string &collector_base_url,
                         const NettestContext &context,
                         std::string *report_id) noexcept {
  if (report_id == nullptr) return false;
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
    doc["test_start_time"] = "2018-08-01 17:06:39";  // TODO(bassosimone): fill
    doc["test_version"] = nettest_.version();
    requestbody = doc.dump();
  } catch (const std::exception &) {
    LIBNETTEST2_EMIT_WARNING("open_report: cannot serialize JSON");
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("open_report: JSON request: " << requestbody);
  std::string responsebody;
  std::string url = collector_base_url;
  url += "/report";
  LIBNETTEST2_EMIT_DEBUG("open_report: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("open_report: JSON reply: " << responsebody);
  try {
    auto doc = nlohmann::json::parse(responsebody);
    *report_id = doc.at("report_id");
  } catch (const std::exception &exc) {
    LIBNETTEST2_EMIT_WARNING("open_report: can't parse reply: " << exc.what());
    return false;
  }
  return true;
}

bool Runner::submit_report(const std::string &collector_base_url,
                           const std::string &report_id,
                           const std::string &requestbody) const noexcept {
  LIBNETTEST2_EMIT_DEBUG("submit_report: JSON request: " << requestbody);
  std::string responsebody;
  std::string url = collector_base_url;
  url += "/report/";
  url += report_id;
  LIBNETTEST2_EMIT_DEBUG("submit_report: URL: " << url);
  if (!curlx_post_json(std::move(url), std::move(requestbody), curl_timeout,
                       &responsebody)) {
    return false;
  }
  LIBNETTEST2_EMIT_DEBUG("submit_report: JSON reply: " << responsebody);
  return true;
}

bool Runner::close_report(const std::string &collector_base_url,
                          const std::string &report_id) noexcept {
  std::string responsebody;
  std::string url = collector_base_url;
  url += "/report/" + report_id + "/close";
  LIBNETTEST2_EMIT_DEBUG("close_report: URL: " << url);
  if (!curlx_post_json(std::move(url), "", curl_timeout, &responsebody)) {
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
                        std::string *probe_network_name) noexcept {
  if (asn == nullptr || probe_network_name == nullptr) return false;
  asn->clear();
  probe_network_name->clear();
  MMDB_s mmdb{};
  auto mmdb_error = ::MMDB_open(dbpath.data(), MMDB_MODE_MMAP, &mmdb);
  if (mmdb_error != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
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
      break;
    }
    if (mmdb_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
      break;
    }
    if (!record.found_entry) {
      LIBNETTEST2_EMIT_WARNING("lookup_asn: no entry for: " << probe_ip);
      break;
    }
    {
      MMDB_entry_data_s entry{};
      mmdb_error = MMDB_get_value(
          &record.entry, &entry, "autonomous_system_number", nullptr);
      if (mmdb_error != 0) {
        LIBNETTEST2_EMIT_WARNING("lookup_asn: " << MMDB_strerror(mmdb_error));
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UINT32) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
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
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
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
                       std::string *cc) noexcept {
  if (cc == nullptr) return false;
  cc->clear();
  MMDB_s mmdb{};
  auto mmdb_error = ::MMDB_open(dbpath.data(), MMDB_MODE_MMAP, &mmdb);
  if (mmdb_error != 0) {
    LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
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
      break;
    }
    if (mmdb_error) {
      LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
      break;
    }
    if (!record.found_entry) {
      LIBNETTEST2_EMIT_WARNING("lookup_cc: no entry for: " << probe_ip);
      break;
    }
    {
      MMDB_entry_data_s entry{};
      mmdb_error = MMDB_get_value(
          &record.entry, &entry, "registered_country", "iso_code", nullptr);
      if (mmdb_error != 0) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: " << MMDB_strerror(mmdb_error));
        break;
      }
      if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
        LIBNETTEST2_EMIT_WARNING("lookup_cc: no data or unexpected data type");
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

// TODO(bassosimone): here we should add support for counting the amount
// of bytes consumed by communicating with the OONI backend

void Runner::CurlDeleter::operator()(CURL *handle) noexcept {
  // TODO(bassosimone): check whether curl_easy_cleanup() takes a NULL input
  if (handle != nullptr) {
    curl_easy_cleanup(handle);
  }
}

class CurlSlist {
 public:
  curl_slist *slist = nullptr;

  CurlSlist() noexcept = default;
  CurlSlist(const CurlSlist &) noexcept = delete;
  CurlSlist &operator=(const CurlSlist &) noexcept = delete;
  CurlSlist(CurlSlist &&) noexcept = delete;
  CurlSlist &operator=(CurlSlist &&) noexcept = delete;

  // TODO(bassosimone): see whether the check for NULL is required
  ~CurlSlist() noexcept { if (slist != nullptr) curl_slist_free_all(slist); }
};

bool Runner::curlx_post_json(std::string url,
                             std::string requestbody,
                             long timeout,
                             std::string *responsebody) const noexcept {
  if (responsebody == nullptr) {
    return false;
  }
  *responsebody = "";
  UniqueCurl handle;
  handle.reset(::curl_easy_init());
  if (!handle) {
    LIBNETTEST2_EMIT_WARNING("curlx_post_json: curl_easy_init() failed");
    return false;
  }
  CurlSlist headers;
  // TODO(bassosimone): here we should implement support for Tor and for
  // cloudfronted. Code doing that was implemented by @hellais into the
  // measurement-kit/web-api-client repository.
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
  return curlx_common(handle, std::move(url), timeout, responsebody);
}

bool Runner::curlx_get(std::string url, long timeout,
      std::string *responsebody) noexcept {
  if (responsebody == nullptr) {
    return false;
  }
  *responsebody = "";
  UniqueCurl handle;
  handle.reset(::curl_easy_init());
  if (!handle) {
    LIBNETTEST2_EMIT_WARNING("curlx_get: curl_easy_init() failed");
    return false;
  }
  return curlx_common(handle, std::move(url), timeout, responsebody);
}

}  // namespace libnettest2
}  // namespace measurement_kit
extern "C" {

static size_t curl_stringstream_callback(
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

}  // extern "C"
namespace measurement_kit {
namespace libnettest2 {

bool Runner::curlx_common(UniqueCurl &handle, std::string url, long timeout,
                          std::string *responsebody) const noexcept {
  if (responsebody == nullptr) {
    return false;
  }
  *responsebody = "";
  if (::curl_easy_setopt(handle.get(), CURLOPT_URL, url.data()) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING(
        "curlx_common: curl_easy_setopt(CURLOPT_URL) failed");
    return false;
  }
  if (::curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION,
                         curl_stringstream_callback) != CURLE_OK) {
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
  if (::curl_easy_perform(handle.get()) != CURLE_OK) {
    LIBNETTEST2_EMIT_WARNING("curlx_common: curl_easy_perform() failed");
    return false;
  }
  *responsebody = ss.str();
  return true;
}

#endif  // LIBNETTEST2_NO_INLINE_IMPL
}  // namespace libnettest2
}  // namespace measurement_kit
#endif
