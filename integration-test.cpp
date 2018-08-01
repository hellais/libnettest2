// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include <stdlib.h>

#include "json.hpp"
#include "libnettest2.hpp"

using namespace measurement_kit;

// MockWebConnectivity
// ```````````````````

class MockWebConnectivity : public libnettest2::Nettest {
 public:
  using libnettest2::Nettest::Nettest;

  std::string name() const noexcept override;

  std::vector<std::string> test_helpers() const noexcept override;

  bool needs_input() const noexcept override;

  bool run(const libnettest2::Settings &settings,
           const libnettest2::NettestContext &context,
           std::string input,
           nlohmann::json *result) noexcept override;

  ~MockWebConnectivity() noexcept override;
};

std::string MockWebConnectivity::name() const noexcept {
  return "web_connectivity";
}

bool MockWebConnectivity::needs_input() const noexcept {
  return true;
}

std::vector<std::string> MockWebConnectivity::test_helpers() const noexcept {
  return {"web-connectivity"};
}

bool MockWebConnectivity::run(const libnettest2::Settings &settings,
                              const libnettest2::NettestContext &context,
                              std::string input,
                              nlohmann::json *result) noexcept {
  return libnettest2::Nettest::run(settings, context, std::move(input), result);
}

MockWebConnectivity::~MockWebConnectivity() noexcept {}

// main
// ````

int main() {
  libnettest2::Settings settings;
  settings.log_level = libnettest2::log_debug;
  settings.geoip_asn_path = "GeoLite2-ASN_20180731/GeoLite2-ASN.mmdb";
  settings.geoip_country_path = "GeoLite2-Country_20180703/GeoLite2-Country.mmdb";
  settings.inputs = {"www.google.com", "www.kernel.org"};
  MockWebConnectivity nettest;
  libnettest2::Runner runner{settings, nettest};
  return runner.run() ? EXIT_SUCCESS : EXIT_FAILURE;
}
