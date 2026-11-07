// C++ shim over the libwebrtc prebuilt's C++ API. Rust never sees the C++
// types: this file converts to libwebrtc's ABI-safe `libwebrtc::string` /
// `libwebrtc::vector` and exposes plain C functions.
#include "shim.h"

#include <string>
#include <vector>

#include "libwebrtc.h"
#include "rtc_field_trials.h"

namespace {

std::vector<libwebrtc::string> parse_trials(const char* csv) {
  std::vector<libwebrtc::string> out;
  if (csv == nullptr || *csv == '\0') {
    return out;
  }
  std::string s(csv);
  size_t start = 0;
  for (;;) {
    size_t comma = s.find(',', start);
    std::string entry = (comma == std::string::npos)
                            ? s.substr(start)
                            : s.substr(start, comma - start);
    if (!entry.empty()) {
      out.push_back(libwebrtc::string(entry));
    }
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  return out;
}

}  // namespace

extern "C" int ct_webrtc_init(const char* field_trials_csv) {
  std::vector<libwebrtc::string> entries = parse_trials(field_trials_csv);
  libwebrtc::vector<libwebrtc::string> trials(entries);
  libwebrtc::LibWebRTC::InitializeWithFieldTrials(trials);
  return 0;
}

extern "C" int ct_webrtc_field_trial_enabled(const char* key) {
  return libwebrtc::RTCFieldTrials::IsEnabled(libwebrtc::string(key)) ? 1 : 0;
}

extern "C" void ct_webrtc_terminate(void) {
  libwebrtc::LibWebRTC::Terminate();
}
