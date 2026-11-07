// Loopback: two PeerConnections in one process, offer/answer, ICE over host
// candidates, then read the DTLS transport state and cipher suite. This is the
// runtime proof that the linked libwebrtc negotiates DTLS 1.3; the negotiated
// key-exchange *group* is not exposed by the wrapper (ssl_group_id is not there),
// so the group is checked by the byte guard and, later, a tcpdump capture.
#include "shim.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "libwebrtc.h"
#include "rtc_dtls_transport.h"
#include "rtc_mediaconstraints.h"
#include "rtc_peerconnection.h"
#include "rtc_peerconnection_factory.h"
#include "rtc_types.h"

namespace lw = libwebrtc;

namespace {

struct Candidate {
  std::string mid;
  int mline = 0;
  std::string sdp;
};

struct Loop {
  std::mutex m;
  std::condition_variable cv;

  bool offer_done = false;
  bool answer_done = false;
  bool local0_done = false;
  bool local1_done = false;
  bool remote0_done = false;
  bool remote1_done = false;
  bool connected0 = false;
  bool connected1 = false;
  std::string offer_sdp;
  std::string answer_sdp;
  std::vector<Candidate> ice0;
  std::vector<Candidate> ice1;
  std::string error;
};

Loop* g_loop = nullptr;

void note_error(const char* e) {
  Loop& l = *g_loop;
  std::lock_guard<std::mutex> lk(l.m);
  if (l.error.empty()) {
    l.error = e ? e : "unknown";
  }
  l.cv.notify_all();
}

class Observer : public lw::RTCPeerConnectionObserver {
 public:
  explicit Observer(bool zero) : zero_(zero) {}

  void OnIceCandidate(lw::scoped_refptr<lw::RTCIceCandidate> c) override {
    // The end-of-candidates marker arrives as an empty candidate; it is not a
    // candidate and must not be handed to AddCandidate.
    if (c->candidate().std_string().empty()) {
      return;
    }
    Loop& l = *g_loop;
    std::lock_guard<std::mutex> lk(l.m);
    auto& out = zero_ ? l.ice0 : l.ice1;
    out.push_back({c->sdp_mid().std_string(), c->sdp_mline_index(),
                   c->candidate().std_string()});
  }

  void OnIceConnectionState(lw::RTCIceConnectionState s) override {
    if (s == lw::RTCIceConnectionStateConnected ||
        s == lw::RTCIceConnectionStateCompleted) {
      Loop& l = *g_loop;
      std::lock_guard<std::mutex> lk(l.m);
      (zero_ ? l.connected0 : l.connected1) = true;
      l.cv.notify_all();
    }
  }

  void OnSignalingState(lw::RTCSignalingState) override {}
  void OnPeerConnectionState(lw::RTCPeerConnectionState) override {}
  void OnIceGatheringState(lw::RTCIceGatheringState) override {}
  void OnAddStream(lw::scoped_refptr<lw::RTCMediaStream>) override {}
  void OnRemoveStream(lw::scoped_refptr<lw::RTCMediaStream>) override {}
  void OnDataChannel(lw::scoped_refptr<lw::RTCDataChannel>) override {}
  void OnRenegotiationNeeded() override {}
  void OnTrack(lw::scoped_refptr<lw::RTCRtpTransceiver>) override {}
  void OnAddTrack(lw::vector<lw::scoped_refptr<lw::RTCMediaStream>>,
                  lw::scoped_refptr<lw::RTCRtpReceiver>) override {}
  void OnRemoveTrack(lw::scoped_refptr<lw::RTCRtpReceiver>) override {}

 private:
  bool zero_;
};

// Waits until pred(l) holds under the lock, or timeout_ms elapses.
template <typename P>
bool wait_until(P pred, int timeout_ms) {
  Loop& l = *g_loop;
  std::unique_lock<std::mutex> lk(l.m);
  return l.cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
    return pred(l) || !l.error.empty();
  });
}

// Move the candidates each side gathered into the other side.
void exchange(lw::scoped_refptr<lw::RTCPeerConnection> pc0,
              lw::scoped_refptr<lw::RTCPeerConnection> pc1) {
  std::vector<Candidate> c0, c1;
  {
    Loop& l = *g_loop;
    std::lock_guard<std::mutex> lk(l.m);
    c0.swap(l.ice0);
    c1.swap(l.ice1);
  }
  for (const auto& c : c0) {
    pc1->AddCandidate(c.mid, c.mline, c.sdp);
  }
  for (const auto& c : c1) {
    pc0->AddCandidate(c.mid, c.mline, c.sdp);
  }
}

}  // namespace

extern "C" int ct_loopback_handshake(int timeout_ms, int* out_dtls_state) {
  Loop loop;
  g_loop = &loop;

  auto factory = lw::LibWebRTC::CreateRTCPeerConnectionFactory();
  if (!factory || !factory->Initialize()) {
    *out_dtls_state = -1;
    return 0;
  }

  lw::RTCConfiguration config;
  auto pc_constraints = lw::RTCMediaConstraints::Create();
  auto pc0 = factory->Create(config, pc_constraints);
  auto pc1 = factory->Create(config, pc_constraints);
  if (!pc0 || !pc1) {
    *out_dtls_state = -1;
    return 0;
  }
  auto sdp_constraints = lw::RTCMediaConstraints::Create();

  Observer obs0(true), obs1(false);
  pc0->RegisterRTCPeerConnectionObserver(&obs0);
  pc1->RegisterRTCPeerConnectionObserver(&obs1);
  pc0->AddTransceiver(lw::RTCMediaType::AUDIO);
  pc1->AddTransceiver(lw::RTCMediaType::AUDIO);

  pc0->CreateOffer(
      [](lw::string sdp, lw::string) {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.offer_sdp = sdp.std_string();
        l.offer_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); }, sdp_constraints);
  if (!wait_until([](const Loop& l) { return l.offer_done; }, timeout_ms)) {
    *out_dtls_state = -1;
    return 0;
  }

  std::string offer;
  {
    std::lock_guard<std::mutex> lk(loop.m);
    offer = loop.offer_sdp;
  }
  pc0->SetLocalDescription(
      offer, "offer",
      [] {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.local0_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); });
  pc1->SetRemoteDescription(
      offer, "offer",
      [] {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.remote1_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); });
  if (!wait_until([](const Loop& l) { return l.local0_done && l.remote1_done; },
                  timeout_ms)) {
    *out_dtls_state = -1;
    return 0;
  }

  pc1->CreateAnswer(
      [](lw::string sdp, lw::string) {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.answer_sdp = sdp.std_string();
        l.answer_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); }, sdp_constraints);
  if (!wait_until([](const Loop& l) { return l.answer_done; }, timeout_ms)) {
    *out_dtls_state = -1;
    return 0;
  }

  std::string answer;
  {
    std::lock_guard<std::mutex> lk(loop.m);
    answer = loop.answer_sdp;
  }
  pc1->SetLocalDescription(
      answer, "answer",
      [] {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.local1_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); });
  pc0->SetRemoteDescription(
      answer, "answer",
      [] {
        Loop& l = *g_loop;
        std::lock_guard<std::mutex> lk(l.m);
        l.remote0_done = true;
        l.cv.notify_all();
      },
      [](const char* e) { note_error(e); });
  if (!wait_until([](const Loop& l) { return l.local1_done && l.remote0_done; },
                  timeout_ms)) {
    *out_dtls_state = -1;
    return 0;
  }

  // ICE: keep feeding candidates across until both sides report connected.
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  for (;;) {
    bool connected = false;
    {
      std::lock_guard<std::mutex> lk(loop.m);
      connected = loop.connected0 && loop.connected1;
    }
    if (connected) {
      break;
    }
    exchange(pc0, pc1);
    if (std::chrono::steady_clock::now() >= deadline) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  int cipher = 0;
  int state = -1;
  {
    std::lock_guard<std::mutex> lk(loop.m);
    if (!loop.connected0 && !loop.connected1 && !loop.error.empty()) {
      // Nothing to read; leave the error for the caller's logs.
    }
  }
  auto transceivers = pc0->transceivers();
  if (transceivers.size() > 0) {
    auto sender = transceivers[0]->sender();
    if (sender) {
      auto dtls = sender->dtls_transport();
      if (dtls) {
        auto info = dtls->GetInformation();
        if (info) {
          state = static_cast<int>(info->state());
          cipher = info->ssl_cipher_suite();
        }
      }
    }
  }

  // Unregister before the observers go out of scope, then close the peers.
  pc0->DeRegisterRTCPeerConnectionObserver();
  pc1->DeRegisterRTCPeerConnectionObserver();
  pc0->Close();
  pc1->Close();

  *out_dtls_state = state;
  return cipher;
}
