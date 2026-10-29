use super::*;
use serde_json::Value;

/// construct-protos `conformance/transport_route.json`: the cases iOS and Android pass.
fn vectors() -> Value {
    let path = format!(
        "{}/conformance/transport_route.json",
        env!("CONSTRUCT_PROTOS_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json")
}

struct Ctx {
    port: u16,
    relay: String,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} in {v}"))
}

fn target(ctx: &Ctx, via: &str) -> Target {
    match via {
        "direct" => Target::Direct,
        "veil" => Target::Veil {
            port: ctx.port,
            relay: ctx.relay.clone(),
        },
        other => panic!("via {other}"),
    }
}

fn mode(v: &str) -> Mode {
    match v {
        "off" => Mode::Off,
        "auto" => Mode::Auto,
        "on" => Mode::On,
        other => panic!("mode {other}"),
    }
}

fn lane(v: &Value) -> Lane {
    match v.as_str().unwrap_or("auth") {
        "auth" => Lane::Auth,
        "sealed" => Lane::Sealed,
        other => panic!("lane {other}"),
    }
}

fn rpc_failure(v: &str) -> RpcFailure {
    match v {
        "transient_cancellation" => RpcFailure::TransientCancellation,
        "auth_rejected" => RpcFailure::AuthRejected,
        "application_error" => RpcFailure::ApplicationError,
        "tls_fingerprint_blocked" => RpcFailure::TlsFingerprintBlocked,
        "tls_cert_expired" => RpcFailure::TlsCertExpired,
        "web_tunnel_blocked" => RpcFailure::WebTunnelBlocked,
        "stale_local_proxy" => RpcFailure::StaleLocalProxy,
        "stream_timeout" => RpcFailure::StreamTimeout,
        "transport_unknown" => RpcFailure::TransportUnknown,
        other => panic!("rpc failure {other}"),
    }
}

fn stream_failure(v: &str) -> StreamFailure {
    match v {
        "open_timeout" => StreamFailure::OpenTimeout,
        "mid_session_timeout" => StreamFailure::MidSessionTimeout,
        "write_failed" => StreamFailure::WriteFailed,
        "closed" => StreamFailure::Closed,
        "transport_unknown" => StreamFailure::TransportUnknown,
        "mid_session_closed" => StreamFailure::MidSessionClosed,
        "mid_session_unknown" => StreamFailure::MidSessionUnknown,
        other => panic!("stream failure {other}"),
    }
}

fn method(v: &str) -> StreamMethod {
    match v {
        "quic" => StreamMethod::Quic,
        "h2" => StreamMethod::H2,
        "veil" => StreamMethod::Veil,
        other => panic!("method {other}"),
    }
}

fn state(v: &Value) -> State {
    match s(v, "kind") {
        "offline" => State::Offline,
        "direct" => State::Direct {
            fails: v["fails"].as_u64().unwrap() as u32,
        },
        "veil_probing" => State::VeilProbing,
        "veil_active" => State::VeilActive {
            relay: s(v, "relay").to_owned(),
            port: v["port"].as_u64().unwrap() as u16,
            since_ms: v["since_ms"].as_i64().unwrap(),
            soft_fails: SoftFails {
                auth: v["soft_fails"]["auth"].as_u64().unwrap() as u32,
                sealed: v["soft_fails"]["sealed"].as_u64().unwrap() as u32,
            },
        },
        "veil_cooldown" => State::VeilCooldown {
            until_ms: v["until_ms"].as_i64().unwrap(),
        },
        other => panic!("state {other}"),
    }
}

fn event(ctx: &Ctx, v: &Value) -> Event {
    match s(v, "kind") {
        "rpc_succeeded" => Event::RpcSucceeded {
            via: target(ctx, s(v, "via")),
            latency_ms: v["latency_ms"].as_u64().unwrap() as u32,
            lane: lane(&v["lane"]),
        },
        "rpc_failed" => Event::RpcFailed {
            failure: rpc_failure(s(v, "failure")),
            via: target(ctx, s(v, "via")),
            foreground: v["foreground"].as_bool().unwrap(),
            lane: lane(&v["lane"]),
        },
        "stream_opened" => Event::StreamOpened {
            method: method(s(v, "method")),
            via: target(ctx, s(v, "via")),
        },
        "stream_failed" => Event::StreamFailed {
            method: method(s(v, "method")),
            failure: stream_failure(s(v, "failure")),
            via: target(ctx, s(v, "via")),
        },
        "network_path_changed" => Event::NetworkPathChanged {
            reachable: v["reachable"].as_bool().unwrap(),
            censored: v["censored"].as_bool().unwrap(),
        },
        "veil_mode_changed" => Event::VeilModeChanged {
            censored: v["censored"].as_bool().unwrap(),
        },
        "veil_config_changed" => Event::VeilConfigChanged,
        "background_wake" => Event::BackgroundWake,
        "proxy_started" => Event::ProxyStarted {
            relay: s(v, "relay").to_owned(),
            port: v["port"].as_u64().unwrap() as u16,
            restarted: v["restarted"].as_bool().unwrap(),
        },
        "proxy_start_failed" => Event::ProxyStartFailed {
            relay: v["relay"].as_str().map(str::to_owned),
            reason: s(v, "reason").to_owned(),
        },
        "cooldown_elapsed" => Event::CooldownElapsed,
        "manual_reset" => Event::ManualReset,
        other => panic!("event {other}"),
    }
}

fn effect(v: &Value) -> Effect {
    match s(v, "kind") {
        "invalidate_grpc_client" => Effect::InvalidateGrpcClient,
        "set_veil_port" => Effect::SetVeilPort(v["port"].as_u64().map(|p| p as u16)),
        "request_proxy_start" => Effect::RequestProxyStart,
        "request_proxy_stop" => Effect::RequestProxyStop,
        "demote_relay" => Effect::DemoteRelay(s(v, "relay").to_owned()),
        "schedule_cooldown_end" => Effect::ScheduleCooldownEnd(v["at_ms"].as_i64().unwrap()),
        other => panic!("effect {other}"),
    }
}

fn config(defaults: &Value, over: &Value) -> Config {
    let get = |k: &str| over.get(k).unwrap_or(&defaults[k]).clone();
    Config {
        direct_fail_threshold: get("direct_fail_threshold").as_u64().unwrap() as u32,
        mid_session_death_weight: get("mid_session_death_weight").as_u64().unwrap() as u32,
        allow_direct_to_veil_escalation: get("allow_direct_to_veil_escalation").as_bool().unwrap(),
        veil_cooldown_ms: get("veil_cooldown_ms").as_i64().unwrap(),
        veil_soft_fail_threshold: get("veil_soft_fail_threshold").as_u64().unwrap() as u32,
    }
}

/// Every shared case, as iOS and Android run them: the starting state, or the final state and
/// the effects of the last event, in order.
#[test]
fn the_route_follows_the_shared_vectors() {
    let v = vectors();
    let now = v["now_ms"].as_i64().unwrap();
    let ctx = Ctx {
        port: v["veil_target"]["port"].as_u64().unwrap() as u16,
        relay: s(&v["veil_target"], "relay").to_owned(),
    };
    let defaults = &v["default_config"];
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 50, "the vector file has its cases");
    let mut failed = Vec::new();
    for case in cases {
        let name = s(case, "name");
        if let Some(init) = case.get("initial") {
            let got = initial(
                mode(s(init, "mode")),
                init["censored"].as_bool().unwrap(),
                init["reachable"].as_bool().unwrap(),
            );
            if got != state(&case["expect_state"]) {
                failed.push(format!("{name}: {got:?}"));
            }
            continue;
        }
        let cfg = config(defaults, case.get("config").unwrap_or(&Value::Null));
        let m = mode(s(case, "mode"));
        let mut current = state(&case["state"]);
        let mut effects = Vec::new();
        for e in case["events"].as_array().unwrap() {
            let out = reduce(&current, &event(&ctx, e), m, cfg, now);
            current = out.state;
            effects = out.effects;
        }
        if current != state(&case["expect_state"]) {
            failed.push(format!("{name}: state {current:?}"));
        }
        if let Some(expected) = case.get("expect_effects") {
            let expected: Vec<Effect> = expected.as_array().unwrap().iter().map(effect).collect();
            if effects != expected {
                failed.push(format!("{name}: effects {effects:?}, want {expected:?}"));
            }
        }
    }
    assert!(
        failed.is_empty(),
        "{} cases:\n{}",
        failed.len(),
        failed.join("\n")
    );
}
