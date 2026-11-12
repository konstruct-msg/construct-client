//! Real HTTP/2 directory reads through the production actor and RPC decoder.
use super::*;
use crate::grpc::{framing, route};
use crate::proto::services::v1::{GetPreKeyBundlesRequest, GetPreKeyBundlesResponse};
use bytes::{Bytes, BytesMut};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
struct Reply {
    status: &'static str,
    active: Vec<String>,
}

struct Fixture {
    task: Task,
    requests: Arc<Mutex<Vec<GetPreKeyBundlesRequest>>>,
    server: tokio::task::JoinHandle<()>,
    _route: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn new(replies: Vec<Reply>) -> Self {
        let guard = route::TEST_LOCK.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn({
            let requests = requests.clone();
            async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (requests, replies) = (requests.clone(), replies.clone());
                    tokio::spawn(async move {
                        let mut connection = h2::server::handshake(tcp).await.unwrap();
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            let (requests, replies) = (requests.clone(), replies.clone());
                            tokio::spawn(async move {
                                assert!(request.uri().path().ends_with("/GetPreKeyBundles"));
                                let mut body = request.into_body();
                                let mut raw = BytesMut::new();
                                while let Some(chunk) = body.data().await {
                                    let chunk = chunk.unwrap();
                                    raw.extend_from_slice(&chunk);
                                    body.flow_control().release_capacity(chunk.len()).unwrap();
                                }
                                let (decoded, remainder) =
                                    framing::decode_frame(raw.freeze()).unwrap();
                                assert!(remainder.is_empty());
                                let request = GetPreKeyBundlesRequest::decode(decoded).unwrap();
                                let reply = {
                                    let mut seen = requests.lock().unwrap();
                                    let reply = replies[seen.len().min(replies.len() - 1)].clone();
                                    seen.push(request);
                                    reply
                                };
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                let mut stream = respond.send_response(response, false).unwrap();
                                if reply.status == "0" {
                                    let response = GetPreKeyBundlesResponse {
                                        active_devices: reply.active,
                                        ..Default::default()
                                    };
                                    stream
                                        .send_data(
                                            framing::encode_frame(&response.encode_to_vec()),
                                            false,
                                        )
                                        .unwrap();
                                } else {
                                    stream.send_data(Bytes::new(), false).unwrap();
                                }
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", reply.status.parse().unwrap());
                                stream.send_trailers(trailers).unwrap();
                            });
                        }
                    });
                }
            }
        });
        route::set_route(route::Route::Veil { port });
        let (mut task, _) = tests::test_task_sending();
        task.grpc = GrpcClient::new("https://directory.example:443");
        Self {
            task,
            requests,
            server,
            _route: guard,
        }
    }

    async fn refresh(&mut self, account: &str) -> Result<Vec<(String, OpenRefusal)>, String> {
        tokio::time::timeout(Duration::from_secs(5), self.task.refresh_devices(account))
            .await
            .expect("directory RPC must finish")
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn own(&self) -> String {
        self.task.identity.user_id.clone()
    }
    fn self_only() -> Reply {
        Reply {
            status: "0",
            active: vec!["device-a".into()],
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        route::set_route(route::Route::Direct);
    }
}

#[tokio::test]
async fn known_empty_own_siblings_do_not_spend_one_bundle_read_per_send() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    for _ in 0..20 {
        assert!(f.refresh(&own).await.unwrap().is_empty());
    }
    assert_eq!(
        f.count(),
        1,
        "single-device snapshot was already successful"
    );
    assert!(
        f.task.peers.devices_of(&own).is_empty(),
        "self is not a peer"
    );
    let seen = f.requests.lock().unwrap();
    assert_eq!(seen[0].user_id, own);
    assert!(seen[0].device_ids.is_empty());
    assert_eq!(seen[0].consume_one_time_prekey, Some(false));
}

#[tokio::test]
async fn failed_directory_read_is_not_a_successful_snapshot() {
    let mut f = Fixture::new(vec![
        Reply {
            status: "8",
            active: Vec::new(),
        },
        Fixture::self_only(),
    ])
    .await;
    let own = f.own();
    assert!(f.refresh(&own).await.is_err());
    assert!(
        !f.task.devices_checked.contains_key(&own),
        "failure must not mark a directory checked"
    );
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(f.count(), 2, "retry the failure, then reuse success");
}

#[tokio::test]
async fn own_directory_expiry_still_rechecks_the_server() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    f.refresh(&own).await.unwrap();
    f.task
        .devices_checked
        .insert(own.clone(), tokio::time::Instant::now() - DEVICES_RECHECK);
    f.refresh(&own).await.unwrap();
    assert_eq!(
        f.count(),
        2,
        "the existing freshness boundary still applies"
    );
}

#[tokio::test]
async fn empty_remote_directory_is_still_retried() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    for _ in 0..2 {
        f.refresh("remote-account").await.unwrap();
    }
    assert_eq!(
        f.count(),
        2,
        "this fix must not cache empty remote accounts"
    );
}

#[tokio::test]
async fn a_missing_session_still_forces_a_read_even_with_a_fresh_stamp() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    f.refresh(&own).await.unwrap();
    let key = [9; 32];
    let device = construct_core::device_id::derive_device_id(&key);
    assert!(f.task.peers.record(&f.task.storage, &own, &device, &key));
    f.refresh(&own).await.unwrap();
    assert_eq!(
        f.count(),
        2,
        "freshness must not hide a missing sibling session"
    );
}

#[tokio::test]
async fn link_completion_invalidates_empty_snapshot_and_waits_for_sibling_keys() {
    let mut f = Fixture::new(vec![
        Fixture::self_only(),
        Reply {
            status: "0",
            active: vec!["device-a".into(), "new-sibling".into()],
        },
    ])
    .await;
    let own = f.own();
    f.refresh(&own).await.unwrap();
    f.task
        .handle_command(OrchestratorCommand::OwnDevicesChanging)
        .await;
    f.task
        .handle_command(OrchestratorCommand::OwnDevicesChanged)
        .await;
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(
        f.count(),
        3,
        "a link and unpublished sibling must not sleep for ten minutes"
    );
}

#[tokio::test]
async fn canceled_or_uncertain_links_do_not_hide_a_sibling_or_cache_inflight_reads() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    f.refresh(&own).await.unwrap();
    let (cmd_tx, mut commands) = mpsc::unbounded_channel();
    let (tx, _) = mpsc::unbounded_channel();
    let handle = OrchestratorHandle { tx, cmd_tx };
    let change = handle.changing_own_devices();
    f.task
        .handle_command(commands.try_recv().expect("start notification"))
        .await;
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(
        f.count(),
        3,
        "do not cache empty reads while a link may commit"
    );
    let operation = tokio::spawn(async move {
        let _change = change;
        std::future::pending::<()>().await;
    });
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    f.task
        .handle_command(commands.try_recv().expect("drop notification"))
        .await;
    assert_eq!(f.task.own_device_changes, 0);
    assert!(
        !f.task.devices_checked.contains_key(&own),
        "inflight result invalidated on completion"
    );
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(
        f.count(),
        4,
        "retry after uncertain completion, then reuse a new success"
    );
}

#[tokio::test]
async fn concurrent_link_guards_do_not_clear_each_others_inflight_state() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    let (cmd_tx, mut commands) = mpsc::unbounded_channel();
    let (tx, _) = mpsc::unbounded_channel();
    let handle = OrchestratorHandle { tx, cmd_tx };
    let first = handle.changing_own_devices();
    let second = handle.changing_own_devices();
    for _ in 0..2 {
        f.task.handle_command(commands.try_recv().unwrap()).await;
    }
    drop(first);
    f.task.handle_command(commands.try_recv().unwrap()).await;
    assert_eq!(f.task.own_device_changes, 1);
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(f.count(), 2);
    drop(second);
    f.task.handle_command(commands.try_recv().unwrap()).await;
    f.refresh(&own).await.unwrap();
    f.refresh(&own).await.unwrap();
    assert_eq!(f.count(), 3);
}

#[tokio::test]
async fn link_vouch_invalidates_a_previous_self_only_snapshot() {
    let mut f = Fixture::new(vec![Fixture::self_only()]).await;
    let own = f.own();
    f.refresh(&own).await.unwrap();
    f.task
        .handle_command(OrchestratorCommand::Vouch {
            device_id: "new-sibling".into(),
            evidence: crate::device_certs::Evidence::QrFingerprint(vec![1; 32]),
        })
        .await;
    assert!(!f.task.devices_checked.contains_key(&own));
    f.refresh(&own).await.unwrap();
    assert_eq!(f.count(), 2);
}

#[test]
fn only_fresh_successful_snapshots_without_missing_sessions_are_reused() {
    let now = tokio::time::Instant::now();
    for own in [false, true] {
        for has_devices in [false, true] {
            for missing in [false, true] {
                for age in [None, Some(Duration::ZERO), Some(DEVICES_RECHECK)] {
                    let checked = age.map(|age| now - age);
                    let expected = (own || has_devices) && !missing && age == Some(Duration::ZERO);
                    assert_eq!(
                        reuse_device_directory(own, has_devices, missing, checked, now),
                        expected
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn empty_or_unpublished_sibling_directory_is_not_cached_as_self_only() {
    for active in [Vec::new(), vec!["device-a".into(), "new-sibling".into()]] {
        let mut f = Fixture::new(vec![Reply {
            status: "0",
            active,
        }])
        .await;
        let own = f.own();
        f.refresh(&own).await.unwrap();
        f.refresh(&own).await.unwrap();
        assert_eq!(
            f.count(),
            2,
            "unknown or keyless sibling is not a confirmed empty set"
        );
    }
}
