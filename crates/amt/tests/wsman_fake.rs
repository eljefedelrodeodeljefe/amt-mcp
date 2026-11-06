//! WS-Man against a fake HTTP endpoint that executes a request and then drops
//! the connection without answering.

use std::time::Duration;

use amt::wsman::CIM;
use amt::{Client, Endpoint};
use amt_fake::{FakeWsman, WsmanStep};

fn client(fake: &FakeWsman) -> Client {
    client_with_timeout(fake, Duration::from_secs(5))
}

fn client_with_timeout(fake: &FakeWsman, timeout: Duration) -> Client {
    let mut ep = Endpoint::new(fake.addr.ip().to_string(), "admin", "pw");
    ep.port = fake.addr.port();
    ep.timeout = timeout;
    Client::new(ep).expect("client")
}

#[tokio::test]
async fn mutating_call_is_not_resent_after_a_dropped_connection() {
    let fake = FakeWsman::start(vec![WsmanStep::Drop]).await;
    let c = client(&fake);
    let res = c
        .invoke(
            &format!("{CIM}CIM_PowerManagementService"),
            "RequestPowerStateChange",
            "",
            "<p:PowerState>10</p:PowerState>",
        )
        .await;
    assert_eq!(fake.count().await, 1, "the power request was sent twice");
    assert!(res.is_err(), "a dropped connection is an error");
}

#[tokio::test]
async fn read_is_retried_once_after_a_dropped_connection() {
    let fake = FakeWsman::start(vec![
        WsmanStep::Drop,
        WsmanStep::Respond("<a:Body><g:X><g:A>1</g:A></g:X></a:Body>".into()),
    ])
    .await;
    let c = client(&fake);
    let xml = c.get(&format!("{CIM}CIM_Chassis")).await.expect("retried");
    assert_eq!(amt::wsman::field(&xml, "A").as_deref(), Some("1"));
    assert_eq!(fake.count().await, 2);
}

#[tokio::test]
async fn mutating_call_is_not_resent_after_a_timeout() {
    let fake = FakeWsman::start(vec![WsmanStep::Hang]).await;
    let c = client_with_timeout(&fake, Duration::from_millis(300));
    let res = c
        .call(
            &format!("{CIM}CIM_PowerManagementService"),
            "RequestPowerStateChange",
            &[],
            "<p:PowerState>10</p:PowerState>",
        )
        .await;
    assert_eq!(fake.count().await, 1, "the power request was sent twice");
    assert!(res.is_err(), "a timeout is an error");
}
