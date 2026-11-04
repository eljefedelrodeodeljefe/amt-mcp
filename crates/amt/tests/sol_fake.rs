use std::time::Duration;

use amt::{Endpoint, Error, SolSession};
use amt_fake::FakeRedirection;

fn endpoint(fake: &FakeRedirection, password: &str) -> Endpoint {
    Endpoint::new(fake.addr.ip().to_string(), "admin", password)
}

#[tokio::test]
async fn digest_handshake_and_echo() {
    let fake = FakeRedirection::start("admin", "S3cret!pw", "login: ").await;
    let sol = SolSession::open(
        &endpoint(&fake, "S3cret!pw"),
        fake.addr.port(),
        Duration::from_secs(5),
    )
    .await
    .expect("session opens");

    let banner = sol
        .read(Duration::from_secs(2), Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(banner, b"login: ");

    sol.send(b"root\r").await.unwrap();
    let echo = sol
        .read(Duration::from_secs(2), Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(echo, b"echo:root\r");

    let seen = fake.seen.lock().await.clone();
    assert!(seen.authenticated);
    assert!(seen.settings_received);
    assert_eq!(seen.typed, b"root\r");
    sol.close().await;
}

#[tokio::test]
async fn wrong_password_is_an_auth_error() {
    let fake = FakeRedirection::start("admin", "S3cret!pw", "").await;
    let err = SolSession::open(
        &endpoint(&fake, "wrong"),
        fake.addr.port(),
        Duration::from_secs(5),
    )
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, Error::RedirectionAuth(2)), "{err}");
}

#[tokio::test]
async fn read_times_out_empty_when_idle() {
    let fake = FakeRedirection::start("admin", "pw", "").await;
    let sol = SolSession::open(
        &endpoint(&fake, "pw"),
        fake.addr.port(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    // The banner is empty, so nothing arrives.
    let got = sol
        .read(Duration::from_millis(200), Duration::from_millis(20))
        .await
        .unwrap();
    assert!(got.is_empty() || got == b"");
}
