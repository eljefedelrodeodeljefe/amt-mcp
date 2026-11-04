use std::time::Duration;

use amt::{Endpoint, IderSession, IderStart};
use amt_fake::FakeRedirection;

#[tokio::test]
async fn ider_serves_capacity_and_blocks() {
    // A 4-block "CD": block n is filled with byte n.
    let dir = std::env::temp_dir().join(format!("amt-ider-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let iso = dir.join("test.iso");
    let mut image = Vec::new();
    for b in 0u8..4 {
        image.extend(std::iter::repeat_n(b, 2048));
    }
    std::fs::write(&iso, &image).unwrap();

    let fake = FakeRedirection::start_ider("admin", "S3cret!pw").await;
    let ep = Endpoint::new(fake.addr.ip().to_string(), "admin", "S3cret!pw");
    let session = IderSession::open(
        &ep,
        fake.addr.port(),
        &iso,
        IderStart::OnReboot,
        Duration::from_secs(5),
    )
    .await
    .expect("IDE-R opens");

    let mut seen = fake.seen.lock().await.clone();
    for _ in 0..50 {
        if !seen.ider_read.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        seen = fake.seen.lock().await.clone();
    }
    assert_eq!(seen.kind, b"IDER");
    assert!(seen.authenticated);
    assert_eq!(seen.ider_toggle, Some(0x01 + 0x08));
    assert_eq!(seen.ider_capacity, Some((3, 2048)));
    assert_eq!(seen.ider_read, image[2048..3 * 2048]);

    let st = session.status().await;
    assert_eq!(st.blocks_read, 2);
    assert_eq!(st.commands, 2);
    session.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn ider_rejects_non_cd_image() {
    let dir = std::env::temp_dir().join(format!("amt-ider-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let iso = dir.join("bad.iso");
    std::fs::write(&iso, [0u8; 1000]).unwrap();
    let ep = Endpoint::new("127.0.0.1", "admin", "x");
    let err = IderSession::open(&ep, 9, &iso, IderStart::Now, Duration::from_secs(1))
        .await
        .err()
        .expect("refused before connecting");
    assert!(err.to_string().contains("2048"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}
