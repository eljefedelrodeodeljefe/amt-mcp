//! Log paging against record counts a device should never send.

use std::time::Duration;

use amt::{Client, Device, Endpoint};
use amt_fake::{FakeWsman, WsmanStep};

#[tokio::test]
async fn audit_log_survives_record_counts_that_overflow() {
    let page = format!(
        "<a:Body><g:ReadRecords_OUTPUT><g:TotalRecordCount>{max}</g:TotalRecordCount>\
<g:RecordsReturned>{max}</g:RecordsReturned><g:ReturnValue>0</g:ReturnValue>\
</g:ReadRecords_OUTPUT></a:Body>",
        max = u32::MAX
    );
    let fake = FakeWsman::start(vec![
        WsmanStep::Respond(page.clone()),
        WsmanStep::Respond(page),
    ])
    .await;
    let mut ep = Endpoint::new(fake.addr.ip().to_string(), "admin", "pw");
    ep.port = fake.addr.port();
    ep.timeout = Duration::from_secs(5);
    let d = Device::new(Client::new(ep).unwrap());
    let records = d.audit_log().await.expect("no panic, no error");
    assert!(records.is_empty());
    assert_eq!(fake.count().await, 1, "paging stops at the first page");
}
