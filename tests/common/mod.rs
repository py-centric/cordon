//! Shared helpers for Cordon integration test suites.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use cordon::api::{ControlPlaneOptions, CordonControlPlane, build_router_with_options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn spawn_server(options: ControlPlaneOptions) -> SocketAddr {
    let router = build_router_with_options(CordonControlPlane::default(), options);
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => panic!("Failed to bind ephemeral port: {e}"),
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => panic!("Failed to read local_addr: {e}"),
    };
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    addr
}

pub async fn send_raw(addr: SocketAddr, request: &str) -> String {
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => panic!("Failed to connect to test server: {e}"),
    };
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

pub fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

pub fn header_of<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.split_once("\r\n\r\n").and_then(|(head, _)| {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    })
}

pub fn get_request(path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}Connection: close\r\n\r\n")
}

pub fn post_json_request(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

pub fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cordon-hardening-{tag}-{}", std::process::id()));
    assert!(
        std::fs::create_dir_all(&dir).is_ok(),
        "failed to create temp dir {}",
        dir.display()
    );
    dir
}

pub fn argv_triples(argv: &[String]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx + 2 < argv.len() {
        out.push((
            argv[idx].clone(),
            argv[idx + 1].clone(),
            argv[idx + 2].clone(),
        ));
        idx += 3;
    }
    out
}
