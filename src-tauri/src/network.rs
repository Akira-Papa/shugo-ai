//! Bounded local observations; no DNS, GeoIP, blocking, direction inference or attack verdict.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom},
    net::IpAddr,
    path::Path,
    sync::atomic::AtomicBool,
};
const TAIL: u64 = 1024 * 1024;
const MAX_LINES: usize = 10_000;
const MAX_PEERS: usize = 256;
const MAX_CONNECTIONS: usize = 2048;
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpConnection {
    pub peer_ip: Option<String>,
    pub local_port: u16,
    pub remote_port: Option<u16>,
    pub state: String,
    pub listening: bool,
    pub direction: &'static str,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReport {
    pub status: &'static str,
    pub source: &'static str,
    pub detail: String,
    pub connections: Vec<TcpConnection>,
    pub malformed: usize,
    pub observed_at: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPeer {
    pub ip: String,
    pub requests: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessReport {
    pub status: &'static str,
    pub detail: String,
    pub peers: Vec<AccessPeer>,
    pub lines_counted: usize,
    pub malformed: usize,
    pub discarded_edges: usize,
    pub tail_limited: bool,
    pub observed_at: u64,
}
fn report(
    source: &'static str,
    mut connections: Vec<TcpConnection>,
    malformed: usize,
) -> NetworkReport {
    let limited = connections.len() > MAX_CONNECTIONS;
    if limited {
        connections.truncate(MAX_CONNECTIONS);
    }
    let mut r = NetworkReport {status:if malformed>0 || limited {"partial"}else{"observed"},source,detail:"取得時点の限定TCP観測です。接続方向は不明。空結果は侵入なしの証明ではありません。権限・OS・短命接続による欠測があります。".into(),connections,malformed,observed_at:crate::types::now_ms()};
    if limited {
        r.detail
            .push_str(" TCP表示上限2048件のため残りは省略しました。");
    }
    r
}
fn unavailable(source: &'static str) -> NetworkReport {
    NetworkReport{status:"unavailable",source,detail:"TCP一覧を取得できません。権限・対応コマンド・3秒/128 KiB出力上限を確認してください。部分出力は採用しません。".into(),connections:vec![],malformed:0,observed_at:crate::types::now_ms()}
}
pub fn collect_connections() -> NetworkReport {
    let cancel = AtomicBool::new(false);
    #[cfg(target_os = "macos")]
    {
        return match crate::collectors::network_command(
            "/usr/sbin/lsof",
            &["-nP", "-iTCP", "-FfnT"],
            &cancel,
        ) {
            Ok(s) => parse_lsof(&s),
            Err(_) => unavailable("lsof"),
        };
    }
    #[cfg(target_os = "linux")]
    {
        // Only known numeric read-only collectors; no caller supplied executable/arguments.
        for path in ["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss"] {
            if fs::symlink_metadata(path).is_ok() {
                return match crate::collectors::network_command(
                    path,
                    &["-H", "-n", "-t", "-a"],
                    &cancel,
                ) {
                    Ok(s) => parse_ss(&s),
                    Err(_) => unavailable("ss"),
                };
            }
        }
        return unavailable("ss");
    }
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").ok();
        let Some(program) = windows_powershell(root.as_deref()) else {
            return unavailable("Get-NetTCPConnection");
        };
        return match crate::collectors::network_command(&program, &["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; ConvertTo-Json -InputObject @(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name='State';Expression={$_.State.ToString()}}) -Compress"],&cancel) {Ok(s)=>parse_windows(&s),Err(_)=>unavailable("Get-NetTCPConnection")};
    }
    #[allow(unreachable_code)]
    unavailable("unsupported OS")
}
#[allow(dead_code)]
fn windows_powershell(root: Option<&str>) -> Option<String> {
    let root = root.unwrap_or("C:\\Windows").trim_end_matches(['\\', '/']);
    let bytes = root.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || root.chars().any(|c| c.is_control())
        || root[3..].split(['\\', '/']).any(|c| c == ".." || c == ".")
    {
        return None;
    }
    Some(format!(
        "{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ))
}
fn endpoint(s: &str) -> Option<(Option<String>, Option<u16>)> {
    let (ip, port) = s.rsplit_once(':')?;
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    let ip = if ip == "*" {
        None
    } else {
        Some(ip.parse::<IpAddr>().ok()?.to_string())
    };
    let port = if port == "*" {
        None
    } else {
        Some(port.parse::<u16>().ok()?)
    };
    Some((ip, port))
}
fn connection(name: &str, state: &str) -> Option<TcpConnection> {
    let (local, remote) = name
        .split_once("->")
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((name, None));
    let (_, local_port) = endpoint(local)?;
    let local_port = local_port?;
    let (peer_ip, remote_port) = match remote {
        Some(r) => endpoint(r)?,
        None => (None, None),
    };
    let state = state_name(state)?;
    let listening = state == "LISTEN";
    if !listening && remote.is_none() {
        return None;
    }
    Some(TcpConnection {
        peer_ip,
        local_port,
        remote_port,
        state: state.into(),
        listening,
        direction: "unknown",
    })
}
fn state_name(s: &str) -> Option<&'static str> {
    Some(match s {
        "ESTABLISHED" | "ESTAB" | "Established" => "ESTABLISHED",
        "LISTEN" | "Listen" => "LISTEN",
        "SYN-SENT" | "SYN_SENT" | "SynSent" => "SYN_SENT",
        "SYN-RECV" | "SYN_RECEIVED" | "SynReceived" => "SYN_RECEIVED",
        "FIN-WAIT-1" | "FIN_WAIT_1" | "FinWait1" => "FIN_WAIT_1",
        "FIN-WAIT-2" | "FIN_WAIT_2" | "FinWait2" => "FIN_WAIT_2",
        "TIME-WAIT" | "TIME_WAIT" | "TimeWait" => "TIME_WAIT",
        "CLOSE-WAIT" | "CLOSE_WAIT" | "CloseWait" => "CLOSE_WAIT",
        "LAST-ACK" | "LAST_ACK" | "LastAck" => "LAST_ACK",
        "CLOSING" | "Closing" => "CLOSING",
        "CLOSED" | "CLOSE" | "Closed" => "CLOSED",
        "BOUND" | "Bound" => "BOUND",
        _ => return None,
    })
}
#[allow(dead_code)]
fn parse_lsof(s: &str) -> NetworkReport {
    let mut out = vec![];
    let mut bad = 0;
    let mut name = None;
    let mut state = None;
    fn flush(
        name: &mut Option<String>,
        state: &mut Option<String>,
        out: &mut Vec<TcpConnection>,
        bad: &mut usize,
    ) {
        if let Some(n) = name.take() {
            match state.take().and_then(|s| connection(&n, &s)) {
                Some(c) => out.push(c),
                None => *bad += 1,
            }
        }
    }
    for line in s.lines() {
        if line.starts_with('p') || line.starts_with('f') {
            flush(&mut name, &mut state, &mut out, &mut bad);
        } else if let Some(n) = line.strip_prefix('n') {
            name = Some(n.to_owned());
        } else if let Some(st) = line.strip_prefix("TST=") {
            state = Some(st.to_owned());
        } else if !line.is_empty() && !line.starts_with('T') {
            bad += 1;
        }
    }
    flush(&mut name, &mut state, &mut out, &mut bad);
    report("lsof", out, bad)
}
#[allow(dead_code)]
fn parse_ss(s: &str) -> NetworkReport {
    let mut out = vec![];
    let mut bad = 0;
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let t: Vec<_> = line.split_whitespace().collect();
        let c = if t.len() == 5 {
            let state = state_name(t[0]);
            let local = endpoint(t[3]);
            let remote = endpoint(t[4]);
            match (state, local, remote) {
                (Some(st), Some((_, Some(lp))), Some((ip, rp))) => Some(TcpConnection {
                    peer_ip: if st == "LISTEN" { None } else { ip },
                    local_port: lp,
                    remote_port: if st == "LISTEN" { None } else { rp },
                    state: st.into(),
                    listening: st == "LISTEN",
                    direction: "unknown",
                }),
                _ => None,
            }
        } else {
            None
        };
        match c {
            Some(c) => out.push(c),
            None => bad += 1,
        }
    }
    report("ss", out, bad)
}
#[allow(dead_code)]
fn parse_windows(s: &str) -> NetworkReport {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return unavailable("Get-NetTCPConnection");
    };
    let rows: Vec<_> = match &v {
        serde_json::Value::Null => vec![],
        serde_json::Value::Array(a) => a.iter().collect(),
        serde_json::Value::Object(_) => vec![&v],
        _ => return unavailable("Get-NetTCPConnection"),
    };
    let mut out = vec![];
    let mut bad = 0;
    for v in rows {
        let c = (|| {
            let st = state_name(v["State"].as_str()?)?;
            v["LocalAddress"].as_str()?.parse::<IpAddr>().ok()?;
            let lp = u16::try_from(v["LocalPort"].as_u64()?).ok()?;
            let remote = v["RemoteAddress"].as_str()?.parse::<IpAddr>().ok()?;
            let rp = u16::try_from(v["RemotePort"].as_u64()?).ok()?;
            Some(TcpConnection {
                peer_ip: if st == "LISTEN" {
                    None
                } else {
                    Some(remote.to_string())
                },
                local_port: lp,
                remote_port: if st == "LISTEN" { None } else { Some(rp) },
                state: st.into(),
                listening: st == "LISTEN",
                direction: "unknown",
            })
        })();
        match c {
            Some(c) => out.push(c),
            None => bad += 1,
        }
    }
    report("Get-NetTCPConnection", out, bad)
}
pub fn access_log(path: &Path) -> Result<AccessReport, String> {
    access_log_checked(path, || {})
}
fn access_log_checked(path: &Path, after_read: impl FnOnce()) -> Result<AccessReport, String> {
    let m = fs::symlink_metadata(path).map_err(|_| "アクセスログを確認できません")?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err("通常ファイルのアクセスログだけ指定できます".into());
    }
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(0x00200000);
    }
    let mut f = o.open(path).map_err(|_| "アクセスログを安全に開けません")?;
    crate::storage_fs::verify_path_identity(&f, path)?;
    let before = f.metadata().map_err(|_| "ログ情報を確認できません")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.dev() != before.dev() || m.ino() != before.ino() {
            return Err("ログが置換されました".into());
        }
    }
    let start = before.len().saturating_sub(TAIL);
    f.seek(SeekFrom::Start(start))
        .map_err(|_| "ログ末尾を読めません")?;
    let mut bytes = vec![];
    (&f).take(before.len() - start)
        .read_to_end(&mut bytes)
        .map_err(|_| "ログを読めません")?;
    after_read();
    crate::storage_fs::verify_path_identity(&f, path)?;
    let after = f.metadata().map_err(|_| "ログ再確認に失敗しました")?;
    if bytes.len() as u64 != before.len() - start
        || after.len() < before.len()
        || before
            .modified()
            .map_err(|_| "ログ更新時刻を確認できません")?
            != after
                .modified()
                .map_err(|_| "ログ更新時刻を確認できません")?
            && after.len() == before.len()
    {
        return Err("読取中にログが変更されました。再確認してください".into());
    }
    Ok(parse_access(&bytes, start > 0, after.len() != before.len()))
}
fn quoted(s: &str) -> Option<&str> {
    let s = s.strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true
        } else if c == '"' {
            return Some(&s[i + 1..]);
        }
    }
    None
}
fn log_ip(line: &str) -> Option<IpAddr> {
    if line.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut fields = line.splitn(4, ' ');
    let ip = fields.next()?.parse().ok()?;
    if fields.next()?.is_empty() || fields.next()?.is_empty() {
        return None;
    }
    let date = fields.next()?.strip_prefix('[')?;
    let (stamp, rest) = date.split_once(']')?;
    if stamp.is_empty() {
        return None;
    }
    let rest = quoted(rest.trim_start())?.trim_start();
    let mut suffix = rest.splitn(3, ' ');
    let status = suffix.next()?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let size = suffix.next()?;
    if size != "-" && size.parse::<u64>().is_err() {
        return None;
    }
    let extra = suffix.next().unwrap_or("").trim();
    if !extra.is_empty() && !quoted(quoted(extra)?.trim_start())?.trim().is_empty() {
        return None;
    }
    Some(ip)
}
fn parse_access(bytes: &[u8], tail_limited: bool, changed: bool) -> AccessReport {
    let mut r=AccessReport{status:"observed",detail:"末尾最大1 MiB・10000行・256IPのcommon/combined形式でログ記載IPをrequest数集計。巡回ごとの末尾snapshotで増分ではありません。同じ行を次回も含むため巡回間の件数を加算しないでください。XFFは無視。実TCPの直接peerかはサーバー設定次第で未保証。国・攻撃・安全は判定しません。0件は無侵害の証明ではありません。".into(),peers:vec![],lines_counted:0,malformed:0,discarded_edges:0,tail_limited,observed_at:crate::types::now_ms()};
    if bytes.is_empty() {
        return r;
    }
    let mut lines = bytes.split(|b| *b == b'\n');
    if tail_limited {
        lines.next();
        r.discarded_edges += 1;
    }
    let mut peers = BTreeMap::<IpAddr, u64>::new();
    let mut visited = 0;
    let complete = bytes.ends_with(b"\n");
    let mut list = lines.peekable();
    while let Some(line) = list.next() {
        if !complete && list.peek().is_none() {
            r.discarded_edges += 1;
            break;
        }
        visited += 1;
        if visited > MAX_LINES {
            r.status = "partial";
            break;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let ip = std::str::from_utf8(line).ok().and_then(log_ip);
        match ip {
            Some(ip) => {
                if !peers.contains_key(&ip) && peers.len() >= MAX_PEERS {
                    r.malformed += 1;
                    continue;
                }
                *peers.entry(ip).or_default() += 1;
                r.lines_counted += 1
            }
            None => r.malformed += 1,
        }
    }
    r.peers = peers
        .into_iter()
        .map(|(ip, requests)| AccessPeer {
            ip: ip.to_string(),
            requests,
        })
        .collect();
    if tail_limited || changed || r.malformed > 0 || r.discarded_edges > 0 {
        r.status = "partial";
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    const COMMON: &str =
        "203.0.113.4 - - [08/Oct/2026:12:00:00 +0000] \"GET /?secret=hidden HTTP/1.1\" 200 12\n";
    #[test]
    fn os_parsers_ipv4_ipv6_listeners_and_unknown_direction() {
        let mac=parse_lsof("p12\nf1\nn127.0.0.1:443\nTST=LISTEN\nf2\nn[2001:db8::1]:50000->[2001:db8::2]:443\nTST=ESTABLISHED\n");
        assert_eq!(mac.connections.len(), 2);
        assert!(mac.connections[0].listening);
        assert_eq!(mac.connections[1].peer_ip.as_deref(), Some("2001:db8::2"));
        assert!(mac.connections.iter().all(|c| c.direction == "unknown"));
        let linux=parse_ss("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nESTAB 0 0 [2001:db8::1]:443 [2001:db8::2]:51000\ninvalid\n");
        assert_eq!(linux.status, "partial");
        assert_eq!(linux.connections.len(), 2);
        assert_eq!(linux.malformed, 1);
        assert!(linux.connections[0].peer_ip.is_none());
        let win = parse_windows(
            r#"[{"LocalAddress":"::","LocalPort":443,"RemoteAddress":"::","RemotePort":0,"State":"Listen"},{"LocalAddress":"192.0.2.1","LocalPort":50000,"RemoteAddress":"203.0.113.8","RemotePort":443,"State":"Established"}]"#,
        );
        assert_eq!(win.connections.len(), 2);
        assert_eq!(win.connections[1].remote_port, Some(443));
        assert_eq!(parse_ss("").status, "observed");
        assert!(parse_ss("").connections.is_empty());
        assert!(parse_ss("").detail.contains("侵入なしの証明ではありません"));
        assert_eq!(parse_windows("broken").status, "unavailable");
        assert_eq!(
            parse_lsof("p1\nf2\nn1.2.3.4:1->5.6.7.8:2\n").status,
            "partial"
        );
    }
    #[test]
    fn log_formats_private_fields_controls_partial_and_ipv6() {
        let combined="2001:db8::5 - user [08/Oct/2026:12:00:00 +0000] \"GET /private?q=token HTTP/1.1\" 200 - \"https://private.invalid\" \"UA-private XFF:1.2.3.4\"\n";
        let bytes =
            format!("{COMMON}{COMMON}{combined}garbage\n203.0.113.4 \u{1b}[31m unsafe\npartial");
        let r = parse_access(bytes.as_bytes(), false, false);
        assert_eq!(r.lines_counted, 3);
        assert_eq!(r.malformed, 2);
        assert_eq!(r.discarded_edges, 1);
        assert_eq!(r.status, "partial");
        assert!(r
            .peers
            .iter()
            .any(|p| p.ip == "203.0.113.4" && p.requests == 2));
        assert!(r.peers.iter().any(|p| p.ip == "2001:db8::5"));
        let json = serde_json::to_string(&r).unwrap();
        for secret in [
            "secret=hidden",
            "UA-private",
            "q=token",
            "private.invalid",
            "1.2.3.4",
        ] {
            assert!(!json.contains(secret));
        }
        assert_eq!(parse_access(b"\xffinvalid\n", false, false).malformed, 1);
        assert_eq!(
            parse_access(COMMON.replace("\n", "\r\n").as_bytes(), false, false).lines_counted,
            1
        );
        assert_eq!(parse_access(b"", false, false).status, "observed");
        let many = COMMON.repeat(MAX_LINES + 20);
        let r = parse_access(many.as_bytes(), false, false);
        assert_eq!(r.lines_counted, MAX_LINES);
        assert_eq!(r.status, "partial");
    }
    #[test]
    fn bounded_tail_and_rotation_use_only_fixtures() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("log");
        let mut f = fs::File::create(&p).unwrap();
        f.set_len(TAIL * 4).unwrap();
        use std::io::Write;
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(format!("\n{COMMON}").as_bytes()).unwrap();
        let r = access_log(&p).unwrap();
        assert!(r.tail_limited);
        assert_eq!(r.lines_counted, 1);
        assert_eq!(r.status, "partial");
        let replacement = d.path().join("next");
        fs::write(&replacement, COMMON).unwrap();
        #[cfg(unix)]
        assert!(access_log_checked(&p, || {
            fs::rename(&replacement, &p).unwrap();
        })
        .is_err());
        #[cfg(unix)]
        {
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&p, &link).unwrap();
            assert!(access_log(&link).is_err());
            let fifo = d.path().join("fifo");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(access_log(&fifo).is_err());
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    #[test]
    fn distinct_ip_and_blank_line_limits_are_partial() {
        let data = (0..300)
            .map(|i| {
                format!(
                    "2001:db8::{i:x} - - [08/Oct/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n"
                )
            })
            .collect::<String>();
        let r = parse_access(data.as_bytes(), false, false);
        assert_eq!(r.peers.len(), MAX_PEERS);
        assert_eq!(r.status, "partial");
        assert_eq!(r.lines_counted, MAX_PEERS);
        let blank = "\n".repeat(MAX_LINES + 2);
        assert_eq!(
            parse_access(blank.as_bytes(), false, false).status,
            "partial"
        );
    }
}

#[cfg(test)]
mod windows_path_tests {
    use super::*;
    #[test]
    fn systemroot_supports_nonstandard_drive_and_rejects_relative_escape() {
        assert!(windows_powershell(Some("D:\\WINNT"))
            .unwrap()
            .starts_with("D:\\WINNT\\System32"));
        assert!(windows_powershell(None).unwrap().starts_with("C:\\Windows"));
        for value in [
            "Windows",
            "C:Windows",
            "C:\\Windows\\..\\tmp",
            "\\\\server\\Windows",
            "C:\\Windows\n",
        ] {
            assert!(windows_powershell(Some(value)).is_none());
        }
    }
}
#[cfg(all(test, target_os = "macos"))]
mod live_loopback_tests {
    use super::*;
    #[test]
    #[ignore = "explicit local loopback acceptance; reports only aggregate pass/fail"]
    fn live_mac_observes_synthetic_loopback_only_in_assertions() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let general = collect_connections();
        assert_ne!(
            general.status, "unavailable",
            "general bounded collector unavailable (no private output)"
        );
        // A busy workstation may exceed the strict all-socket output cap. Do not
        // turn that into a successful partial listing; scope this acceptance to
        // the deliberately created socket, using the same collector and parser.
        let selection = format!("-iTCP:{local_port}");
        let raw = crate::collectors::network_command(
            "/usr/sbin/lsof",
            &["-nP", &selection, "-FfnT"],
            &AtomicBool::new(false),
        )
        .expect("synthetic collector failed (details hidden)");
        let report = parse_lsof(&raw);
        drop(raw);
        assert_ne!(
            report.status, "unavailable",
            "synthetic collector unavailable"
        );
        eprintln!(
            "aggregate-only: general_available={}; synthetic_collection_available=true",
            general.status != "unavailable"
        );
        assert!(
            report
                .connections
                .iter()
                .any(|c| c.local_port == local_port && c.listening),
            "synthetic listener missing"
        );
        assert!(
            report.connections.iter().any(|c| c.local_port == local_port
                && c.state == "ESTABLISHED"
                && c.peer_ip.as_deref() == Some("127.0.0.1")),
            "synthetic connection missing"
        );
        drop((client, server, listener));
    }
}

#[cfg(test)]
mod inventory_limit_tests {
    use super::*;
    #[test]
    fn tcp_cap_is_partial_and_empty_windows_array_is_observed() {
        let line = "ESTAB 0 0 192.0.2.1:50000 203.0.113.1:443\n";
        let report = parse_ss(&line.repeat(MAX_CONNECTIONS + 1));
        assert_eq!(report.connections.len(), MAX_CONNECTIONS);
        assert_eq!(report.status, "partial");
        assert!(report.detail.contains("2048"));
        let empty = parse_windows("[]");
        assert_eq!(empty.status, "observed");
        assert!(empty.connections.is_empty());
    }
}
