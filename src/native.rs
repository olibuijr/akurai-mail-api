use base64::Engine;
use mailparse::{MailHeaderMap, ParsedMail};
use rand::distr::{Alphanumeric, SampleString};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha1::{Digest as Sha1Digest, Sha1};
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type NativeResult<T> = Result<T, String>;

const STATE: &str = "/var/lib/akurai-mail/state.json";
const WEBMAIL_STATE: &str = "/var/lib/akurai-mail/webmail.json";
const DOVECOT_USERS: &str = "/etc/dovecot/users";
const POSTFIX_VMAILBOX: &str = "/etc/postfix/vmailbox";
const POSTFIX_VIRTUAL: &str = "/etc/postfix/virtual";
const DOMAINS_STATE: &str = "/var/lib/akurai-mail/domains.json";
const OPENDKIM_KEYTABLE: &str = "/etc/opendkim/KeyTable";
const OPENDKIM_SIGNINGTABLE: &str = "/etc/opendkim/SigningTable";
const OPENDKIM_TRUSTEDHOSTS: &str = "/etc/opendkim/TrustedHosts";
const OPENDKIM_KEYS_DIR: &str = "/etc/opendkim/keys";
const DOMAIN: &str = "olibuijr.com";
const HOSTNAME: &str = "mail.olibuijr.com";
const PUBLIC_IP: &str = "3.94.46.219";
const MAX_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;

static STATUS_CACHE: LazyLock<Mutex<Option<(Instant, Value)>>> = LazyLock::new(|| Mutex::new(None));
static DNS_CACHE: LazyLock<Mutex<Option<(Instant, Value)>>> = LazyLock::new(|| Mutex::new(None));
static DOMAIN_LIST_CACHE: LazyLock<Mutex<Option<(Instant, Value)>>> =
    LazyLock::new(|| Mutex::new(None));

fn cached(
    slot: &LazyLock<Mutex<Option<(Instant, Value)>>>,
    ttl: Duration,
    build: impl FnOnce() -> NativeResult<Value>,
) -> NativeResult<Value> {
    if let Some((at, value)) = slot.lock().unwrap().as_ref() {
        if at.elapsed() < ttl {
            return Ok(value.clone());
        }
    }
    let value = build()?;
    *slot.lock().unwrap() = Some((Instant::now(), value.clone()));
    Ok(value)
}

fn clear_read_caches() {
    *STATUS_CACHE.lock().unwrap() = None;
    *DNS_CACHE.lock().unwrap() = None;
    *DOMAIN_LIST_CACHE.lock().unwrap() = None;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn state_default() -> Value {
    json!({
        "domain": DOMAIN,
        "hostname": HOSTNAME,
        "publicIp": PUBLIC_IP,
        "users": [],
        "aliases": [],
        "events": [],
        "metricsHistory": [],
        "spamPolicy": spam_policy_default(),
    })
}

fn webmail_default() -> Value {
    json!({
        "contacts": [],
        "signatures": {},
        "vacation": {},
        "vacationSent": {},
        "rules": [],
        "preferences": { "density": "comfortable", "theme": "light" },
        "audit": [],
    })
}

fn spam_policy_default() -> Value {
    json!({
        "enabled": true,
        "autoMove": true,
        "threshold": 5,
        "blocklist": [],
        "allowlist": [],
        "domainBlocklist": [],
        "subjectKeywords": ["crypto", "lottery", "winner", "urgent payment", "gift card", "wire transfer"],
        "attachmentExtensions": ["exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar"],
        "maxLinks": 10,
        "stats": { "scanned": 0, "moved": 0, "lastScan": 0 },
    })
}

fn merge_defaults(value: &mut Value, defaults: &Value) {
    let (Some(obj), Some(def)) = (value.as_object_mut(), defaults.as_object()) else {
        return;
    };
    for (key, default_value) in def {
        match obj.get_mut(key) {
            Some(existing) if existing.is_object() && default_value.is_object() => {
                merge_defaults(existing, default_value);
            }
            Some(_) => {}
            None => {
                obj.insert(key.clone(), default_value.clone());
            }
        }
    }
}

fn load_json(path: &str, default: Value) -> NativeResult<Value> {
    let p = Path::new(path);
    if !p.exists() {
        save_json(path, &default)?;
        return Ok(default);
    }
    let text = fs::read_to_string(p).map_err(|e| format!("read {path}: {e}"))?;
    let mut value: Value = serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    merge_defaults(&mut value, &default);
    Ok(value)
}

fn save_json(path: &str, value: &Value) -> NativeResult<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let tmp = p.with_extension("tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, p).map_err(|e| format!("replace {path}: {e}"))?;
    Ok(())
}

fn command_output(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn command_status(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn command_checked(cmd: &str, args: &[&str]) -> NativeResult<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd} failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{cmd} failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn object_mut(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = json!({});
    }
    value.as_object_mut().unwrap()
}

fn prepend_event(data: &mut Value, key: &str, text: String, keep: usize) {
    let obj = object_mut(data);
    let mut rows = obj
        .remove(key)
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    rows.insert(0, json!({ "at": now(), "text": text }));
    rows.truncate(keep);
    obj.insert(key.to_string(), Value::Array(rows));
}

fn services() -> Value {
    let mut out = Map::new();
    for name in [
        "postfix",
        "dovecot",
        "opendkim",
        "nginx",
        "akurai-mail-ui",
        "fail2ban",
    ] {
        let status = command_output("systemctl", &["is-active", name]);
        out.insert(name.to_string(), json!(status.trim().to_string()));
    }
    Value::Object(out)
}

fn mem_info() -> Value {
    let text = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 1_u64;
    let mut available = 0_u64;
    for line in text.lines() {
        if let Some(raw) = line.strip_prefix("MemTotal:") {
            total = raw
                .split_whitespace()
                .next()
                .unwrap_or("1")
                .parse()
                .unwrap_or(1);
        }
        if let Some(raw) = line.strip_prefix("MemAvailable:") {
            available = raw
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
        }
    }
    let used = total.saturating_sub(available);
    json!({
        "totalMb": (total as f64 / 1024.0).round() as u64,
        "usedMb": (used as f64 / 1024.0).round() as u64,
        "percent": (((used as f64 / total as f64) * 1000.0).round() / 10.0),
    })
}

fn cpu_times() -> (u64, u64) {
    let text = fs::read_to_string("/proc/stat").unwrap_or_default();
    let nums: Vec<u64> = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    let total = nums.iter().sum();
    let idle = nums.get(3).copied().unwrap_or(0) + nums.get(4).copied().unwrap_or(0);
    (total, idle)
}

fn cpu_percent(data: &mut Value) -> f64 {
    let (total, idle) = cpu_times();
    let prev_total = data
        .pointer("/lastCpu/total")
        .and_then(Value::as_u64)
        .unwrap_or(total);
    let prev_idle = data
        .pointer("/lastCpu/idle")
        .and_then(Value::as_u64)
        .unwrap_or(idle);
    object_mut(data).insert(
        "lastCpu".to_string(),
        json!({ "total": total, "idle": idle }),
    );
    let diff_total = total.saturating_sub(prev_total).max(1);
    let diff_idle = idle.saturating_sub(prev_idle);
    (((1.0 - (diff_idle as f64 / diff_total as f64)).clamp(0.0, 1.0) * 1000.0).round()) / 10.0
}

fn disk_info() -> Value {
    let text = command_output("df", &["-P", "-B1", "/"]);
    let parts: Vec<&str> = text
        .lines()
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let total: f64 = parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(1.0);
    let used: f64 = parts.get(2).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    json!({
        "totalGb": ((total / 1024.0 / 1024.0 / 1024.0) * 10.0).round() / 10.0,
        "usedGb": ((used / 1024.0 / 1024.0 / 1024.0) * 10.0).round() / 10.0,
        "percent": (((used / total) * 1000.0).round() / 10.0),
    })
}

fn vm_metrics(data: &mut Value) -> Value {
    let metrics = json!({
        "at": now(),
        "cpu": cpu_percent(data),
        "memory": mem_info(),
        "disk": disk_info(),
    });
    let mut history = data
        .get("metricsHistory")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(json!({
        "at": metrics["at"],
        "cpu": metrics["cpu"],
        "memory": metrics["memory"]["percent"],
        "disk": metrics["disk"]["percent"],
    }));
    if history.len() > 48 {
        history = history.split_off(history.len() - 48);
    }
    object_mut(data).insert("metricsHistory".to_string(), Value::Array(history));
    metrics
}

#[derive(Clone)]
struct MailUser {
    email: String,
    home: PathBuf,
}

fn mailbox_size(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    total
}

fn mailbox_last_delivery(home: &Path) -> u64 {
    let new_dir = home.join("Maildir/new");
    let Ok(entries) = fs::read_dir(new_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| {
            e.metadata()
                .ok()?
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
        })
        .map(|d| d.as_secs())
        .max()
        .unwrap_or(0)
}

fn dovecot_users() -> Vec<Value> {
    dovecot_user_rows()
        .into_iter()
        .map(|user| {
            let size = mailbox_size(&user.home);
            json!({
                "email": user.email,
                "createdAt": 0,
                "status": "active",
                "home": user.home,
                "hasPassword": true,
                "quotaUsed": size,
                "quotaUsedMb": ((size as f64 / 1024.0 / 1024.0) * 100.0).round() / 100.0,
                "lastDelivery": mailbox_last_delivery(&user.home),
            })
        })
        .collect()
}

fn dovecot_user_rows() -> Vec<MailUser> {
    let text = fs::read_to_string(DOVECOT_USERS).unwrap_or_default();
    let mut users = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || !line.contains(':') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        let email = parts.first().unwrap_or(&"").trim();
        if !email.contains('@') {
            continue;
        }
        let home = parts.get(5).copied().unwrap_or("").trim();
        if home.is_empty() {
            continue;
        }
        users.push(MailUser {
            email: email.to_string(),
            home: PathBuf::from(home),
        });
    }
    users.sort_by(|a, b| a.email.cmp(&b.email));
    users
}

fn user_home(address: &str) -> NativeResult<PathBuf> {
    dovecot_user_rows()
        .into_iter()
        .find(|u| u.email == address)
        .map(|u| u.home)
        .ok_or_else(|| "mailbox not found".to_string())
}

fn aliases() -> Value {
    let text = fs::read_to_string(POSTFIX_VIRTUAL).unwrap_or_default();
    let mut rows: Vec<Value> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (alias, target) = line.split_once(char::is_whitespace)?;
            Some(json!({
                "alias": alias,
                "target": target.trim(),
                "createdAt": 0,
                "status": "active",
            }))
        })
        .collect();
    rows.sort_by(|a, b| a["alias"].as_str().cmp(&b["alias"].as_str()));
    Value::Array(rows)
}

fn mail_queue() -> Value {
    let text = command_output("mailq", &[]);
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains("Mail queue is empty") {
        return json!({ "count": 0, "summary": "Mail queue is empty" });
    }
    let count = trimmed
        .lines()
        .filter(|line| line.chars().next().is_some_and(|c| c.is_ascii_hexdigit()))
        .count();
    json!({
        "count": count,
        "summary": trimmed.lines().last().unwrap_or("Queue has messages"),
    })
}

fn delivery_errors() -> Value {
    let text = command_output(
        "journalctl",
        &[
            "-u",
            "postfix",
            "--since",
            "24 hours ago",
            "--no-pager",
            "-n",
            "80",
        ],
    );
    let re = Regex::new("(?i)\\b(reject|warning|error|fatal|bounced)\\b").unwrap();
    let mut rows: Vec<Value> = text
        .lines()
        .filter(|line| re.is_match(line))
        .map(|line| {
            let start = line.len().saturating_sub(240);
            json!(line[start..].to_string())
        })
        .collect();
    if rows.len() > 12 {
        rows = rows.split_off(rows.len() - 12);
    }
    Value::Array(rows)
}

fn top_processes() -> Value {
    let text = command_output("ps", &["aux", "--sort=-pcpu"]);
    let rows: Vec<Value> = text
        .lines()
        .skip(1)
        .take(15)
        .filter_map(|line| {
            let parts: Vec<&str> = line
                .splitn(11, char::is_whitespace)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.len() < 11 {
                return None;
            }
            Some(json!({
                "pid": parts[1].parse::<u32>().unwrap_or(0),
                "user": parts[0],
                "cpu": parts[2].parse::<f64>().unwrap_or(0.0),
                "mem": parts[3].parse::<f64>().unwrap_or(0.0),
                "vsz": parts[4].parse::<u64>().unwrap_or(0),
                "rss": parts[5].parse::<u64>().unwrap_or(0),
                "command": parts[10].chars().take(120).collect::<String>(),
            }))
        })
        .collect();
    Value::Array(rows)
}

fn read_name(data: &[u8], pos: &mut usize) -> NativeResult<String> {
    let mut labels = Vec::new();
    let mut p = *pos;
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        if p >= data.len() {
            return Err("dns name out of range".to_string());
        }
        let len = data[p];
        if len & 0xC0 == 0xC0 {
            if p + 1 >= data.len() {
                return Err("dns pointer out of range".to_string());
            }
            let ptr = (((len & 0x3F) as usize) << 8) | data[p + 1] as usize;
            if !jumped {
                *pos = p + 2;
            }
            p = ptr;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return Err("dns pointer loop".to_string());
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                *pos = p + 1;
            }
            break;
        }
        p += 1;
        let end = p + len as usize;
        if end > data.len() {
            return Err("dns label out of range".to_string());
        }
        labels.push(String::from_utf8_lossy(&data[p..end]).to_string());
        p = end;
    }
    Ok(labels.join("."))
}

fn dns_query(name: &str, qtype: &str) -> NativeResult<Vec<String>> {
    let typ = match qtype {
        "A" => 1_u16,
        "MX" => 15,
        "TXT" => 16,
        _ => return Err("unsupported qtype".to_string()),
    };
    let tid = (now() & 0xffff) as u16;
    let mut packet = Vec::new();
    packet.extend_from_slice(&tid.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for part in name.trim_end_matches('.').split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&typ.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    socket
        .send_to(&packet, "1.1.1.1:53")
        .map_err(|e| e.to_string())?;
    let mut data = [0_u8; 4096];
    let (len, _) = socket.recv_from(&mut data).map_err(|e| e.to_string())?;
    let data = &data[..len];
    if data.len() < 12 {
        return Err("short dns response".to_string());
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let _ = read_name(data, &mut pos)?;
        pos += 4;
    }
    let mut vals = Vec::new();
    for _ in 0..an {
        let _ = read_name(data, &mut pos)?;
        if pos + 10 > data.len() {
            break;
        }
        let atype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        let start = pos;
        let end = pos + rdlen;
        if end > data.len() {
            break;
        }
        let rdata = &data[start..end];
        pos = end;
        if atype != typ {
            continue;
        }
        match atype {
            1 if rdata.len() == 4 => {
                vals.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
            }
            15 if rdata.len() >= 2 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let mut name_pos = start + 2;
                let exchange = read_name(data, &mut name_pos)?;
                vals.push(format!("{pref} {exchange}"));
            }
            16 => {
                let mut p = 0;
                let mut txt = String::new();
                while p < rdata.len() {
                    let ln = rdata[p] as usize;
                    p += 1;
                    if p + ln > rdata.len() {
                        break;
                    }
                    txt.push_str(&String::from_utf8_lossy(&rdata[p..p + ln]));
                    p += ln;
                }
                vals.push(txt);
            }
            _ => {}
        }
    }
    Ok(vals)
}

fn dns_health() -> Value {
    let mut checks = vec![
        json!({ "name": HOSTNAME, "type": "A", "expect": PUBLIC_IP }),
        json!({ "name": DOMAIN, "type": "MX", "expect": "10 mail.olibuijr.com" }),
        json!({ "name": DOMAIN, "type": "TXT", "expect": "v=spf1 ip4:3.94.46.219 mx -all" }),
        json!({ "name": format!("_dmarc.{DOMAIN}"), "type": "TXT", "expect": "v=DMARC1; p=quarantine; rua=mailto:postmaster@olibuijr.com" }),
    ];
    for check in &mut checks {
        let name = check["name"].as_str().unwrap_or_default();
        let qtype = check["type"].as_str().unwrap_or_default();
        let expect = check["expect"].as_str().unwrap_or_default();
        match dns_query(name, qtype) {
            Ok(values) => {
                check["ok"] = json!(values.iter().any(|v| v == expect));
                check["values"] = json!(values);
            }
            Err(e) => {
                check["ok"] = json!(false);
                check["values"] = json!([]);
                check["error"] = json!(e);
            }
        }
    }
    Value::Array(checks)
}

fn spam_policy(data: &mut Value) -> Value {
    let defaults = spam_policy_default();
    let obj = object_mut(data);
    let entry = obj.entry("spamPolicy").or_insert(defaults.clone());
    merge_defaults(entry, &defaults);
    entry.clone()
}

fn spam_folder_count(address: &str) -> usize {
    folder_root(address, "Spam")
        .ok()
        .map(|root| count_messages_in_root(&root))
        .unwrap_or(0)
}

fn spam_summary(data: &mut Value) -> Value {
    let policy = spam_policy(data);
    let counts: Vec<Value> = dovecot_user_rows()
        .into_iter()
        .map(|user| json!({ "email": user.email, "spam": spam_folder_count(&user.email) }))
        .collect();
    let total: usize = counts
        .iter()
        .map(|row| row["spam"].as_u64().unwrap_or(0) as usize)
        .sum();
    json!({ "policy": policy, "mailboxes": counts, "totalSpam": total })
}

fn build_status() -> NativeResult<Value> {
    let mut data = load_json(STATE, state_default())?;
    data["services"] = services();
    data["metrics"] = vm_metrics(&mut data);
    data["users"] = Value::Array(dovecot_users());
    data["aliases"] = aliases();
    data["queue"] = mail_queue();
    data["deliveryErrors"] = delivery_errors();
    data["dnsHealth"] = dns_health();
    data["antiSpam"] = spam_summary(&mut data);
    data["generatedAt"] = json!(now());
    save_json(STATE, &data)?;
    Ok(data)
}

pub fn status() -> NativeResult<Value> {
    cached(&STATUS_CACHE, Duration::from_secs(3), build_status)
}

pub fn metrics() -> NativeResult<Value> {
    let mut data = load_json(STATE, state_default())?;
    let metrics = vm_metrics(&mut data);
    save_json(STATE, &data)?;
    Ok(json!({
        "metrics": metrics,
        "services": services(),
        "processes": top_processes(),
        "at": now(),
    }))
}

fn read_dkim_public_key(domain: &str) -> String {
    let path = Path::new(OPENDKIM_KEYS_DIR).join(domain).join("mail.txt");
    let text = fs::read_to_string(path).unwrap_or_default();
    let re = Regex::new("\"([^\"]*)\"").unwrap();
    re.captures_iter(&text)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect::<Vec<_>>()
        .join("")
}

fn domain_dns_records(domain: &str) -> Value {
    let mut records = vec![
        json!({ "type": "MX", "name": "@", "value": format!("10 {HOSTNAME}.") }),
        json!({ "type": "TXT", "name": "@", "value": format!("v=spf1 mx a:{HOSTNAME} -all") }),
        json!({ "type": "TXT", "name": "_dmarc", "value": format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}") }),
    ];
    let dkim = read_dkim_public_key(domain);
    records.push(json!({
        "type": "TXT",
        "name": "mail._domainkey",
        "value": if dkim.is_empty() { "(DKIM key not yet generated)".to_string() } else { dkim },
    }));
    Value::Array(records)
}

fn dns_check_domain(domain: &str) -> Value {
    let mut checks = vec![
        json!({ "name": domain, "type": "MX", "expect": format!("10 {}", HOSTNAME.trim_end_matches('.')) }),
        json!({ "name": domain, "type": "TXT", "expectContains": "v=spf1" }),
        json!({ "name": format!("_dmarc.{domain}"), "type": "TXT", "expectContains": "v=DMARC1" }),
    ];
    if !read_dkim_public_key(domain).is_empty() {
        checks.push(json!({ "name": format!("mail._domainkey.{domain}"), "type": "TXT", "expectContains": "v=DKIM1" }));
    }
    for check in &mut checks {
        let name = check["name"].as_str().unwrap_or_default();
        let qtype = check["type"].as_str().unwrap_or_default();
        match dns_query(name, qtype) {
            Ok(values) => {
                let ok = if let Some(expect) = check.get("expect").and_then(Value::as_str) {
                    values.iter().any(|v| v == expect)
                } else if let Some(expect) = check.get("expectContains").and_then(Value::as_str) {
                    values.iter().any(|v| v.contains(expect))
                } else {
                    !values.is_empty()
                };
                check["ok"] = json!(ok);
                check["values"] = json!(values);
            }
            Err(e) => {
                check["ok"] = json!(false);
                check["values"] = json!([]);
                check["error"] = json!(e);
            }
        }
        if let Some(obj) = check.as_object_mut() {
            obj.remove("expect");
            obj.remove("expectContains");
        }
    }
    Value::Array(checks)
}

fn load_domains() -> NativeResult<Value> {
    load_json(
        DOMAINS_STATE,
        json!({ "domains": [{ "domain": DOMAIN, "addedAt": 0, "status": "active" }] }),
    )
}

fn save_domains(data: &Value) -> NativeResult<()> {
    save_json(DOMAINS_STATE, data)
}

fn build_dns() -> NativeResult<Value> {
    Ok(json!({ "records": [
        { "type": "A", "name": HOSTNAME, "value": PUBLIC_IP },
        { "type": "A", "name": format!("smtp.{DOMAIN}"), "value": PUBLIC_IP },
        { "type": "A", "name": format!("imap.{DOMAIN}"), "value": PUBLIC_IP },
        { "type": "A", "name": format!("webmail.{DOMAIN}"), "value": PUBLIC_IP },
        { "type": "MX", "name": DOMAIN, "value": format!("10 {HOSTNAME}") },
        { "type": "TXT", "name": DOMAIN, "value": format!("v=spf1 ip4:{PUBLIC_IP} mx -all") },
        { "type": "TXT", "name": format!("_dmarc.{DOMAIN}"), "value": format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}") },
        { "type": "TXT", "name": format!("mail._domainkey.{DOMAIN}"), "value": format!("See /etc/opendkim/keys/{DOMAIN}/mail.txt") },
    ] }))
}

pub fn dns() -> NativeResult<Value> {
    cached(&DNS_CACHE, Duration::from_secs(60), build_dns)
}

fn build_domain_list() -> NativeResult<Value> {
    let data = load_domains()?;
    let domains = data["domains"].as_array().cloned().unwrap_or_default();
    let mut rows = Vec::new();
    for item in domains {
        let domain = item["domain"].as_str().unwrap_or(DOMAIN);
        let checks = dns_check_domain(domain);
        let ok = checks
            .as_array()
            .map(|rows| rows.iter().all(|c| c["ok"].as_bool().unwrap_or(false)))
            .unwrap_or(false);
        rows.push(json!({
            "domain": domain,
            "addedAt": item["addedAt"].as_u64().unwrap_or(0),
            "status": if ok { "verified" } else { "pending" },
            "dnsRecords": domain_dns_records(domain),
            "dnsChecks": checks,
        }));
    }
    Ok(json!({ "ok": true, "domains": rows }))
}

pub fn domain_list() -> NativeResult<Value> {
    cached(
        &DOMAIN_LIST_CACHE,
        Duration::from_secs(60),
        build_domain_list,
    )
}

fn random_password() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 24)
}

fn known_domains() -> Vec<String> {
    let mut domains = vec![DOMAIN.to_string()];
    if let Ok(data) = load_domains() {
        if let Some(rows) = data["domains"].as_array() {
            for row in rows {
                if let Some(domain) = row["domain"].as_str() {
                    if !domains.iter().any(|d| d == domain) {
                        domains.push(domain.to_string());
                    }
                }
            }
        }
    }
    domains
}

fn ensure_mailbox(email: &str, password: &str) -> NativeResult<()> {
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| "mailbox must include a domain".to_string())?;
    if local.is_empty() || !known_domains().iter().any(|d| d == domain) {
        return Err(format!(
            "mailbox must be in a configured domain (have: {})",
            known_domains().join(", ")
        ));
    }
    let mail_root = Path::new("/var/vmail").join(domain).join(local);
    fs::create_dir_all(&mail_root).map_err(|e| format!("mkdir {}: {e}", mail_root.display()))?;
    let _ = command_status(
        "chown",
        &["-R", "vmail:mail", mail_root.to_str().unwrap_or_default()],
    );
    let _ = command_status("chmod", &["0770", mail_root.to_str().unwrap_or_default()]);
    let hash = command_checked("doveadm", &["pw", "-s", "BLF-CRYPT", "-p", password])?;

    let mut lines: Vec<String> = fs::read_to_string(DOVECOT_USERS)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with(&format!("{email}:")) && !line.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    lines.push(format!(
        "{email}:{hash}:5000:8::{}::userdb_mail=maildir:{}/Maildir",
        mail_root.display(),
        mail_root.display()
    ));
    fs::write(DOVECOT_USERS, lines.join("\n") + "\n")
        .map_err(|e| format!("write {DOVECOT_USERS}: {e}"))?;
    let _ = command_status("chown", &["root:dovecot", DOVECOT_USERS]);
    let _ = command_status("chmod", &["0640", DOVECOT_USERS]);

    let mut vmailbox: Vec<String> = fs::read_to_string(POSTFIX_VMAILBOX)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with(&format!("{email} ")) && !line.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    vmailbox.push(format!("{email} {domain}/{local}/"));
    fs::write(POSTFIX_VMAILBOX, vmailbox.join("\n") + "\n")
        .map_err(|e| format!("write {POSTFIX_VMAILBOX}: {e}"))?;
    let _ = command_status("postmap", &[POSTFIX_VMAILBOX]);
    let _ = command_status("systemctl", &["reload", "dovecot"]);
    let _ = command_status("systemctl", &["reload", "postfix"]);
    Ok(())
}

pub fn add_user(email: &str, password: Option<&str>) -> NativeResult<Value> {
    clear_read_caches();
    let password = password
        .map(ToString::to_string)
        .unwrap_or_else(random_password);
    ensure_mailbox(email, &password)?;
    let mut data = load_json(STATE, state_default())?;
    prepend_event(&mut data, "events", format!("Mailbox active: {email}"), 40);
    save_json(STATE, &data)?;
    Ok(json!({ "ok": true, "email": email, "password": password }))
}

pub fn set_password(email: &str, password: Option<&str>) -> NativeResult<Value> {
    clear_read_caches();
    if !dovecot_user_rows().iter().any(|u| u.email == email) {
        return Ok(json!({ "ok": false, "error": "user not found" }));
    }
    let password = password
        .map(ToString::to_string)
        .unwrap_or_else(random_password);
    ensure_mailbox(email, &password)?;
    let mut data = load_json(STATE, state_default())?;
    prepend_event(
        &mut data,
        "events",
        format!("Password rotated: {email}"),
        40,
    );
    save_json(STATE, &data)?;
    Ok(json!({ "ok": true, "email": email, "password": password }))
}

pub fn add_alias(alias: &str, target: &str) -> NativeResult<Value> {
    clear_read_caches();
    let mut lines: Vec<String> = fs::read_to_string(POSTFIX_VIRTUAL)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with(&format!("{alias} ")) && !line.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    lines.push(format!("{alias} {target}"));
    fs::write(POSTFIX_VIRTUAL, lines.join("\n") + "\n")
        .map_err(|e| format!("write {POSTFIX_VIRTUAL}: {e}"))?;
    let _ = command_status("postmap", &[POSTFIX_VIRTUAL]);
    let _ = command_status("systemctl", &["reload", "postfix"]);
    let mut data = load_json(STATE, state_default())?;
    prepend_event(
        &mut data,
        "events",
        format!("Alias active: {alias} -> {target}"),
        40,
    );
    save_json(STATE, &data)?;
    Ok(json!({ "ok": true, "alias": alias, "target": target }))
}

fn clean_list(values: &Value, domain: bool) -> Vec<String> {
    let mut rows = Vec::new();
    match values {
        Value::Array(items) => {
            for item in items {
                rows.extend(clean_list(item, domain));
            }
        }
        Value::String(s) => {
            for item in s.split(['\n', ',', ';']) {
                let value = item.trim().to_lowercase();
                if !value.is_empty() {
                    rows.push(if domain {
                        value.trim_start_matches('@').to_string()
                    } else {
                        value
                    });
                }
            }
        }
        _ => {}
    }
    rows.sort();
    rows.dedup();
    rows
}

fn update_policy_list(policy: &mut Value, field: &str, mode: &str, values: &Value) {
    let domain_field = field == "domainBlocklist";
    let mut current = clean_list(policy.get(field).unwrap_or(&Value::Null), domain_field);
    let incoming = clean_list(values, domain_field);
    if mode == "set" {
        current = incoming;
    } else if mode == "remove" {
        current.retain(|item| !incoming.iter().any(|v| v == item));
    } else {
        current.extend(incoming);
        current.sort();
        current.dedup();
    }
    current.truncate(200);
    policy[field] = json!(current);
}

pub fn anti_spam_config(payload: Value) -> NativeResult<Value> {
    clear_read_caches();
    let mut data = load_json(STATE, state_default())?;
    let mut policy = spam_policy(&mut data);
    for key in ["enabled", "autoMove"] {
        if let Some(v) = payload.get(key).and_then(Value::as_bool) {
            policy[key] = json!(v);
        }
    }
    if let Some(v) = payload.get("threshold").and_then(Value::as_i64) {
        policy["threshold"] = json!(v.clamp(1, 20));
    }
    if let Some(v) = payload.get("maxLinks").and_then(Value::as_i64) {
        policy["maxLinks"] = json!(v.clamp(0, 100));
    }
    if let Some(field) = payload.get("field").and_then(Value::as_str) {
        if [
            "blocklist",
            "allowlist",
            "domainBlocklist",
            "subjectKeywords",
            "attachmentExtensions",
        ]
        .contains(&field)
        {
            update_policy_list(
                &mut policy,
                field,
                payload.get("mode").and_then(Value::as_str).unwrap_or("add"),
                payload
                    .get("values")
                    .or_else(|| payload.get("value"))
                    .unwrap_or(&Value::Null),
            );
        }
    }
    data["spamPolicy"] = policy;
    prepend_event(
        &mut data,
        "events",
        "Anti-spam policy updated".to_string(),
        40,
    );
    let anti_spam = spam_summary(&mut data);
    save_json(STATE, &data)?;
    Ok(json!({ "ok": true, "antiSpam": anti_spam }))
}

pub fn anti_spam_scan(email: Option<&str>) -> NativeResult<Value> {
    clear_read_caches();
    let mut data = load_json(STATE, state_default())?;
    let policy = spam_policy(&mut data);
    let users: Vec<String> = if let Some(email) = email {
        vec![email.to_string()]
    } else {
        dovecot_user_rows().into_iter().map(|u| u.email).collect()
    };
    let mut results = Vec::new();
    let mut scanned = 0_u64;
    let mut moved = 0_u64;
    for email in users {
        let row = scan_mailbox_for_spam(&email, &policy)?;
        scanned += row["scanned"].as_u64().unwrap_or(0);
        moved += row["moved"].as_u64().unwrap_or(0);
        results.push(row);
    }
    let mut policy = spam_policy(&mut data);
    policy["stats"]["scanned"] = json!(policy["stats"]["scanned"].as_u64().unwrap_or(0) + scanned);
    policy["stats"]["moved"] = json!(policy["stats"]["moved"].as_u64().unwrap_or(0) + moved);
    policy["stats"]["lastScan"] = json!(now());
    data["spamPolicy"] = policy;
    prepend_event(
        &mut data,
        "events",
        format!("Anti-spam scan moved {moved} of {scanned} message(s)"),
        40,
    );
    let anti_spam = spam_summary(&mut data);
    save_json(STATE, &data)?;
    Ok(
        json!({ "ok": true, "scanned": scanned, "moved": moved, "results": results, "antiSpam": anti_spam }),
    )
}

fn configure_domain_mail(domain: &str) -> NativeResult<()> {
    let vmd_file = Path::new("/etc/postfix/vmailbox_domains");
    let mut domains: Vec<String> = fs::read_to_string(vmd_file)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();
    if !domains.iter().any(|d| d == domain) {
        domains.push(domain.to_string());
        fs::write(vmd_file, domains.join("\n") + "\n")
            .map_err(|e| format!("write {}: {e}", vmd_file.display()))?;
    }

    let key_dir = Path::new(OPENDKIM_KEYS_DIR).join(domain);
    if !key_dir.join("mail.private").exists() {
        fs::create_dir_all(&key_dir).map_err(|e| format!("mkdir {}: {e}", key_dir.display()))?;
        command_checked(
            "opendkim-genkey",
            &[
                "-s",
                "mail",
                "-d",
                domain,
                "-D",
                key_dir.to_str().unwrap_or_default(),
            ],
        )?;
        let _ = command_status(
            "chown",
            &[
                "-R",
                "opendkim:opendkim",
                key_dir.to_str().unwrap_or_default(),
            ],
        );
        let _ = command_status(
            "chmod",
            &[
                "0600",
                key_dir.join("mail.private").to_str().unwrap_or_default(),
            ],
        );
    }

    replace_lines_containing(
        OPENDKIM_KEYTABLE,
        domain,
        format!(
            "mail._domainkey.{domain} {domain}:mail:{}/mail.private",
            key_dir.display()
        ),
    )?;
    replace_lines_containing(
        OPENDKIM_SIGNINGTABLE,
        domain,
        format!("*@{domain} mail._domainkey.{domain}"),
    )?;
    let mut trusted: Vec<String> = fs::read_to_string(OPENDKIM_TRUSTEDHOSTS)
        .unwrap_or_else(|_| "127.0.0.1\n::1\nlocalhost\n".to_string())
        .lines()
        .map(ToString::to_string)
        .collect();
    if !trusted.iter().any(|d| d == domain) {
        trusted.push(domain.to_string());
        fs::write(OPENDKIM_TRUSTEDHOSTS, trusted.join("\n") + "\n")
            .map_err(|e| format!("write {OPENDKIM_TRUSTEDHOSTS}: {e}"))?;
    }
    let vmail_dir = Path::new("/var/vmail").join(domain);
    fs::create_dir_all(&vmail_dir).map_err(|e| format!("mkdir {}: {e}", vmail_dir.display()))?;
    let _ = command_status(
        "chown",
        &["-R", "vmail:mail", vmail_dir.to_str().unwrap_or_default()],
    );
    let _ = command_status("systemctl", &["reload", "opendkim"]);
    let _ = command_status("systemctl", &["reload", "postfix"]);
    Ok(())
}

fn replace_lines_containing(path: &str, needle: &str, new_line: String) -> NativeResult<()> {
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.contains(needle))
        .map(ToString::to_string)
        .collect();
    lines.push(new_line);
    fs::write(path, lines.join("\n") + "\n").map_err(|e| format!("write {path}: {e}"))
}

pub fn domain_add(domain: &str) -> NativeResult<Value> {
    clear_read_caches();
    let domain = domain.trim().to_lowercase();
    let valid =
        Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").unwrap();
    if !valid.is_match(&domain) {
        return Ok(json!({ "ok": false, "error": "invalid domain name" }));
    }
    let mut data = load_domains()?;
    let domains = data["domains"]
        .as_array_mut()
        .ok_or_else(|| "invalid domains state".to_string())?;
    if domains
        .iter()
        .any(|d| d["domain"].as_str() == Some(&domain))
    {
        return Ok(json!({ "ok": false, "error": "domain already exists" }));
    }
    configure_domain_mail(&domain)?;
    domains.push(json!({ "domain": domain, "addedAt": now(), "status": "active" }));
    save_domains(&data)?;
    let mut state = load_json(STATE, state_default())?;
    prepend_event(&mut state, "events", format!("Domain added: {domain}"), 40);
    save_json(STATE, &state)?;
    Ok(json!({ "ok": true, "domain": domain, "dnsRecords": domain_dns_records(&domain) }))
}

pub fn domain_check(domain: &str) -> NativeResult<Value> {
    let domain = domain.trim().to_lowercase();
    let checks = dns_check_domain(&domain);
    let ok = checks
        .as_array()
        .map(|rows| rows.iter().all(|c| c["ok"].as_bool().unwrap_or(false)))
        .unwrap_or(false);
    Ok(
        json!({ "ok": true, "domain": domain, "status": if ok { "verified" } else { "pending" }, "dnsRecords": domain_dns_records(&domain), "dnsChecks": checks }),
    )
}

pub fn domain_remove(domain: &str) -> NativeResult<Value> {
    clear_read_caches();
    let domain = domain.trim().to_lowercase();
    if domain == DOMAIN {
        return Ok(json!({ "ok": false, "error": "cannot remove the primary domain" }));
    }
    let mut data = load_domains()?;
    if let Some(domains) = data["domains"].as_array_mut() {
        domains.retain(|d| d["domain"].as_str() != Some(&domain));
    }
    save_domains(&data)?;
    for table in [OPENDKIM_KEYTABLE, OPENDKIM_SIGNINGTABLE] {
        let lines: Vec<String> = fs::read_to_string(table)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.contains(&domain))
            .map(ToString::to_string)
            .collect();
        fs::write(table, lines.join("\n") + "\n").map_err(|e| format!("write {table}: {e}"))?;
    }
    let lines: Vec<String> = fs::read_to_string(OPENDKIM_TRUSTEDHOSTS)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.trim() != domain)
        .map(ToString::to_string)
        .collect();
    fs::write(OPENDKIM_TRUSTEDHOSTS, lines.join("\n") + "\n")
        .map_err(|e| format!("write {OPENDKIM_TRUSTEDHOSTS}: {e}"))?;
    let vmd = "/etc/postfix/vmailbox_domains";
    let lines: Vec<String> = fs::read_to_string(vmd)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.trim() != domain)
        .map(ToString::to_string)
        .collect();
    fs::write(vmd, lines.join("\n") + "\n").map_err(|e| format!("write {vmd}: {e}"))?;
    let _ = command_status("systemctl", &["reload", "opendkim"]);
    let _ = command_status("systemctl", &["reload", "postfix"]);
    let mut state = load_json(STATE, state_default())?;
    prepend_event(
        &mut state,
        "events",
        format!("Domain removed: {domain}"),
        40,
    );
    save_json(STATE, &state)?;
    Ok(json!({ "ok": true, "domain": domain, "removed": true }))
}

pub fn validate_login(email: &str, password: &str) -> NativeResult<bool> {
    let status = Command::new("doveadm")
        .args(["auth", "test", email, password])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("doveadm auth failed: {e}"))?;
    Ok(status.success())
}

fn folder_suffix(folder: &str) -> NativeResult<&'static str> {
    match folder {
        "Inbox" => Ok(""),
        "Sent" => Ok(".Sent"),
        "Drafts" => Ok(".Drafts"),
        "Archive" => Ok(".Archive"),
        "Spam" => Ok(".Junk"),
        "Trash" => Ok(".Trash"),
        _ => Err("unknown folder".to_string()),
    }
}

fn folder_root(address: &str, folder: &str) -> NativeResult<PathBuf> {
    let root = user_home(address)?.join("Maildir");
    let suffix = folder_suffix(folder)?;
    let path = if suffix.is_empty() {
        root
    } else {
        root.join(suffix)
    };
    for name in ["cur", "new", "tmp"] {
        fs::create_dir_all(path.join(name)).map_err(|e| format!("mkdir maildir: {e}"))?;
    }
    Ok(path)
}

fn count_messages_in_root(root: &Path) -> usize {
    ["cur", "new"]
        .iter()
        .filter_map(|sub| fs::read_dir(root.join(sub)).ok())
        .flat_map(|entries| entries.flatten())
        .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
        .count()
}

fn folder_counts(address: &str) -> NativeResult<Value> {
    let mut rows = Vec::new();
    for folder in ["Inbox", "Sent", "Drafts", "Archive", "Spam", "Trash"] {
        let root = folder_root(address, folder)?;
        let total = count_messages_in_root(&root);
        let unread = fs::read_dir(root.join("new"))
            .map(|e| e.flatten().count())
            .unwrap_or(0);
        rows.push(json!({ "name": folder, "total": total, "unread": unread }));
    }
    Ok(Value::Array(rows))
}

fn msg_id(folder: &str, subdir: &str, name: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&vec![folder, subdir, name]).unwrap_or_default())
}

fn decode_msg_id(value: &str) -> NativeResult<(String, String, String)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("invalid message id: {e}"))?;
    let row: Vec<String> =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid message id JSON: {e}"))?;
    if row.len() != 3 {
        return Err("invalid message id".to_string());
    }
    Ok((row[0].clone(), row[1].clone(), row[2].clone()))
}

fn message_path(address: &str, value: &str) -> NativeResult<(String, String, PathBuf)> {
    let (folder, subdir, name) = decode_msg_id(value)?;
    if subdir != "cur" && subdir != "new" {
        return Err("message not found".to_string());
    }
    let path = folder_root(address, &folder)?.join(&subdir).join(name);
    if !path.exists() {
        return Err("message not found".to_string());
    }
    Ok((folder, subdir, path))
}

fn filename(part: &ParsedMail<'_>) -> Option<String> {
    part.get_content_disposition()
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
}

fn first_body(part: &ParsedMail<'_>, mimetype: &str) -> String {
    if part.subparts.is_empty()
        && part.ctype.mimetype.eq_ignore_ascii_case(mimetype)
        && filename(part).is_none()
    {
        return part.get_body().unwrap_or_default();
    }
    for child in &part.subparts {
        let body = first_body(child, mimetype);
        if !body.is_empty() {
            return body;
        }
    }
    String::new()
}

fn clean_addr(value: &str) -> String {
    value.replace(['\n', '\r'], " ").trim().to_string()
}

fn normalized_email(value: &str) -> String {
    let re = Regex::new(r"(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})").unwrap();
    re.captures(value)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .unwrap_or_default()
}

fn sender_domain(value: &str) -> String {
    normalized_email(value)
        .split_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_default()
}

fn message_links(text: &str) -> usize {
    Regex::new("(?i)https?://|www\\.")
        .unwrap()
        .find_iter(text)
        .count()
}

fn attachment_names(part: &ParsedMail<'_>, rows: &mut Vec<String>) {
    if let Some(name) = filename(part) {
        rows.push(name);
    }
    for child in &part.subparts {
        attachment_names(child, rows);
    }
}

fn attachments_meta(part: &ParsedMail<'_>, current: &mut usize, rows: &mut Vec<Value>) {
    if let Some(name) = filename(part) {
        let size = part.get_body_raw().map(|b| b.len()).unwrap_or(0);
        rows.push(json!({ "index": *current, "filename": name, "contentType": part.ctype.mimetype, "size": size }));
    }
    *current += 1;
    for child in &part.subparts {
        attachments_meta(child, current, rows);
    }
}

fn part_by_index<'a>(
    part: &'a ParsedMail<'a>,
    target: usize,
    current: &mut usize,
) -> Option<&'a ParsedMail<'a>> {
    if *current == target {
        return Some(part);
    }
    *current += 1;
    for child in &part.subparts {
        if let Some(found) = part_by_index(child, target, current) {
            return Some(found);
        }
    }
    None
}

fn spam_score(parsed: &ParsedMail<'_>, policy: &Value) -> (u64, Vec<String>) {
    let from = parsed.headers.get_first_value("From").unwrap_or_default();
    let sender = normalized_email(&from);
    let domain = sender_domain(&from);
    let allowlist = string_array(&policy["allowlist"]);
    if allowlist.iter().any(|v| v == &sender || v == &domain) {
        return (0, vec!["allowlisted".to_string()]);
    }
    let mut score = 0_u64;
    let mut reasons = Vec::new();
    if string_array(&policy["blocklist"])
        .iter()
        .any(|v| v == &sender)
    {
        score += 10;
        reasons.push("blocked sender".to_string());
    }
    if string_array(&policy["domainBlocklist"])
        .iter()
        .any(|v| v == &domain)
    {
        score += 8;
        reasons.push("blocked domain".to_string());
    }
    let subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_default();
    let plain = first_body(parsed, "text/plain");
    let search = format!("{subject}\n{plain}").to_lowercase();
    for word in string_array(&policy["subjectKeywords"]) {
        let word = word.trim().to_lowercase();
        if !word.is_empty() && search.contains(&word) {
            score += 2;
            reasons.push(format!("keyword: {word}"));
        }
    }
    let auth = parsed
        .headers
        .get_first_value("Authentication-Results")
        .unwrap_or_default()
        .to_lowercase();
    for signal in ["spf=fail", "dkim=fail", "dmarc=fail", "spf=softfail"] {
        if auth.contains(signal) {
            score += 3;
            reasons.push(signal.to_string());
        }
    }
    let blocked_ext = string_array(&policy["attachmentExtensions"]);
    let mut names = Vec::new();
    attachment_names(parsed, &mut names);
    for name in names {
        if let Some((_, ext)) = name.rsplit_once('.') {
            let ext = ext.to_lowercase();
            if blocked_ext.iter().any(|v| v.trim_start_matches('.') == ext) {
                score += 6;
                reasons.push(format!("attachment: .{ext}"));
            }
        }
    }
    let links = message_links(&search);
    if links > policy["maxLinks"].as_u64().unwrap_or(10) as usize {
        score += 2;
        reasons.push(format!("link count: {links}"));
    }
    reasons.truncate(8);
    (score, reasons)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn sanitize_html(value: &str) -> String {
    let mut out =
        Regex::new("(?is)<(script|style|iframe|object|embed|link|meta|base|form)[^>]*>.*?</\\1>")
            .unwrap()
            .replace_all(value, "")
            .to_string();
    out = Regex::new("(?is)<(script|style|iframe|object|embed|link|meta|base|form)[^>]*/?>")
        .unwrap()
        .replace_all(&out, "")
        .to_string();
    out = Regex::new(r#"(?is)\s+on[a-zA-Z]+\s*=\s*(['"]).*?\1"#)
        .unwrap()
        .replace_all(&out, "")
        .to_string();
    Regex::new(r#"(?is)\s+(href|src)\s*=\s*(['"])\s*javascript:.*?\2"#)
        .unwrap()
        .replace_all(&out, "$1=\"#\"")
        .to_string()
}

fn html_from_message(parsed: &ParsedMail<'_>) -> String {
    let html = first_body(parsed, "text/html");
    if !html.is_empty() {
        return sanitize_html(&html);
    }
    escape_html(&first_body(parsed, "text/plain")).replace('\n', "<br>")
}

fn message_summary(folder: &str, subdir: &str, path: &Path, policy: &Value) -> NativeResult<Value> {
    let bytes = fs::read(path).map_err(|e| format!("read message: {e}"))?;
    let parsed = mailparse::parse_mail(&bytes).map_err(|e| format!("parse message: {e}"))?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let flags = name.split_once(":2,").map(|(_, f)| f).unwrap_or("");
    let plain = first_body(&parsed, "text/plain");
    let preview = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut attachments = Vec::new();
    attachment_names(&parsed, &mut attachments);
    let (score, reasons) = spam_score(&parsed, policy);
    let timestamp = path
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(json!({
        "id": msg_id(folder, subdir, name),
        "folder": folder,
        "from": clean_addr(&parsed.headers.get_first_value("From").unwrap_or_default()),
        "to": clean_addr(&parsed.headers.get_first_value("To").unwrap_or_default()),
        "subject": parsed.headers.get_first_value("Subject").unwrap_or_else(|| "(no subject)".to_string()),
        "date": parsed.headers.get_first_value("Date").unwrap_or_default(),
        "timestamp": timestamp,
        "preview": preview.chars().take(180).collect::<String>(),
        "unread": subdir == "new" || !flags.contains('S'),
        "flagged": flags.contains('F'),
        "attachments": attachments,
        "spamScore": score,
        "spamReasons": reasons,
    }))
}

fn set_seen(path: &Path) -> NativeResult<PathBuf> {
    if path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        != Some("new")
    {
        return Ok(path.to_path_buf());
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let target = path
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| "invalid maildir path".to_string())?
        .join("cur")
        .join(if name.contains(":2,") {
            name.to_string()
        } else {
            format!("{name}:2,S")
        });
    fs::rename(path, &target).map_err(|e| format!("mark read: {e}"))?;
    Ok(target)
}

fn update_flag(path: &Path, flag: char, enabled: bool) -> NativeResult<PathBuf> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let (base, flags) = name.split_once(":2,").unwrap_or((name, ""));
    let mut chars: Vec<char> = flags.chars().collect();
    if enabled && !chars.contains(&flag) {
        chars.push(flag);
    }
    if !enabled {
        chars.retain(|c| *c != flag);
    }
    chars.sort_unstable();
    let target = path.with_file_name(format!(
        "{base}:2,{}",
        chars.into_iter().collect::<String>()
    ));
    fs::rename(path, &target).map_err(|e| format!("update flag: {e}"))?;
    Ok(target)
}

fn move_path_to_folder(address: &str, path: &Path, target_folder: &str) -> NativeResult<PathBuf> {
    let root = folder_root(address, target_folder)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("message");
    let mut target = root.join("cur").join(name);
    let mut suffix = 0;
    while target.exists() {
        suffix += 1;
        target = root.join("cur").join(format!("{name}.{suffix}"));
    }
    fs::rename(path, &target).map_err(|e| format!("move message: {e}"))?;
    Ok(target)
}

fn move_message_path(
    address: &str,
    message_id: &str,
    target_folder: &str,
) -> NativeResult<PathBuf> {
    let (_, _, path) = message_path(address, message_id)?;
    move_path_to_folder(address, &path, target_folder)
}

fn process_incoming(address: &str, folder: &str) -> NativeResult<()> {
    if folder != "Inbox" {
        return Ok(());
    }
    let mut state = load_json(STATE, state_default())?;
    let policy = spam_policy(&mut state);
    let root = folder_root(address, "Inbox")?;
    let mut spam_moved = 0_u64;
    let mut scanned = 0_u64;
    for subdir in ["new", "cur"] {
        for entry in fs::read_dir(root.join(subdir))
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with('.'))
            {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(parsed) = mailparse::parse_mail(&bytes) else {
                continue;
            };
            scanned += 1;
            let (score, _) = spam_score(&parsed, &policy);
            if policy["enabled"].as_bool().unwrap_or(true)
                && policy["autoMove"].as_bool().unwrap_or(true)
                && score >= policy["threshold"].as_u64().unwrap_or(5)
            {
                let _ = move_path_to_folder(address, &path, "Spam");
                spam_moved += 1;
            }
        }
    }
    if scanned > 0 {
        let mut policy = spam_policy(&mut state);
        policy["stats"]["scanned"] =
            json!(policy["stats"]["scanned"].as_u64().unwrap_or(0) + scanned);
        policy["stats"]["moved"] =
            json!(policy["stats"]["moved"].as_u64().unwrap_or(0) + spam_moved);
        policy["stats"]["lastScan"] = json!(now());
        state["spamPolicy"] = policy;
        save_json(STATE, &state)?;
    }
    Ok(())
}

fn scan_mailbox_for_spam(address: &str, policy: &Value) -> NativeResult<Value> {
    let root = folder_root(address, "Inbox")?;
    let mut scanned = 0_u64;
    let mut moved = 0_u64;
    for subdir in ["new", "cur"] {
        for entry in fs::read_dir(root.join(subdir))
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let path = entry.path();
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(parsed) = mailparse::parse_mail(&bytes) else {
                continue;
            };
            scanned += 1;
            let (score, _) = spam_score(&parsed, policy);
            if policy["enabled"].as_bool().unwrap_or(true)
                && policy["autoMove"].as_bool().unwrap_or(true)
                && score >= policy["threshold"].as_u64().unwrap_or(5)
            {
                let _ = move_path_to_folder(address, &path, "Spam");
                moved += 1;
            }
        }
    }
    Ok(json!({ "email": address, "scanned": scanned, "moved": moved }))
}

pub fn webmail_state(email: &str, folder: &str, query: &str) -> NativeResult<Value> {
    let data = load_json(WEBMAIL_STATE, webmail_default())?;
    process_incoming(email, folder)?;
    let root = folder_root(email, folder)?;
    let mut state = load_json(STATE, state_default())?;
    let policy = spam_policy(&mut state);
    let mut rows = Vec::new();
    let query = query.to_lowercase();
    for subdir in ["new", "cur"] {
        for entry in fs::read_dir(root.join(subdir))
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with('.'))
            {
                continue;
            }
            let Ok(item) = message_summary(folder, subdir, &path, &policy) else {
                continue;
            };
            let haystack = format!(
                "{} {} {} {}",
                item["from"].as_str().unwrap_or(""),
                item["to"].as_str().unwrap_or(""),
                item["subject"].as_str().unwrap_or(""),
                item["preview"].as_str().unwrap_or("")
            )
            .to_lowercase();
            if query.is_empty() || haystack.contains(&query) {
                rows.push(item);
            }
        }
    }
    rows.sort_by(|a, b| b["timestamp"].as_u64().cmp(&a["timestamp"].as_u64()));
    rows.truncate(100);
    Ok(json!({
        "ok": true,
        "mailbox": email,
        "folder": folder,
        "folders": folder_counts(email)?,
        "messages": rows,
        "contacts": data["contacts"].clone(),
        "signatures": data["signatures"].clone(),
        "vacation": data["vacation"].clone(),
        "rules": data["rules"].clone(),
        "preferences": data["preferences"].clone(),
        "audit": data["audit"].as_array().map(|a| a.iter().take(20).cloned().collect::<Vec<_>>()).unwrap_or_default(),
    }))
}

pub fn webmail_read(email: &str, id: &str, mark_read: bool) -> NativeResult<Value> {
    let (folder, subdir, mut path) = message_path(email, id)?;
    let mut current_subdir = subdir;
    if mark_read {
        path = set_seen(&path)?;
        current_subdir = "cur".to_string();
    }
    let bytes = fs::read(&path).map_err(|e| format!("read message: {e}"))?;
    let parsed = mailparse::parse_mail(&bytes).map_err(|e| format!("parse message: {e}"))?;
    let mut state = load_json(STATE, state_default())?;
    let policy = spam_policy(&mut state);
    let summary = message_summary(&folder, &current_subdir, &path, &policy)?;
    let mut attachments = Vec::new();
    let mut current = 0;
    attachments_meta(&parsed, &mut current, &mut attachments);
    let mut message = summary.as_object().cloned().unwrap_or_default();
    message.insert(
        "bodyText".to_string(),
        json!(first_body(&parsed, "text/plain")),
    );
    message.insert("bodyHtml".to_string(), json!(html_from_message(&parsed)));
    message.insert("attachments".to_string(), Value::Array(attachments));
    Ok(json!({ "ok": true, "message": Value::Object(message) }))
}

fn save_to_folder(address: &str, folder: &str, content: &[u8], seen: bool) -> NativeResult<String> {
    let root = folder_root(address, folder)?;
    let filename = format!(
        "{}.{}.rust{}",
        now(),
        std::process::id(),
        if seen { ":2,S" } else { "" }
    );
    let path = root.join(if seen { "cur" } else { "new" }).join(&filename);
    fs::write(&path, content).map_err(|e| format!("save message: {e}"))?;
    Ok(filename)
}

fn wrap_base64(data: &[u8]) -> String {
    let raw = base64::engine::general_purpose::STANDARD.encode(data);
    raw.as_bytes()
        .chunks(76)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn build_message(sender: &str, payload: &Value) -> NativeResult<(Vec<u8>, Vec<String>)> {
    let clean = |key: &str| clean_addr(payload.get(key).and_then(Value::as_str).unwrap_or(""));
    let to = clean("to");
    let cc = clean("cc");
    let bcc = clean("bcc");
    let subject = clean("subject");
    let mut recipients = Vec::new();
    for raw in [&to, &cc, &bcc] {
        for item in raw.split([',', ';']) {
            let addr = clean_addr(item);
            if !addr.is_empty() {
                recipients.push(addr);
            }
        }
    }
    if recipients.is_empty() {
        return Err("at least one recipient is required".to_string());
    }
    let mut body = payload
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if let Some(sig) = payload
        .get("signature")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        body = format!("{}\n\n{}", body.trim_end(), sig.trim());
    }
    let msgid = format!("<{}.{}@{}>", now(), std::process::id(), DOMAIN);
    let attachments = payload
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = String::new();
    out.push_str(&format!("From: {sender}\r\n"));
    out.push_str(&format!("To: {to}\r\n"));
    if !cc.is_empty() {
        out.push_str(&format!("Cc: {cc}\r\n"));
    }
    out.push_str(&format!(
        "Subject: {}\r\n",
        if subject.is_empty() {
            "(no subject)"
        } else {
            &subject
        }
    ));
    out.push_str(&format!(
        "Date: {}\r\n",
        command_output("date", &["-R"]).trim()
    ));
    out.push_str(&format!("Message-ID: {msgid}\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    if attachments.is_empty() {
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        out.push_str(&body);
        out.push_str("\r\n");
    } else {
        let boundary = format!("akurai-{}-{}", now(), std::process::id());
        out.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
        ));
        out.push_str(&format!(
            "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
        ));
        for item in attachments.iter().take(5) {
            let name = clean_addr(
                item.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("attachment"),
            );
            let ctype = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream");
            let encoded = item.get("data").and_then(Value::as_str).unwrap_or("");
            let data = base64::engine::general_purpose::STANDARD
                .decode(encoded.split_once(',').map(|(_, v)| v).unwrap_or(encoded))
                .map_err(|e| format!("invalid attachment: {e}"))?;
            if data.len() > MAX_ATTACHMENT_BYTES {
                return Err(format!("attachment too large: {name}"));
            }
            out.push_str(&format!("--{boundary}\r\nContent-Type: {ctype}\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n", wrap_base64(&data)));
        }
        out.push_str(&format!("--{boundary}--\r\n"));
    }
    Ok((out.into_bytes(), recipients))
}

pub fn webmail_send(email: &str, payload: Value) -> NativeResult<Value> {
    let sender = clean_addr(payload.get("from").and_then(Value::as_str).unwrap_or(email));
    if !dovecot_user_rows().iter().any(|u| u.email == sender) {
        return Err("sender mailbox not found".to_string());
    }
    let (message, recipients) = build_message(&sender, &payload)?;
    let mut child = Command::new("/usr/sbin/sendmail")
        .args(["-t", "-oi"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sendmail failed: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "sendmail stdin unavailable".to_string())?
        .write_all(&message)
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(400)
            .collect());
    }
    save_to_folder(&sender, "Sent", &message, true)?;
    Ok(json!({ "ok": true, "sent": true, "recipients": recipients }))
}

pub fn webmail_draft(email: &str, payload: Value) -> NativeResult<Value> {
    let sender = clean_addr(payload.get("from").and_then(Value::as_str).unwrap_or(email));
    let (message, _) = build_message(
        &sender,
        &json!({
            "to": payload.get("to").cloned().unwrap_or(Value::String(String::new())),
            "cc": payload.get("cc").cloned().unwrap_or(Value::String(String::new())),
            "bcc": payload.get("bcc").cloned().unwrap_or(Value::String(String::new())),
            "subject": payload.get("subject").cloned().unwrap_or(Value::String("(draft)".to_string())),
            "body": payload.get("body").cloned().unwrap_or(Value::String(String::new())),
            "attachments": payload.get("attachments").cloned().unwrap_or(Value::Array(vec![])),
        }),
    )?;
    let key = save_to_folder(email, "Drafts", &message, true)?;
    Ok(json!({ "ok": true, "draft": key }))
}

pub fn webmail_action(email: &str, id: &str, action: &str, target: &str) -> NativeResult<Value> {
    match action {
        "delete" => {
            move_message_path(email, id, "Trash")?;
        }
        "archive" => {
            move_message_path(email, id, "Archive")?;
        }
        "spam" => {
            let (_, _, path) = message_path(email, id)?;
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(parsed) = mailparse::parse_mail(&bytes) {
                    let sender = normalized_email(
                        &parsed.headers.get_first_value("From").unwrap_or_default(),
                    );
                    let mut state = load_json(STATE, state_default())?;
                    let mut policy = spam_policy(&mut state);
                    let mut blocklist = string_array(&policy["blocklist"]);
                    if !sender.is_empty() && !blocklist.iter().any(|s| s == &sender) {
                        blocklist.push(sender.clone());
                        policy["blocklist"] = json!(blocklist);
                        state["spamPolicy"] = policy;
                        prepend_event(
                            &mut state,
                            "events",
                            format!("Spam sender blocked: {sender}"),
                            40,
                        );
                        save_json(STATE, &state)?;
                    }
                }
            }
            move_path_to_folder(email, &path, "Spam")?;
        }
        "move" => {
            move_message_path(email, id, target)?;
        }
        "read" => {
            let (_, _, path) = message_path(email, id)?;
            let _ = set_seen(&path)?;
        }
        "unread" => {
            let (_, _, path) = message_path(email, id)?;
            let path = update_flag(&path, 'S', false)?;
            let target_path = path
                .parent()
                .and_then(|p| p.parent())
                .ok_or_else(|| "invalid maildir path".to_string())?
                .join("new")
                .join(path.file_name().unwrap());
            fs::rename(path, target_path).map_err(|e| format!("mark unread: {e}"))?;
        }
        "star" => {
            let (_, _, path) = message_path(email, id)?;
            let _ = update_flag(&path, 'F', true)?;
        }
        "unstar" => {
            let (_, _, path) = message_path(email, id)?;
            let _ = update_flag(&path, 'F', false)?;
        }
        _ => return Err("unknown message action".to_string()),
    }
    Ok(json!({ "ok": true, "action": action }))
}

pub fn webmail_config(email: &str, kind: &str, payload: Value) -> NativeResult<Value> {
    let mut data = load_json(WEBMAIL_STATE, webmail_default())?;
    match kind {
        "contact" => {
            let email_value =
                clean_addr(payload.get("email").and_then(Value::as_str).unwrap_or(""));
            let mut contacts = data["contacts"].as_array().cloned().unwrap_or_default();
            contacts.retain(|c| c["email"].as_str() != Some(&email_value));
            if !email_value.is_empty() {
                contacts.push(json!({ "name": clean_addr(payload.get("name").and_then(Value::as_str).unwrap_or("")), "email": email_value }));
            }
            contacts.sort_by(|a, b| a["email"].as_str().cmp(&b["email"].as_str()));
            data["contacts"] = Value::Array(contacts);
        }
        "signature" => {
            let key = clean_addr(
                payload
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or(email),
            );
            let signatures = data["signatures"]
                .as_object_mut()
                .ok_or_else(|| "invalid signatures state".to_string())?;
            signatures.insert(
                key,
                json!(
                    payload
                        .get("signature")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                ),
            );
        }
        "vacation" => {
            data["vacation"] = json!({
                "enabled": payload.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                "subject": clean_addr(payload.get("subject").and_then(Value::as_str).unwrap_or("")),
                "body": payload.get("body").and_then(Value::as_str).unwrap_or(""),
            });
        }
        "rule" => {
            let mut rules = data["rules"].as_array().cloned().unwrap_or_default();
            let mut hasher = Sha1::new();
            hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
            rules.push(json!({
                "id": format!("{:x}", hasher.finalize()).chars().take(12).collect::<String>(),
                "field": payload.get("field").and_then(Value::as_str).unwrap_or("from"),
                "contains": payload.get("contains").and_then(Value::as_str).unwrap_or(""),
                "action": payload.get("action").and_then(Value::as_str).unwrap_or("Archive"),
                "enabled": payload.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            }));
            if rules.len() > 50 {
                rules = rules.split_off(rules.len() - 50);
            }
            data["rules"] = Value::Array(rules);
        }
        "preferences" => {
            let prefs = data["preferences"]
                .as_object_mut()
                .ok_or_else(|| "invalid preferences state".to_string())?;
            if let Some(incoming) = payload.as_object() {
                for (key, value) in incoming {
                    prefs.insert(key.clone(), value.clone());
                }
            }
        }
        _ => return Err("unknown config kind".to_string()),
    }
    save_json(WEBMAIL_STATE, &data)?;
    Ok(json!({ "ok": true, "webmail": data }))
}

pub fn webmail_export() -> NativeResult<Value> {
    Ok(json!({ "ok": true, "webmail": load_json(WEBMAIL_STATE, webmail_default())? }))
}

pub fn webmail_import(payload: Value) -> NativeResult<Value> {
    let mut data = load_json(WEBMAIL_STATE, webmail_default())?;
    for key in ["contacts", "signatures", "vacation", "rules", "preferences"] {
        if let Some(value) = payload.get(key) {
            data[key] = value.clone();
        }
    }
    prepend_event(&mut data, "audit", "Settings imported".to_string(), 100);
    save_json(WEBMAIL_STATE, &data)?;
    Ok(json!({ "ok": true, "webmail": data }))
}

pub fn webmail_attachment(email: &str, id: &str, index: &str) -> NativeResult<Value> {
    let (_, _, path) = message_path(email, id)?;
    let bytes = fs::read(&path).map_err(|e| format!("read message: {e}"))?;
    let parsed = mailparse::parse_mail(&bytes).map_err(|e| format!("parse message: {e}"))?;
    let target = index
        .parse::<usize>()
        .map_err(|_| "invalid attachment index".to_string())?;
    let mut current = 0;
    let part = part_by_index(&parsed, target, &mut current)
        .ok_or_else(|| "attachment not found".to_string())?;
    let name = filename(part).ok_or_else(|| "attachment not found".to_string())?;
    let data = part
        .get_body_raw()
        .map_err(|e| format!("read attachment: {e}"))?;
    Ok(json!({
        "ok": true,
        "filename": name,
        "contentType": part.ctype.mimetype,
        "data": base64::engine::general_purpose::STANDARD.encode(data),
    }))
}

pub fn webmail_apply_rules(email: &str, folder: &str) -> NativeResult<Value> {
    let data = load_json(WEBMAIL_STATE, webmail_default())?;
    let rules: Vec<Value> = data["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r["enabled"].as_bool().unwrap_or(true))
        .collect();
    let root = folder_root(email, folder)?;
    let mut moved = 0_u64;
    let mut state = load_json(STATE, state_default())?;
    let policy = spam_policy(&mut state);
    for subdir in ["new", "cur"] {
        for entry in fs::read_dir(root.join(subdir))
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let path = entry.path();
            let Ok(item) = message_summary(folder, subdir, &path, &policy) else {
                continue;
            };
            for rule in &rules {
                let field = rule["field"].as_str().unwrap_or("from");
                let contains = rule["contains"].as_str().unwrap_or("").to_lowercase();
                let target = rule["action"].as_str().unwrap_or("Archive");
                if !contains.is_empty()
                    && item[field]
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&contains)
                    && folder_suffix(target).is_ok()
                    && target != folder
                {
                    let _ = move_path_to_folder(email, &path, target);
                    moved += 1;
                    break;
                }
            }
        }
    }
    Ok(json!({ "ok": true, "moved": moved }))
}
