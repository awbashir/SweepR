//! Writes a synthetic, deterministic 300-device network as `sweepr report` input JSON:
//! a firewall, three switches (one without SNMP), six access points, VLANs 1/10/20/99 and a
//! handful of deliberate risks (Telnet, HTTP-only management, default SNMP community, expired
//! and self-signed certificates, SMB/RDP/VNC exposure, a duplicate IP, phones outside the
//! voice VLAN, an unmanaged switch behind an access port).
//!
//! ```sh
//! cargo run --example sample_audit_input > sample.json
//! sweepr report --input sample.json -o sample.html
//! ```

use serde_json::{json, Value};

/// Tiny deterministic PRNG (xorshift) so the sample is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

const DAY: i64 = 86_400_000;

fn mac(oui: &str, n: u32) -> String {
    format!(
        "{oui}:{:02x}:{:02x}:{:02x}",
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

fn port(switch: &str, ip: &str, p: &str, vlan: u16, m: &str) -> Value {
    json!({ "switchName": switch, "switchIp": ip, "portName": p, "vlanId": vlan, "mac": m })
}

fn main() {
    // Certificate dates are relative to now so expiry findings stay stable over time.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let mut rng = Rng(0x5eed_cafe_f00d);
    let mut devices: Vec<Value> = Vec::new();
    let mut mappings: Vec<Value> = Vec::new();
    let mut n = 0u32;
    let mut next_id = || {
        n += 1;
        n
    };

    // acc-sw-2fl is a 4-member stack polled over SNMP; acc-sw-3fl does not answer SNMP.
    const ACC: (&str, &str) = ("acc-sw-2fl", "10.0.99.3");
    let mut acc_port = 0u32;
    let mut next_acc_port = || {
        acc_port += 1;
        format!(
            "Gi{}/0/{}",
            1 + (acc_port - 1) / 44,
            1 + (acc_port - 1) % 44
        )
    };

    // --- infrastructure (management VLAN 99) ---
    let fw_mac = mac("00:09:0f", next_id());
    devices.push(json!({
        "ip": "10.0.99.1", "mac": fw_mac, "vlanId": 99, "role": "firewall",
        "hostname": "fw-edge-01", "dnsName": "fw-edge-01.corp.example", "vendor": "Fortinet, Inc.",
        "openPorts": [22, 443, 10443], "sources": ["arp", "dns", "tcp"],
        "tlsCert": { "port": 443, "subjectCn": "fw-edge-01.corp.example", "issuerCn": "Corp Issuing CA",
                     "notAfterMs": now_ms + 210 * DAY, "selfSigned": false, "keyType": "RSA", "keyBits": 2048,
                     "signatureAlgorithm": "sha256WithRSAEncryption" },
        "latency": { "avgMs": 0.6, "lossPct": 0.0 }
    }));
    let core_mac = mac("00:1b:54", next_id());
    devices.push(json!({
        "ip": "10.0.99.2", "mac": core_mac, "vlanId": 99, "role": "switch", "hostname": "core-sw1",
        "vendor": "Cisco Systems, Inc", "openPorts": [22, 23, 80], "sources": ["arp", "cdp", "snmp"],
        "neighbor": { "protocol": "cdp", "localInterface": "en0", "sourceMac": core_mac, "deviceId": "core-sw1.corp.example",
                      "systemName": "core-sw1", "platform": "cisco WS-C3850-48P", "portId": "GigabitEthernet1/0/12",
                      "softwareVersion": "Cisco IOS XE Software, Version 16.12.4", "managementAddrs": ["10.0.99.2"],
                      "nativeVlan": 1, "capabilities": ["router", "switch"] }
    }));
    let acc2_mac = mac("00:1b:54", next_id());
    devices.push(json!({
        "ip": "10.0.99.3", "mac": acc2_mac, "vlanId": 99, "role": "switch", "hostname": "acc-sw-2fl",
        "vendor": "Cisco Systems, Inc", "openPorts": [22, 443], "sources": ["arp", "lldp", "snmp"],
        "tlsCert": { "port": 443, "subjectCn": "acc-sw-2fl", "notAfterMs": now_ms + 12 * DAY, "selfSigned": true,
                     "keyType": "RSA", "keyBits": 1024, "signatureAlgorithm": "sha1WithRSAEncryption" }
    }));
    let acc3_mac = mac("94:18:82", next_id());
    devices.push(json!({
        "ip": "10.0.99.4", "mac": acc3_mac, "vlanId": 99, "role": "switch", "hostname": "acc-sw-3fl",
        "vendor": "Hewlett Packard Enterprise", "openPorts": [22, 23, 443], "sources": ["arp", "lldp"]
    }));
    // Access points (self-signed management certificates).
    let mut ap_macs = Vec::new();
    for i in 0..6 {
        let m = mac("24:5a:4c", next_id());
        ap_macs.push(m.clone());
        devices.push(json!({
            "ip": format!("10.0.99.{}", 20 + i), "mac": m, "vlanId": 99, "role": "access_point",
            "hostname": format!("ap-{}fl-{:02}", 2 + i / 3, i % 3 + 1), "vendor": "Ubiquiti Inc",
            "openPorts": [22, 443], "sources": ["arp", "mdns"],
            "tlsCert": { "port": 443, "subjectCn": "UniFi", "notAfterMs": now_ms + 3000 * DAY, "selfSigned": true,
                         "keyType": "RSA", "keyBits": 2048, "signatureAlgorithm": "sha256WithRSAEncryption" }
        }));
        let ap_port = format!("Gi{}/0/45", 1 + i % 4);
        mappings.push(port(ACC.0, ACC.1, &ap_port, 99, &ap_macs[i]));
        // Guest / BYOD wireless clients bridged by the AP.
        for c in 0..(6 + i as u32 * 2) {
            mappings.push(port(
                ACC.0,
                ACC.1,
                &ap_port,
                10,
                &mac("da:a1:19", 0x100 * (i as u32 + 1) + c),
            ));
        }
    }
    // Management servers.
    devices.push(json!({
        "ip": "10.0.99.30", "mac": mac("00:11:32", next_id()), "vlanId": 99, "role": "host", "hostname": "nas-backup",
        "dnsName": "nas-backup.corp.example", "vendor": "Synology Incorporated", "openPorts": [21, 22, 139, 443, 445],
        "tlsCert": { "port": 443, "subjectCn": "nas-backup.corp.example", "issuerCn": "Corp Issuing CA",
                     "notAfterMs": now_ms - 9 * DAY, "notAfter": "2026-09-24T00:00:00Z", "keyType": "RSA", "keyBits": 2048,
                     "signatureAlgorithm": "sha256WithRSAEncryption" },
        "webTitle": "Synology DiskStation"
    }));
    devices.push(json!({
        "ip": "10.0.99.31", "mac": mac("00:50:56", next_id()), "vlanId": 99, "role": "host", "hostname": "jump-01",
        "dnsName": "jump-01.corp.example", "vendor": "VMware, Inc.", "openPorts": [22, 3389, 5900]
    }));
    for (k, d) in devices.iter().enumerate().skip(10) {
        let m = d["mac"].as_str().unwrap().to_string();
        mappings.push(port(
            "core-sw1",
            "10.0.99.2",
            &format!("Gi1/0/{}", 30 + k),
            99,
            &m,
        ));
    }

    // --- VLAN 1 (untagged on the scanner port; native VLAN 1 advertised by core-sw1) ---
    let legacy = [
        ("HP Inc.", "printer"),
        ("Brother Industries, Ltd.", "printer"),
        ("Axis Communications AB", "cam"),
    ];
    for i in 0..16u32 {
        let id = next_id();
        let (vendor, kind) = legacy[(i % 3) as usize];
        let unknown = i >= 12;
        let mut d = json!({
            "ip": format!("10.0.1.{}", 10 + i), "mac": if unknown { mac("02:4e:11", id) } else { mac("00:80:77", id) },
            "role": "host", "interface": "en0", "sources": ["arp"],
            "openPorts": if kind == "printer" { vec![23, 80, 9100] } else { vec![80, 554] },
        });
        if !unknown {
            d["vendor"] = json!(vendor);
            d["hostname"] = json!(format!("{kind}-{:02}", i + 1));
        } else {
            d["openPorts"] = json!([]);
        }
        devices.push(d);
        let m = devices.last().unwrap()["mac"].as_str().unwrap().to_string();
        mappings.push(port(
            "core-sw1",
            "10.0.99.2",
            &format!("Gi1/0/{}", 1 + i),
            1,
            &m,
        ));
    }

    // --- VLAN 20 voice ---
    let mut phones = 0;
    for i in 0..40u32 {
        let id = next_id();
        let m = mac("80:5e:c0", id);
        devices.push(json!({
            "ip": format!("10.0.20.{}", 10 + i), "mac": m, "vlanId": 20, "role": "host",
            "vendor": "Yealink Network Technology Co.,Ltd.", "hostname": format!("SIP-T54W-{:03}", i + 1),
            "openPorts": [80, 443], "voiceVlan": 20
        }));
        // Phone ports are shared with the desk PC (PC passthrough); see below.
        mappings.push(port(ACC.0, ACC.1, &next_acc_port(), 20, &m));
        phones += 1;
    }

    // --- VLAN 10 users ---
    let vendors = [
        ("Dell Inc.", "00:14:22"),
        ("Hewlett Packard", "3c:d9:2b"),
        ("LCFC(HeFei) Electronics Technology co., ltd", "54:e1:ad"),
        ("Apple, Inc.", "f0:18:98"),
        ("Microsoft Corporation", "00:15:5d"),
        ("Intel Corporate", "a4:4c:c8"),
    ];
    let mut user_count = 0;
    let mut wired_pcs = 0u32;
    while devices.len() < 298 {
        let id = next_id();
        let i = user_count;
        user_count += 1;
        let (vendor, oui) = vendors[rng.below(vendors.len() as u64) as usize];
        let randomized = rng.chance(6);
        let m = if randomized {
            mac("ce:7a:30", id)
        } else {
            mac(oui, id)
        };
        let mut ports = vec![];
        let windows = vendor != "Apple, Inc." && rng.chance(70);
        if windows {
            ports.push(445);
            if rng.chance(18) {
                ports.push(139);
            }
            if rng.chance(5) {
                ports.push(3389);
            }
        } else if rng.chance(30) {
            ports.push(22);
        }
        let ip = format!("10.0.{}.{}", 10 + i / 250, 10 + i % 250);
        let mut d = json!({ "ip": ip, "mac": m, "vlanId": 10, "role": "host", "openPorts": ports,
                            "sources": ["arp", "tcp"] });
        if !randomized {
            d["vendor"] = json!(vendor);
        }
        if rng.chance(80) {
            d["dnsName"] = json!(format!("ws-{:04}.corp.example", 1000 + i));
        } else if windows && rng.chance(60) {
            d["smbName"] = json!(format!("LAPTOP-{:05X}", rng.below(0xfffff)));
        }
        if rng.chance(10) {
            d["latency"] = json!({ "avgMs": 1.0 + rng.below(400) as f64 / 10.0, "lossPct": rng.below(4) as f64 });
        }
        devices.push(d);
        // A third of the users are on Wi-Fi (behind the APs), the rest wired; the first 40
        // wired PCs sit behind the IP phones' passthrough ports.
        if rng.chance(33) {
            let ap = (i % 6) as usize;
            mappings.push(port(
                ACC.0,
                ACC.1,
                &format!("Gi{}/0/45", 1 + ap % 4),
                10,
                &m,
            ));
        } else if wired_pcs < 40 {
            mappings.push(port(
                ACC.0,
                ACC.1,
                &format!("Gi{}/0/{}", 1 + wired_pcs / 44, 1 + wired_pcs % 44),
                10,
                &m,
            ));
            wired_pcs += 1;
        } else {
            mappings.push(port(ACC.0, ACC.1, &next_acc_port(), 10, &m));
        }
        // Misplaced phones in the data VLAN.
        if i % 40 == 7 && phones < 48 {
            let id = next_id();
            let pm = mac("80:5e:c0", id);
            devices.push(json!({ "ip": format!("10.0.11.{}", 10 + phones - 40), "mac": pm, "vlanId": 10, "role": "host",
                                 "vendor": "Yealink Network Technology Co.,Ltd.", "openPorts": [80] }));
            phones += 1;
        }
    }
    // Duplicate IP (two MACs claim 10.0.10.10) and an ARP-spoofing-like MAC.
    devices.push(json!({ "ip": "10.0.10.250", "mac": "00:14:22:aa:bb:cc", "vlanId": 10, "role": "host",
                         "vendor": "Dell Inc.", "extraIps": ["10.0.10.10"], "dnsName": "ws-rogue.corp.example" }));
    devices.push(json!({ "ip": "10.0.10.251", "mac": "00:14:22:aa:bb:cc", "vlanId": 10, "role": "host", "vendor": "Dell Inc." }));
    // Unmanaged switch behind an access port.
    for c in 0..6 {
        mappings.push(port(
            ACC.0,
            ACC.1,
            "Gi4/0/44",
            10,
            &mac("00:e0:4c", 0x9000 + c),
        ));
    }
    // Uplinks: core <-> access switches carry every MAC from below.
    let all_macs: Vec<String> = devices
        .iter()
        .filter_map(|d| d["mac"].as_str().map(str::to_string))
        .collect();
    for (k, m) in all_macs.iter().enumerate() {
        let up = if k % 2 == 0 { "Te1/1/1" } else { "Te1/1/2" };
        mappings.push(port("core-sw1", "10.0.99.2", up, 10, m));
    }
    mappings.push(port(ACC.0, ACC.1, "Te1/1/1", 99, &core_mac));
    mappings.push(port(ACC.0, ACC.1, "Te1/1/1", 99, &fw_mac));
    mappings.push(port("core-sw1", "10.0.99.2", "Gi1/0/48", 99, &fw_mac));

    // Switch ports for every device mapped above (endpoint -> access port).
    for d in devices.iter_mut() {
        let Some(m) = d["mac"].as_str().map(str::to_string) else {
            continue;
        };
        let pm = mappings
            .iter()
            .find(|p| p["mac"] == m.as_str() && !p["portName"].as_str().unwrap().starts_with("Te"));
        if let Some(pm) = pm.filter(|_| d["role"] == "host" || d["role"] == "access_point") {
            d["switchPort"] = pm.clone();
        }
    }

    let vlan = |id: u16, name: &str, sources: &[&str]| json!({ "id": id, "name": name, "sources": sources, "switchName": "core-sw1" });
    let snmp_vlans = vec![
        vlan(1, "default", &["snmp"]),
        vlan(10, "users", &["snmp"]),
        vlan(20, "voice", &["snmp"]),
        vlan(30, "old-guest", &["snmp"]),
        vlan(40, "lab", &["snmp"]),
        vlan(99, "mgmt", &["snmp"]),
        vlan(1002, "fddi-default", &["vtp"]),
    ];
    let core_maps: Vec<Value> = mappings
        .iter()
        .filter(|p| p["switchName"] == "core-sw1")
        .cloned()
        .collect();
    let acc2_maps: Vec<Value> = mappings
        .iter()
        .filter(|p| p["switchName"] == "acc-sw-2fl")
        .cloned()
        .collect();
    let out = json!({
        "meta": {
            "toolVersion": "SweepR 0.1.0", "interface": "en0", "ranges": ["10.0.0.0/16"],
            "vlans": "untagged,10,20,99", "portSpec": "21,22,23,80,139,443,445,554,3389,5900,8443,9100,10443",
            "startedMs": now_ms - 7 * 60_000, "finishedMs": now_ms - 7 * 60_000 + 263_000,
            "cdpLldp": true, "ipv6": false, "resolveNames": true,
            "snmp": { "version": "v2c", "community": "public" }, "scannerHost": "audit-mbp"
        },
        "devices": devices,
        "vlans": snmp_vlans.iter().cloned().chain([json!({ "id": 10, "sources": ["tagged8021q"], "interface": "en0.10" })]).collect::<Vec<_>>(),
        "neighbors": [
            devices[1]["neighbor"].clone(),
            { "protocol": "lldp", "localInterface": "en0.10", "sourceMac": acc2_mac, "deviceId": "acc-sw-2fl",
              "systemName": "acc-sw-2fl.corp.example", "platform": "Cisco C9200L-48P-4X",
              "systemDescription": "Cisco IOS XE Software, Version 17.6.4", "portId": "Gi1/0/21",
              "managementAddrs": ["10.0.99.3"], "nativeVlan": 10, "voiceVlan": 20, "capabilities": ["switch"] }
        ],
        "portMappings": mappings,
        "snmpInfos": [
            { "ip": "10.0.99.2", "sysName": "core-sw1", "role": "switch",
              "sysDescr": "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4",
              "vlans": snmp_vlans, "portMappings": core_maps },
            { "ip": "10.0.99.3", "sysName": "acc-sw-2fl", "role": "switch", "sysDescr": "Cisco IOS XE Software, C9200L",
              "partial": true, "warnings": ["dot1qTpFdbTable walk stopped after 2000 ms deadline"],
              "vlans": [vlan(10, "users", &["snmp"]), vlan(20, "voice", &["snmp"]), vlan(99, "mgmt", &["snmp"])],
              "portMappings": acc2_maps }
        ]
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serializable")
    );
    eprintln!("{} devices", out["devices"].as_array().map_or(0, Vec::len));
}
