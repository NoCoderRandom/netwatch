# NetWatch Session Log

Read this at the start of every session to understand where we left off.
Also check: prompts/ directory for planned work.

---

## Session — 2026-04-04 (Part 1): Device Identification Engine (BUILT)

### What was done

Built a complete **Device Identification Engine** that fuses evidence from
12 sources into a unified `DeviceIdentity` (vendor, model, version,
device_type, confidence) per scanned host.

### New files created
| File | Purpose |
|------|---------|
| `core/device_identifier.py` | Main engine — `DeviceIdentifier` class, `DeviceIdentity` dataclass, 12 extractors, weighted fusion algorithm |
| `data/device_aliases.json` | 115 vendor name normalizations (e.g. "Synology Inc." -> "Synology") |

### Files modified
| File | Change |
|------|--------|
| `netwatch.py` | Import DeviceIdentifier, instantiate in __init__, run identification loop after security checks in run_security_checks(), emit INFO finding per identified host, pass device_identities to export_html() calls |
| `core/module_manager.py` | Added `mac-oui` module to MODULE_REGISTRY (IEEE OUI CSV, 4MB, default=True), added `_parse_mac_oui()` parser, registered in `_PARSERS` dict |
| `ui/export.py` | Added `device_identities` parameter to `export_html()`, `export_json()`, `_generate_html()`, `_render_jinja()`, and `export()`. Passes dict to Jinja template. Adds `device_identities` section to JSON export. |
| `ui/templates/report.html.j2` | Added CSS for device identity display. Topology cards show device type/vendor/model when identified. New "Device Inventory" table section between topology and findings. Host headers show identified device name. Host meta section has styled identity badge with confidence. |

---

## Session — 2026-04-04 (Part 2): Sessions 02–04 Executed

### What was done

Executed all four planned prompt sessions (01 was done in Part 1, 02–04
done here). The Device Identification Engine was expanded from 12 to 14
extractors, pattern databases were tripled in size, confidence tuning was
added, terminal display was built, and a new `--identify` CLI flag was added.

### Session 02: JA3S + FTP + HTTP Raw Headers

Added to `core/device_identifier.py`:
- **NEW `_extract_from_ja3s()`** — imports `get_last_ja3s_match` from ssl_checker, checks all open ports for JA3S matches, maps app names via `_JA3S_APP_PATTERNS` (16 patterns). Confidence: 0.5
- **NEW `_extract_from_ftp_banner()`** — checks FTP service banners for server software (vsFTPd, ProFTPD, PureFTPd, FileZilla, Microsoft FTP, wu-ftpd) via `_FTP_BANNER_PATTERNS` (6 patterns). Extracts version. Confidence: 0.25–0.35
- **IMPROVED `_extract_from_http_fingerprint()`** — now also reads `fp.raw_headers`, runs `_HTTP_SERVER_PATTERNS` against Server header, checks X-Powered-By/X-Generator/X-Served-By. Returns list of evidence instead of single item.
- **IMPROVED `_extract_from_http_server_headers()`** — falls back to `port_info.http_fingerprint.raw_headers["Server"]` when banner/version are empty

### Session 03: Credentials Model Index + Pattern Expansion

Added to `core/device_identifier.py`:
- **Model-vendor reverse index** — lazy-loads `default_credentials.json`, builds 31-entry `{model -> vendor}` dict. After fusion, if model is recognized but vendor missing/agrees, vendor is set/boosted by 0.3 confidence.
- **`_SSH_BANNER_PATTERNS`** expanded: 9 → 19 patterns. Added ROSSSH, HUAWEI, Comware, LANCOM, Sun_SSH, Serv-U, WeOnlyDo, dropbear version, OpenSSH version, honeypot.
- **`_HTTP_SERVER_PATTERNS`** expanded: 23 → 38 patterns. Added ASUSRT, WatchGuard, SonicWALL, Zyxel, Aruba, Grandstream, Polycom, Yealink, NETGEAR, TP-LINK, D-Link, RomPager, WebIOPi, AkamaiGHost.
- **`_CERT_PATTERNS`** expanded: 18 → 28 patterns. Added Netgear, TP-Link, ASUS, D-Link, Linksys, WatchGuard, SonicWall, Sophos, pfSense, Grandstream.
- **`_PORT_DEVICE_HINTS`** expanded: 21 → 31 rules. Added MikroTik combo, SIP, IPsec, Proxmox, Kubernetes, Prometheus/Cockpit, Plex, Jellyfin, WireGuard, OpenVPN.
- **`data/device_aliases.json`** expanded: 117 → 134 entries. Added WatchGuard, SonicWall, Zyxel, Grandstream, Polycom, Yealink, LANCOM, HPE/H3C, Oracle.

### Session 04: Terminal Display + Confidence Tuning + --identify

Added/changed in `netwatch.py`:
- **`_print_device_id_table()`** — Rich Table with columns IP, Type, Vendor, Model, Version, Conf%. Color-coded: green >=70%, yellow 40-69%, dim <40%. Printed after device identification loop.
- **Per-host check line enrichment** — "✓ 192.168.50.1 — Router — ASUS RT-AX88U" instead of "Checked 192.168.50.1". Uses `identify_preliminary()`.
- **`--identify` CLI flag** — runs scan + banners + device identification only (no security checks). New `run_identify_only()` method. Added to `create_parser()` and `main()`.
- **`identify_preliminary()`** added to DeviceIdentifier — runs 9 host-local extractors without needing findings (MAC, nmap, HTTP fingerprint, banners, ports, nmap services, JA3S, FTP).

Added to `core/device_identifier.py` fusion:
- **Agreement bonus** — N distinct sources agreeing multiplies confidence by `(1 + 0.1 * (N-1))`
- **Conflict penalty** — competing values reduce winner by `loser_total * 0.3`
- **Threshold raised** — field minimum from 0.1 to 0.15

### Current extractor count: 14
| # | Extractor | Source | Confidence |
|---|-----------|--------|-----------|
| 1 | `_extract_from_mac_oui` | MAC address / OUI DB | 0.40–0.45 |
| 2 | `_extract_from_nmap_os` | nmap OS fingerprint | varies |
| 3 | `_extract_from_http_fingerprint` | HttpFingerprint + raw_headers | 0.50+ |
| 4 | `_extract_from_http_server_headers` | HTTP Server header / banner | 0.20–0.50 |
| 5 | `_extract_from_tls_cert` | TLS certificate CN/issuer | 0.35 |
| 6 | `_extract_from_ssh_banner` | SSH banner | 0.10–0.70 |
| 7 | `_extract_from_upnp` | UPnP discovery | 0.75 |
| 8 | `_extract_from_snmp` | SNMP sysDescr | 0.85 |
| 9 | `_extract_from_wappalyzer` | Wappalyzer CPE/categories | 0.30–0.45 |
| 10 | `_extract_from_mdns` | mDNS/Zeroconf | 0.55 |
| 11 | `_extract_from_port_heuristics` | Open port combos | 0.10–0.70 |
| 12 | `_extract_from_nmap_service_info` | nmap service fields | 0.45 |
| 13 | `_extract_from_ja3s` | JA3S TLS fingerprint | 0.50 |
| 14 | `_extract_from_ftp_banner` | FTP server banner | 0.25–0.35 |

### Pattern database sizes
| Pattern List | Count |
|-------------|-------|
| `_SSH_BANNER_PATTERNS` | 19 |
| `_HTTP_SERVER_PATTERNS` | 38 |
| `_CERT_PATTERNS` | 28 |
| `_OS_GUESS_PATTERNS` | 15 |
| `_JA3S_APP_PATTERNS` | 16 |
| `_FTP_BANNER_PATTERNS` | 6 |
| `_PORT_DEVICE_HINTS` | 31 |
| `device_aliases.json` | 134 |

### External data sources verified (2026-04-04)
All 10 external sources return HTTP 200 (OSV returns 405 for GET as expected — it requires POST):
endoflife.date API, OSV.dev, NVD API, SecLists (x2), DefaultCreds, webappanalyzer, salesforce/ja3, many-passwords, IEEE OUI.

---

## Known Gaps — Addressed by New Prompts (prompts/01–03)

Analysis performed 2026-04-04. These are the remaining improvements:

1. **Identity→EOL bridge is missing** — Device identification finds "Synology NAS v7.2" but the EOL checker never checks synology-dsm 7.2 against endoflife.date. The two pipelines don't talk to each other. (prompt 01)

2. **HTTP fingerprint firmware versions not checked for EOL** — HttpFingerprint.firmware_version is read by device identifier but never fed to EOL checker. (prompt 01)

3. **QUICK scan profile missing `-sV`** — Default scan gets no version data from nmap, limiting both EOL and identification. (prompt 02)

4. **SNMP sysDescr patterns limited** — Only 15 patterns. Missing Fortinet, WatchGuard, SonicWall, Aruba, Huawei, HP iLO, Dell iDRAC, and others. (prompt 02)

5. **SSH banner OS version not extracted for EOL** — Banners like "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" contain embedded OS+version but this is not piped to EOL. (prompt 02)

6. **Consumer router/camera EOL not available upstream** — endoflife.date doesn't track MikroTik, Ubiquiti, Netgear, D-Link, TP-Link, ASUS, Hikvision, Dahua. NOT_TRACKED_PRODUCTS skips them. No code fix possible without a custom EOL data source. (documented, not in prompts)

7. **No device identification in interactive menu** — No "Device Inventory" option, no way to run --identify from the menu. (prompt 03)

8. **README does not document device identification** — The --identify flag, device identification engine, and new pattern databases are not in the README. (prompt 03)

### How to use the new prompts
```
prompts/01_identity_eol_bridge.txt        → Connect identification to EOL checking
prompts/02_version_detection_expansion.txt → Better version extraction + SNMP + scan profiles
prompts/03_ui_readme_polish.txt           → Interactive menu + README + console UX
```
Each prompt is ~70% of a session. Do them in order.

### Version
All changes are on top of v1.7.0 (commit 80adc71). Not yet committed.
