# Host Security Assessment Report

### <host.fqdn> (<primary_ip>)

**DNS**
- A -> <ipv4>
- AAAA -> <ipv6>
- CNAME -> <cname_target>
- PTR -> <ptr_record>
- Also resolves: <alt_host_1>, <alt_host_2>

**Open Ports**
- <port/proto> - <service> - <product/version and relevant notes>
- <port/proto> - <service> - <product/version and relevant notes>

**Discovered URL Paths** (<service_port>)

| Path | Status | Title / Notes | Notable |
|---|---:|---|---|
| / | 200 | <title> | |

**Path Detail - <focus area>**

`<path>` returned notable behavior compared to the host baseline.

```http
HTTP/1.1 <status>
<headers>
```

**Observations**
- <observation 1>
- <observation 2>
- <observation 3>

**Host Metadata**
- ASN: <asn>
- Hosting: <hosting>
- Tech stack: <stack>
- First seen: <yyyy-mm-dd>
- Last seen: <yyyy-mm-dd>
- Tags: <tag1>, <tag2>

**Findings Attached**
- <finding_id> (<severity>) - <short description>
- <finding_id> (<severity>) - <short description>

**Validation / Re-test Commands**

```bash
# Confirm host live + headers
httpx -u https://<host.fqdn> -title -tech-detect -status-code

# Re-check high-value path
curl -skI https://<host.fqdn>/<path>

# Re-crawl
katana -u https://<host.fqdn> -jc -d 3 -silent

# Re-scan vuln templates
nuclei -u https://<host.fqdn> -severity medium,high,critical

# Port verification
nmap -Pn -sV -p<ports> <host.fqdn>
```

---

CLI usage from Autotron:

```bash
# Print markdown report for one host
go run ./cmd/asm report --host <host.fqdn>

# Write report to file
go run ./cmd/asm report --host <host.fqdn> --out reports/<host.fqdn>.md

# Strict mode (fail if no graph data for host)
go run ./cmd/asm report --host <host.fqdn> --strict

# Top correlated findings with filters
go run ./cmd/asm report --top 50 --severity high --confidence confirmed
go run ./cmd/asm report --tool nuclei --since 2026-04-01

# JSON output (host report)
go run ./cmd/asm report --host <host.fqdn> --json

# JSON output (top findings view)
go run ./cmd/asm report --top 100 --json --severity medium

# Preferred format flag
go run ./cmd/asm report --top 25 --format json
go run ./cmd/asm report --host <host.fqdn> --format markdown

# Save to default path under reports/
go run ./cmd/asm report --host <host.fqdn> --save
go run ./cmd/asm report --top 50 --format json --save
```
