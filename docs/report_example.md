# External Asset Report Format (Spec)

Use this structure for host-level recon and vulnerability reporting.

---

### exchange-alpha.example.com (203.0.113.45)

**DNS**
- A -> 203.0.113.45
- AAAA -> 2001:db8::45
- CNAME -> exchange-alpha.o365.example.com
- PTR -> mail-edge-01.example.com
- Also resolves: exchange.example.com, autodiscover.example.com

**Open Ports**
- 80/tcp - http - nginx 1.24.0 (redirects -> 443)
- 443/tcp - https - nginx 1.24.0 (TLS 1.2/1.3, cert CN=*.example.com, expires 2026-11-14)
- 25/tcp - smtp - Exchange 2019 CU13
- 587/tcp - submission - Exchange 2019 CU13
- 993/tcp - imaps - Exchange 2019 CU13

**Discovered URL Paths** (443/tcp)

| Path | Status | Title / Notes | Notable |
|---|---:|---|---|
| / | 403 | nginx default deny | |
| /owa/ | 302 | -> /owa/auth/logon.aspx | |
| /owa/auth/logon.aspx | 200 | Outlook Web App sign-in | ★ banner leak |
| /ecp/ | 302 | -> /ecp/Default.aspx (admin panel) | ★ exposed |
| /autodiscover/autodiscover.xml | 401 | Exchange Autodiscover | |
| /ews/exchange.asmx | 401 | Exchange Web Services | |
| /mapi/ | 401 | MAPI over HTTP | |
| /rpc/rpcproxy.dll | 401 | Outlook Anywhere | |
| /aspnet_client/ | 403 |  | |
| /.well-known/security.txt | 404 | missing | |
| /api/v2/health | 200 | custom health endpoint | ★ unique headers |

**Path Detail - Unique Headers**

`/api/v2/health` returned a non-standard header set that differs from the rest of the host (`nginx`-default). This likely indicates a bypassed reverse proxy route or a misrouted internal service.

```http
HTTP/1.1 200 OK
Server: Kestrel
X-Powered-By: ASP.NET Core 6.0
X-Internal-Node: mbx-ic-03.corp.example.local
X-Request-Id: 7f3a1c88-2e44-4a9b-9d21-b0c1e6f2d111
X-Debug-Build: exchange-health-probe-v1.4.2-DEBUG
Access-Control-Allow-Origin: *
Cache-Control: no-store
Content-Type: application/json
```

**Observations**
- `X-Internal-Node` leaks internal hostname + AD domain (`corp.example.local`).
- `X-Debug-Build` indicates a debug build running in production.
- `Access-Control-Allow-Origin: *` on an authenticated host is a CORS concern.
- `Server: Kestrel` confirms this path bypasses the nginx fronting other routes, suggesting a direct `proxy_pass` to an internal .NET service.

**Host Metadata**
- ASN: AS64500 (CAMPUSCLOUD-NET)
- Hosting: Self-hosted (on-prem edge)
- Tech stack: Microsoft Exchange 2019, nginx reverse proxy, Windows Server 2019, ASP.NET Core 6.0 (on `/api/v2/health`)
- First seen: 2025-08-12
- Last seen: 2026-04-08
- Tags: mail, production, internet-facing

**Findings Attached**
- F-007 (Medium) - Exchange OWA exposes version banner in `/owa/auth/logon.aspx`
- F-012 (Low) - TLS 1.2 enabled alongside 1.3 (policy prefers 1.3-only)
- F-018 (High) - `/api/v2/health` leaks internal hostname, debug build, wildcard CORS
- F-019 (Medium) - `/ecp/` admin panel reachable from the internet

**Validation / Re-test Commands**

```bash
# Confirm host still live
httpx -u https://exchange-alpha.example.com -title -tech-detect -status-code

# Re-probe the unique-header path
curl -skI https://exchange-alpha.example.com/api/v2/health

# Re-crawl for new paths
katana -u https://exchange-alpha.example.com -jc -d 3 -silent

# Re-scan for vulns
nuclei -u https://exchange-alpha.example.com -severity medium,high,critical

# Port re-verification
nmap -Pn -sV -p25,80,443,587,993 exchange-alpha.example.com
```
