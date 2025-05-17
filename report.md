# FARSIGHT Reconnaissance Report
            
## Target: example.com
**Scan Date:** 2025-05-17 18:15:16
**Scan Depth:** 1
**Modules Run:** org, recon, threat

---
## Executive Summary

This report presents the findings from a reconnaissance scan of **example.com**.

- **14** domains/subdomains discovered
- **2** open ports found
- **Well-protected** email security posture


---
## Organization & Domain Discovery

### WHOIS Information
```
Domain: example.com
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation_date: 1995-08-14 04:00:00
Expiration_date: 2025-08-13 04:00:00
Updated_date: 2024-08-14 07:01:34
Name_servers: A.IANA-SERVERS.NET, B.IANA-SERVERS.NET
Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited, clientTransferProhibited https://icann.org/epp#clientTransferProhibited, clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
```


### Discovered Domains (14)
```
*.example.com
*.hosted.jivesoftware.com
*.uat3.hosted.jivesoftware.com
AS207960 Test Intermediate - example.com
dev.example.com
example.com
products.example.com
support.example.com
www.example.com
example.com
example.com
example.com
example.com
example.com
m.example.com
www.example.com
example.com
m.testexample.com
www.example.com
example.com
user@example.com
example.com
www.example.com
subjectname@example.com
www.example.com
www.example.org
```


### Certificate Transparency Data
Domains found in certificate transparency logs:

```
dev.example.com
example.com
products.example.com
support.example.com
www.example.com
example.com
example.com
www.example.com
example.com
example.com
m.example.com
www.example.com
*.uat3.hosted.jivesoftware.com
example.com
user@example.com
example.com
m.testexample.com
www.example.com
*.hosted.jivesoftware.com
www.example.org
example.com
example.com
*.example.com
www.example.com
subjectname@example.com
AS207960 Test Intermediate - example.com
```


---
## Reconnaissance & Asset Discovery

### DNS Records
### DNS Records

#### example.com

**A Records:**

| Type | Data |
|------|------|
| A | 96.7.128.198 |
| A | 23.215.0.138 |
| A | 23.215.0.136 |
| A | 23.192.228.84 |
| A | 23.192.228.80 |
| A | 96.7.128.175 |

**MX Records:**

| Type | Data |
|------|------|
| MX | 0 . |

**NS Records:**

| Type | Data |
|------|------|
| NS | N/A |
| NS | N/A |

**TXT Records:**

| Type | Data |
|------|------|
| TXT | "v=spf1 -all" |
| TXT | "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9" |

**CNAME Records:**

No records found.



### Subdomains Discovered
Total subdomains discovered: **1**

```
www.example.com
```


### Port Scan Results
Target IP: **96.7.128.198**

| Port | Service | Banner |
|------|---------|--------|
| 80 | HTTP |  |
| 443 | HTTPS |  |


### Email Security Assessment
#### Email Security Findings

**SPF Record:** ✅ Implemented

```
v=spf1 -all
```

**DMARC Record:** ✅ Implemented

```
v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
```

**Recommendations:**

- Email security is well-configured

---
## Threat Intelligence

### Data Leaks & Breaches
No data leaks or breaches found.

### Dark Web Mentions
No dark web mentions found.

### Exposed Credentials
No exposed credentials found.

---
## About This Report

This report was generated automatically by FARSIGHT v0.1.0 on 2025-05-17 18:15:16.

All data in this report is presented for informational purposes only.
