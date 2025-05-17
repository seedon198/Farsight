# FARSIGHT Reconnaissance Report
            
## Target: nmap.org
**Scan Date:** 2025-05-17 18:22:46
**Scan Depth:** 1
**Modules Run:** recon, org, typosquat

---
## Executive Summary

This report presents the findings from a reconnaissance scan of **nmap.org**.

- **7** domains/subdomains discovered
- **4** open ports found
- **Partially protected** email security posture
- **0** typosquatting domains detected

---
## Organization & Domain Discovery

### WHOIS Information
```
Domain: nmap.org
Registrar: DYNADOT LLC
Creation_date: 1999-01-18 05:00:00
Expiration_date: 2029-01-18 05:00:00
Updated_date: 2023-08-31 05:05:15, 2023-08-26 05:16:38
Name_servers: ns1.linode.com, ns2.linode.com, ns3.linode.com, ns4.linode.com, ns5.linode.com
Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Emails: abuse@dynadot.com
Org: Super Privacy Service LTD c/o Dynadot
```


### Discovered Domains (7)
```
insecure.com
issues.nmap.org
nmap.org
svn.nmap.org
www.nmap.org
nmap.org
nmap.org
www.nmap.org
svn.nmap.org
svn.nmap.org
www.svn.nmap.org
www.nmap.org
```


### Certificate Transparency Data
Domains found in certificate transparency logs:

```
issues.nmap.org
nmap.org
svn.nmap.org
www.nmap.org
insecure.com
svn.nmap.org
www.svn.nmap.org
www.nmap.org
nmap.org
nmap.org
www.nmap.org
svn.nmap.org
```


---
## Reconnaissance & Asset Discovery

### DNS Records
### DNS Records

#### nmap.org

**A Records:**

| Type | Data |
|------|------|
| A | 50.116.1.184 |

**MX Records:**

| Type | Data |
|------|------|
| MX | 10 ASPMX3.GOOGLEMAIL.COM. |
| MX | 10 ASPMX2.GOOGLEMAIL.COM. |
| MX | 1 ASPMX.L.GOOGLE.COM. |
| MX | 5 ALT1.ASPMX.L.GOOGLE.COM. |
| MX | 5 ALT2.ASPMX.L.GOOGLE.COM. |

**NS Records:**

| Type | Data |
|------|------|
| NS | N/A |
| NS | N/A |
| NS | N/A |
| NS | N/A |
| NS | N/A |

**TXT Records:**

| Type | Data |
|------|------|
| TXT | "v=spf1 a mx ptr ip4:50.116.1.184 ip6:2600:3c01::f03c:91ff:fe98:ff4e ip6:2600:3c01:e000:3e6::6d4e:7061 include:_spf.google.com ~all" |
| TXT | "google-site-verification=SrtYpJGxZzMTcczZG44XtLVK-sEPit9bputDjWc0lF4" |

**CNAME Records:**

No records found.



### Subdomains Discovered
Total subdomains discovered: **15**

```
admin.nmap.org
blog.nmap.org
dev.nmap.org
mail.nmap.org
ns1.nmap.org
ns2.nmap.org
remote.nmap.org
secure.nmap.org
server.nmap.org
smtp.nmap.org
staging.nmap.org
test.nmap.org
vpn.nmap.org
webmail.nmap.org
www.nmap.org
```


### Port Scan Results
Target IP: **50.116.1.184**

| Port | Service | Banner |
|------|---------|--------|
| 22 | SSH | SSH-2.0-OpenSSH_7.4 |
| 25 | SMTP | 220 ack.nmap.org ESMTP Postfix |
| 80 | HTTP |  |
| 443 | HTTPS |  |


### Email Security Assessment
#### Email Security Findings

**SPF Record:** ✅ Implemented

```
v=spf1 a mx ptr ip4:50.116.1.184 ip6:2600:3c01::f03c:91ff:fe98:ff4e ip6:2600:3c01:e000:3e6::6d4e:7061 include:_spf.google.com ~all
```

**DMARC Record:** ❌ Not implemented

**Recommendations:**

- Implement DMARC to improve email security and receive reports on email authentication

---
## Typosquatting Analysis

### Detected Typosquats (0)
No typosquatting domains detected.

---
## About This Report

This report was generated automatically by FARSIGHT v0.1.0 on 2025-05-17 18:22:46.

All data in this report is presented for informational purposes only.
