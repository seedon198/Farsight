# FARSIGHT Reconnaissance Report
            
## Target: sony.com
**Scan Date:** 2025-05-17 18:54:31
**Scan Depth:** 1
**Modules Run:** org, news, recon

---
## Executive Summary

This report presents the findings from a reconnaissance scan of **sony.com**.

- **1** domains/subdomains discovered
- **2** open ports found
- **Well-protected** email security posture


---
## Organization & Domain Discovery

### WHOIS Information
```
Domain: sony.com
Registrar: CSC CORPORATE DOMAINS, INC.
Creation_date: 1989-07-07 04:00:00, 1989-07-07 00:00:00
Expiration_date: 2026-07-06 04:00:00
Updated_date: 2024-07-02 05:19:43, 2024-07-02 01:19:43
Name_servers: PDNS1.CSCDNS.NET, PDNS2.CSCDNS.NET, pdns2.cscdns.net, pdns1.cscdns.net
Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited, serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited, serverTransferProhibited https://icann.org/epp#serverTransferProhibited, serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited, clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited, serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited, serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited, serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited
Emails: domainabuse@cscglobal.com, hostmaster@sony.com, dns-admin@cscglobal.com
Org: Sony Corporation of America
```


### Discovered Domains (1)
```
sony.com
```


### Certificate Transparency Data
No certificate transparency data available.

---
## Reconnaissance & Asset Discovery

### DNS Records
### DNS Records

#### sony.com

**A Records:**

| Type | Data |
|------|------|
| A | 52.6.127.76 |
| A | 44.218.59.236 |

**MX Records:**

| Type | Data |
|------|------|
| MX | 10 mxa-001d1709.gslb.pphosted.com. |
| MX | 10 mxb-001d1709.gslb.pphosted.com. |

**NS Records:**

| Type | Data |
|------|------|
| NS | N/A |
| NS | N/A |

**TXT Records:**

| Type | Data |
|------|------|
| TXT | "0ed1fe018ab8b5050c7c8341b7b8894557d2554815" |
| TXT | "3107e583-6c54-414f-8708-dadd2b68db17" |
| TXT | "Dynatrace-site-verification=1babd889-fadb-4ff7-8463-0980d5597143__9c12rjohn2l0ijdaaalvihrite" |
| TXT | "MFC=2c04db9e-a7b5-4b3c-a971-b8dbf1e148b3" |
| TXT | "MS=ms30214679" |
| TXT | "SSI-BOX-verification=3005070" |
| TXT | "YzcX/ANAcVb1c6oLNOXQzniFpgGypdlowJHvEvmRuqyhkvEsdv/zFQuiZuYakJL3xpHMmttCjOvNqxz3g+LFeg==" |
| TXT | "ZOOM_verify_rEu3V6YvT3iT4iHJy6N2TQ" |
| TXT | "_cbc-idp-site-verification-bd1686=65b56d227485091e0ac07e8998080a9543f122a1b04435ee76d25e4f752c9050" |
| TXT | "_cbc-idp-site-verification-fde40b=9081ffc73c90ac585fa7d9769b63215689408840dded54e7256c7e19360fe758" |
| TXT | "_tl13flz107h4rbful1ic34v8450rf60" |
| TXT | "adobe-idp-site-verification=cff4ddad-a01e-4226-a77f-8c081cde0aee" |
| TXT | "adobe-sign-verification=b4a30c4f74bb611dce0e5d515054481c" |
| TXT | "adobe-sign-verification=d9afcd8ad833d41a47f92fec1bf30bf5" |
| TXT | "amazonses:OfVkq/yn1d+o09tdXhxkoHbIGCNeP8aYj3amzwACQ3c=" |
| TXT | "amazonses:uiKa9HJAcBY9FnqDkcA2neYsNY7672GwLqmefcFcEeo=" |
| TXT | "apple-domain-verification=HBPp89XmNImI9Qwc" |
| TXT | "apple-domain-verification=nb7VlmdSF87vwM2c" |
| TXT | "apple-domain-verification=t838FSLg4LjXckfk" |
| TXT | "atlassian-domain-verification=/PaoSe8zbFJuWVCT7GftJBGp94eYcxfj63DrEJ1FwO9TWOypzG5iRIPdvIuayCEg" |
| TXT | "atlassian-domain-verification=952mPCXTF37KezRl6E/Bi2/ZatxPM1gKFPIf4MXehRtaz9DKajMnwKdtPvWhDT0/" |
| TXT | "atlassian-domain-verification=J8IuFHzPA35SrowKp4YTkNaH2y55875Vd4ajfcdSaa8IwFnHFgwDVXn/7ah4zKLQ" |
| TXT | "atlassian-domain-verification=wQ8HCOCZf3qKkVA9AJLbklKI2Vg3gLMCLGjitCRrWNPdK2uOnnud6x8IJ8KES8BC" |
| TXT | "atlassian-domain-verification=waYuW8HMlUW/U3Dv4MxS16bX0nEfYNpuqW5c18LpYhqHUi280snd3mDAQFwjkAzx" |
| TXT | "cisco-ci-domain-verification=221d305d2b1221f9d96ea9cde0d89df2a2ddc44fef8454a724e1a22dd27bd782" |
| TXT | "cisco-ci-domain-verification=63d5c7eae53960e203dc78b5f8df051547793ec65388f2b6c981213444854fa2" |
| TXT | "cloudhealth=ef6859d5-232b-4ff0-8811-ded26d79e7ee" |
| TXT | "docusign=3122656f-b5f7-497b-8782-4907222b538a" |
| TXT | "docusign=877ac654-f0e6-4bc6-a293-49c26778da82" |
| TXT | "duo_sso_verification=OCP7uIMPOgLi1G6lzhe7ytJ1mlBnCnegPoARYrbP5iaQz1lbBdgKOs7mxHqm6pMC" |
| TXT | "facebook-domain-verification=rn9nh6m7g7sxesufnk7gufxr7pht73" |
| TXT | "fastly-domain-delegation-sony-323730-2020-12-07" |
| TXT | "google-site-verification=j1FfNnOllL0QdFSzHNHnHAcWV_54Kbd_bURGKTK3y4s" |
| TXT | "google-site-verification=zfXryc1xAcIFps86mXmIJrDtpsur406Wn-pOMSS0i5w" |
| TXT | "include:5133606.spf02.hubspotemail.net" |
| TXT | "intersight=e96be0bed3c84c3117ce32993955e9a8179f4a21ef59509de20f1b5beb03b23b" |
| TXT | "k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBfF8XiPmS/aLbBcNnixpRclWpr1Z0MY4Hy9h3oW4VF6XDJaKhmTWkaOvKIv3ZMQyjIrbpmBwL0xiyy3F88HwPi9tA7POXgpsl12W3EXu2qzOHhMvpT7VZC0vFArz3H1djX3+4UGixZyt14lrXEvgd9TE9cJs2/RXdF0Joosx74QIDAQAB" |
| TXT | "mgverify=11d18dfff6511cf00d0a1d5d7e1f6a0a2fcd0f2a554de658fa5b069b947fec18" |
| TXT | "mindmanager-verification=2cb8b923f6d897035b2f7d5d73cc0e61690f625cef67ad7cdd39a19428709148" |
| TXT | "notion-domain-verification=be3uo8AorliA1f8sISmIWqJxGWhSGQKgTWhKhkHahR6" |
| TXT | "onetrust-domain-verification=07d2af6be3aa4cdc99ebe26e053cdd18" |
| TXT | "smartsheet-site-validation=6_otSYK33LBHB3hGD4yvBCRC3K36fKfy" |
| TXT | "smartsheet-site-validation=bKd1dTuQ8acbZh57Q5DDRrTEaI0qI2SW" |
| TXT | "status-page-domain-verification=t7crx8w5wb4b" |
| TXT | "stripe-verification=35ba23934a707a07c4c9be6e43adc627d3cb801a293fdb8ca7bc5a940d9c853d" |
| TXT | "stripe-verification=e3c5cc73ce14364162038aa39a921d6ad8cd17b95c69d1e35ebe7d776f416c27" |
| TXT | "traction-guest=cdf7c589-6dec-4726-a5cf-63b199033f64" |
| TXT | "v=spf1 include:amazonses.com include:spf.protection.outlook.com include:spfa.sony.com ip4:121.100.43.221 ip4:121.100.43.225 ip4:121.100.43.226 ip4:139.60.152.0/22 ip4:148.105.8.0/21 ip4:160.33.101.112/28 ip4:160.33.194.224/28 ip4:160.33.194.232 ip4:160.33" ".194.233 ip4:160.33.194.234 ip4:160.33.194.235 ip4:160.33.96.128/28 ip4:185.132.182.190 ip4:185.132.183.11 ip4:185.183.30.70 ip4:198.2.128.0/18 ip4:205.201.128.0/20 ip4:208.74.204.0/22 ip4:212.100.250.11 ip4:212.100.250.16/29 ip4:37.188.101.80/28 ip4:46.1" "9.168.0/23 ip4:5.61.115.112/28 ip4:5.61.115.80/28 ip4:5.61.115.96/28 ip4:5.61.117.112/28 ip4:5.61.117.80/28 ip4:5.61.117.96/28 ip4:52.222.62.51/32 ip4:52.222.73.120/32 ip4:52.222.73.83/32 ip4:52.222.75.85/32 ip4:54.186.193.102/32 ip4:83.138.165.68/31 ip4:" "91.207.212.191 ip6:2607:fd28:0102:1:1::/80 ip6:2607:fd28:0102:3:300::/80 ip4:101.231.129.3 ip4:101.231.129.4 ip4:3.93.157.0/24 ip4:3.210.190.0/24 ip4:18.208.124.128/25 ip4:54.174.52.0/24 ip4:54.174.57.0/24 ip4:54.174.59.0/24 ip4:54.174.60.0/23 ip4:54.174." "63.0/24 ip4:139.180.17.0/24 ip4:141.193.184.32/27 ip4:141.193.184.64/26 ip4:141.193.184.128/25 ip4:141.193.185.32/27 ip4:141.193.185.64/26 ip4:141.193.185.128/25 ip4:143.244.80.0/20 ip4:158.247.16.0/20 ip4:108.179.144.0/20 ip4:66.159.233.15 ip4:66.159.234" ".91 ip4:66.159.233.14 ip4:66.159.234.90 ip4:66.159.232.89 ip4:143.55.149.237 ip4:66.159.233.25 ip4:66.159.234.101 ip4:101.231.129.43 ip4:216.139.64.0/19 ip4:211.125.130.0/24 ip6:2001:cf8:0:b0::/64 -all" |
| TXT | "vQmLLyL7EiCbLfmJNXSAa4CPvnWFHN6cAKmXtcETJbzKpwymXUQgnlIlaSlVd7JFTH2Rd4OeM2Fa1tg0gSZIuA==" |
| TXT | "webexdomainverification.ELPM=7682f227-dbc9-4df9-ae72-7649e05b521f" |

**CNAME Records:**

No records found.



### Subdomains Discovered
Total subdomains discovered: **6**

```
blog.sony.com
ns1.sony.com
ns2.sony.com
secure.sony.com
test.sony.com
www.sony.com
```


### Port Scan Results
Target IP: **52.6.127.76**

| Port | Service | Banner |
|------|---------|--------|
| 80 | HTTP |  |
| 443 | HTTPS |  |


### Email Security Assessment
#### Email Security Findings

**SPF Record:** ✅ Implemented

```
v=spf1 include:amazonses.com include:spf.protection.outlook.com include:spfa.sony.com ip4:121.100.43.221 ip4:121.100.43.225 ip4:121.100.43.226 ip4:139.60.152.0/22 ip4:148.105.8.0/21 ip4:160.33.101.112/28 ip4:160.33.194.224/28 ip4:160.33.194.232 ip4:160.33" ".194.233 ip4:160.33.194.234 ip4:160.33.194.235 ip4:160.33.96.128/28 ip4:185.132.182.190 ip4:185.132.183.11 ip4:185.183.30.70 ip4:198.2.128.0/18 ip4:205.201.128.0/20 ip4:208.74.204.0/22 ip4:212.100.250.11 ip4:212.100.250.16/29 ip4:37.188.101.80/28 ip4:46.1" "9.168.0/23 ip4:5.61.115.112/28 ip4:5.61.115.80/28 ip4:5.61.115.96/28 ip4:5.61.117.112/28 ip4:5.61.117.80/28 ip4:5.61.117.96/28 ip4:52.222.62.51/32 ip4:52.222.73.120/32 ip4:52.222.73.83/32 ip4:52.222.75.85/32 ip4:54.186.193.102/32 ip4:83.138.165.68/31 ip4:" "91.207.212.191 ip6:2607:fd28:0102:1:1::/80 ip6:2607:fd28:0102:3:300::/80 ip4:101.231.129.3 ip4:101.231.129.4 ip4:3.93.157.0/24 ip4:3.210.190.0/24 ip4:18.208.124.128/25 ip4:54.174.52.0/24 ip4:54.174.57.0/24 ip4:54.174.59.0/24 ip4:54.174.60.0/23 ip4:54.174." "63.0/24 ip4:139.180.17.0/24 ip4:141.193.184.32/27 ip4:141.193.184.64/26 ip4:141.193.184.128/25 ip4:141.193.185.32/27 ip4:141.193.185.64/26 ip4:141.193.185.128/25 ip4:143.244.80.0/20 ip4:158.247.16.0/20 ip4:108.179.144.0/20 ip4:66.159.233.15 ip4:66.159.234" ".91 ip4:66.159.233.14 ip4:66.159.234.90 ip4:66.159.232.89 ip4:143.55.149.237 ip4:66.159.233.25 ip4:66.159.234.101 ip4:101.231.129.43 ip4:216.139.64.0/19 ip4:211.125.130.0/24 ip6:2001:cf8:0:b0::/64 -all
```

**DMARC Record:** ✅ Implemented

```
v=DMARC1; p=none; rua=mailto:dmarc_agg@vali.email,mailto:dmarc_rua@emaildefense.proofpoint.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;fo=1
```

**Recommendations:**

- Email security is well-configured

---
## News Monitoring

### Recent News Articles
### [PlayStation at 30: The betrayal and revenge story of the PS1 - Video Games Chronicle](https://news.google.com/rss/articles/CBMiqAFBVV95cUxORUplSFFKNEVKWWdJSUFLVkszTHlna1RETWN6TFRIMnR2YjN1c3lvaTF2bFdQNlRDRjMzTUhpRktpemVQaXNGRzFLdUpOUjBTVFlfZlFPWTE5N2dJV2ZabFo4T2daXzdma1VENDQ5MzlnV090bE85czRXUFRtSENQU2N3OHhvbXUxdXJSdFBad2VyMl9yT1ZaNmJCU0tZd1VhR25ocmdlUm4?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Tue, 03 Dec 2024 13:03:01 GMT

PlayStation at 30: The betrayal and revenge story of the PS1  Video Games Chronicle

---

### [PlayStation at 30: the console that made video games cool - The Guardian](https://news.google.com/rss/articles/CBMipAFBVV95cUxNc2IzbXo1X25rUE9ySlhWNHlsUFlvaS10N044YW4wbXBpMUEtTmtvODdCSklOcFVZZWhBVFliaXNXZms0QWtCU3hqU2tlWUwwMGljOEF0djhrQkRNNUxDMWU3MUFDUHJUam41Sm82M0pGc0lWUEdoSlFOUnY4aHhxQVV0c2trTkI1UE9DaklJQUU5cWJ3UHlhdjZTZVZVbHl1NTMyOQ?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Tue, 03 Dec 2024 08:00:00 GMT

PlayStation at 30: the console that made video games cool  The Guardian

---

### [The Sony PlayStation at 30 – and six of the best PS1 games to try - stuff.tv](https://news.google.com/rss/articles/CBMigAFBVV95cUxOcWh0WVdaRFdQdHJPcmlvdkc5OF9KdUxSY1V0bWhLYVNubXU5WnpCOUVHOFdMSC1obVR0NFRDeUtMcTF6UjdGb0dTblNoSWxYY21ybTZCZXFrcUxGcUVfRU50QVRlamY3VUtEY19KYkZvX3Z2SG5meC1Hdnh6dXQwNA?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Tue, 03 Dec 2024 08:00:00 GMT

The Sony PlayStation at 30 – and six of the best PS1 games to try  stuff.tv

---

### [PlayStation at 30: How Sony's gray box conquered gaming - The Japan Times](https://news.google.com/rss/articles/CBMihwFBVV95cUxOWk5VdnFlMGk4LVU4RGxHb2ZQLVZlRTA4SVkwQ00yeGZmMkp0MUVuOXdWME45TmpPc3JzZHpqZkRfR25nVzlwcDVEOU13LUJmT1VBOXZsYzVUc3c3R1c4TDN0YWE0dmN0S0RRRlVDLS1hZGg0SnJIRXVQc2R4bU1rYzduZFlzQ0E?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Mon, 02 Dec 2024 08:00:00 GMT

PlayStation at 30: How Sony's gray box conquered gaming  The Japan Times

---

### [PlayStation at 30: Sony's console journey from grey origins to legendary game libraries - News24](https://news.google.com/rss/articles/CBMi5AFBVV95cUxObWJKQWlRaGo5NENSa29FQmwyOE03bWRxNko3U2R0VTc5WW55ZzZlMldrZGo1Q01MNGczcEtKd1ZqOEpiRFJLV2Vvd3d3bGpTQWFOWGhwMEI5RXpMNk5seGRaX3JMVG5YT3BSN1lrOGV1bDlYTHpfN0JyQ1VQVXZPZFpUSmxUUENNYkF1V1dQTUswcWJadmt3VUxxUGNMRnNHbUFrVG1ySUdzOVB2V0t6NmZ4Ykp5a2tmYTZzTnd6YXVhRmRBTndkcFQ4X2FBR0lHSndVbE9kdUxsTjRHcFdWSDVoVF8?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Fri, 29 Nov 2024 08:00:00 GMT

PlayStation at 30: Sony's console journey from grey origins to legendary game libraries  News24

---

### [PlayStation at 30: How Sony’s grey box reshaped gaming and conquered the young adult market, turning video games into a cultural phenomenon - Malay Mail](https://news.google.com/rss/articles/CBMipAJBVV95cUxQQ25Hdmh3dVBLeGQyWDVrby1jSThFdXpJR0o0a3E1SFlLcmVXZVVFWVRweUFoN3VvS3hBSm4xZ3UxZjM1Sjg0My02dUEzQ0RzYy1PM05RWm5qSWNvUGpyYmxIZWtSaDVXeHk3NXl6NUlXbEdNTVlwTkVKTklsT3JFVEJJX1Ezc3RhU1RLLWJmR0dDTC1YOVhpcVI1ZlZmUnA3RVEzUGFDMHNEd1lPWi1wbURIV3VCLUpObHE5ZEowZ0VNdUdQVjRxOG9vdjBxYkZSdDVXLUpFTElRZk9tT2lCWlhZbHNwYVo4QlR5S2JqT0xwX2FtSVhsOXhJTFE4c0stemppdE44Q3ZNclk2ODFGQndsNF9lLTdFRzk2blU0VnFBa0JJ0gGqAkFVX3lxTFBOTEFlbDBjdF9RR1ozVTdsQUQ0bHlYZm1LRlJDblEyVDR0OURPYXVKVktiTG52Wmt0eXVGcTFxNGVrMi1QenZlY2gwbFNnZGF3RGNxUmE5MWVTdzJnbTFDNy11VVdMYjA4YzZEMGtuR21jTDBoVEV0cm1hSG9OMXZsMGgtQ0NiMDNtaFhDTVhDUWRFMzhSQ1pjc1I5RjBfbHA2QjVxZG85WnFraEJSMVJ2QVQyTDBfN29UVnp0MWU3UGVKdGNEazhDZVlhb3F4NG8wNFVvbjlkVHhhOXR3dXlDZjFnTGhvdl9WRVdrUUFudlpzck9LcS11c24zN1g1bGptd2dqMDdLWEpzdjVIcUF6RjBzcUE2RTJrZEJLSG5NcVRIQkk2eWhQVEE?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Fri, 29 Nov 2024 08:00:00 GMT

PlayStation at 30: How Sony’s grey box reshaped gaming and conquered the young adult market, turning video games into a cultural phenomenon  Malay Mail

---

### [PlayStation at 30: The console that proved everyone wrong - The Citizen](https://news.google.com/rss/articles/CBMipwFBVV95cUxNaEtfTTZUbXNTakJzcU9mVEY0bW1NNURZYW1OX2lPSVhnX2c3eVR4eHhXb0c5VkdKTlZZOHVQZ1FpbkZhZElzYTZtc096NXcya0lIek55T3NVMjRicjNuMjFfdmJmVUNLTjZtX21CWm1KSm9tbThNRnlHLXJiWmFJMUlXaHIxVlFJOXRGNDY0enRjdFRzcWtHNU0wTVhXazM3YnN6dkpPQQ?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Fri, 29 Nov 2024 08:00:00 GMT

PlayStation at 30: The console that proved everyone wrong  The Citizen

---

### [PlayStation 30th Anniversary Pre-Orders Start Today, Here's How To Get In Line - Kotaku](https://news.google.com/rss/articles/CBMihwFBVV95cUxQeDRGZkFTcTBlbHh4d0dLWVVUS292M0NKa0ZtSmlVNHVCYy1jU0lvVFF3cnA1dUhMQnkzWTRwSDBHTEZDM2YxaUVSdUlRSEFiY2Qwc0E2X3hCWEhuWGZwSXJKNk5mcVVQTHROa25xSWEwVXhXT1RTNVNQU0F4Z3pXTXNUVEZZV1E?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Thu, 26 Sep 2024 07:00:00 GMT

PlayStation 30th Anniversary Pre-Orders Start Today, Here's How To Get In Line  Kotaku

---

### [Celebrating 30 years of PlayStation with a nostalgic look - PlayStation.Blog](https://news.google.com/rss/articles/CBMinwFBVV95cUxNeExUd29KNXdMd2RLc3IzRV9xM3R3MGlITDk5S1ZuRTRLaGJ1aXAyRXFRV0J3VVpxOTVtOHV3MWlUOEpUc01VTUlnd3VMc3ByZ1RUUlZjYjFXTzJGSDlUUEt4blpGeGVlMWlvelFtcjQyNGpKX3p2RTVSTGNpWjVoWFdCZVJGamplVWtlZUxVMXJLenU1NzJheUF0U1BYdmc?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Thu, 19 Sep 2024 07:00:00 GMT

Celebrating 30 years of PlayStation with a nostalgic look  PlayStation.Blog

---

### [PlayStation 30th Anniversary quiz - PlayStation](https://news.google.com/rss/articles/CBMiYEFVX3lxTE13ZlNMYXFnZVBYTXRxRkhpamFkay1pY1djMWpTeEI0Y21KWEhuOTVJbUJaRERXZ0tFckk5RlBmTldjbUZKUW1TZGF5NUh4Ny04MFd5bG9jczV4T0I5TkdhWQ?oc=5&hl=en-IN&gl=IN&ceid=IN:en)

**Published:** Mon, 09 Sep 2024 16:02:50 GMT

PlayStation 30th Anniversary quiz  PlayStation

---



---
## About This Report

This report was generated automatically by FARSIGHT v0.1.0 on 2025-05-17 18:54:31.

All data in this report is presented for informational purposes only.
