# Phishing / Spam Email Analysis — "OneCasino" Welcome Gift Lure

## Summary

| Field | Value |
|---|---|
| Subject | `Welcome gift inside: 50 spins waiting for you💰.944175#.` |
| From | `"OneCasino " <132784@534617.vav.proo55.us.com>` |
| To | `jacobcookofficial@gmail.com` |
| Date | Wed, 28 Jan 2026 22:49:43 +0000 |
| Return-Path | `<bounce@vav.proo55.us.com>` |
| Sending IP | `141.95.0.46` |
| Message-ID | `<69109263.170a0220.29f1ba.ca4a.GMR@mx.google.com>` |
| Verdict | **Spam / marketing-phish lure** — bulk casino spam sent from a disposable, randomly-generated subdomain, using a shortened URL. Low sophistication, high spam-signal, one vendor flags the URL as phishing. |

---

## 1. Raw Headers of Interest

```
Delivered-To: jacobcookofficial@gmail.com
Return-Path: <bounce@vav.proo55.us.com>
Received: from vav.proo55.us.com (vps-b3328616.vps.ovh.net. [141.95.0.46])
Received-SPF: pass (google.com: domain of bounce@vav.proo55.us.com designates 141.95.0.46 as permitted sender) smtp.mailfrom=bounce@vav.proo55.us.com;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@534617.vav.proo55.us.com header.s=smtp header.b=AXdOUFl6;
       dkim=neutral (expired) header.i=@googlemail.com header.s=20230601 header.b=doulgfdp;
       spf=pass (google.com: domain of bounce@vav.proo55.us.com designates 141.95.0.46 as permitted sender) smtp.mailfrom=bounce@vav.proo55.us.com;
DKIM-Signature: v=1; a=rsa-sha1; c=relaxed/relaxed; s=smtp; d=534617.vav.proo55.us.com;
From: "OneCasino " <132784@534617.vav.proo55.us.com>
Subject: Welcome gift inside: 50 spins waiting for you💰.944175#.
X-Failed-Recipients: jacobcookofficial@google.com
```

![MXToolbox "Headers Found" table listing all raw email headers extracted from the .eml file](screenshots/06-mxtoolbox-headers-found.png)
*Figure 6 — Full parsed header table from MXToolbox's Analyze Headers tool, confirming the sender, Return-Path, DKIM domain, and SPF pass result.*

**Key observations:**
- The `From` domain (`534617.vav.proo55.us.com`) is a randomly numbered subdomain of `proo55.us.com` — a disposable-looking sender domain, typical of throwaway bulk-mail infrastructure.
- `X-Failed-Recipients` header pointing at a different address (`@google.com`) suggests this message was originally bounced/reprocessed — consistent with mailer misconfiguration common in spam operations, not a targeted attack.
- SPF **passes** for the sending IP, and DKIM **passes**, but only because both records are published by the spammer's own throwaway subdomain — passing authentication does **not** mean the sender is trustworthy, only that the message wasn't spoofed from someone else's domain.

## 2. DMARC / SPF / DKIM (MXToolbox)

![MXToolbox header analysis summary showing DMARC not compliant, SPF and DKIM alignment/authentication all failed](screenshots/04-mxtoolbox-dmarc-spf-dkim-summary.png)
*Figure 4 — MXToolbox delivery-information summary: DMARC non-compliant, SPF/DKIM alignment and authentication all failing.*

- **DMARC:** No DMARC record found for either `534617.vav.proo55.us.com` or the organizational domain `proo55.us.com`. Without DMARC, there is no enforced policy telling receiving servers what to do with unauthenticated mail from this domain family.
- **SPF:** `spf:vav.proo55.us.com` explicitly authorizes IP `141.95.0.46` — expected, since the spammer controls this DNS record.
- **DKIM:** MXToolbox reports the DKIM signature as invalid / not properly aligned (`DKIM-Signature Domain ... is invalid`), and notes there must be at least one aligned DKIM signature for alignment — which is missing here.

![MXToolbox SPF and DKIM detail view showing no DMARC record found for either the subdomain or organizational domain, and DKIM signature errors](screenshots/05-mxtoolbox-spf-dkim-details.png)
*Figure 5 — Detailed SPF/DKIM/DMARC breakdown: no DMARC record at either the subdomain or organizational level, and DKIM signature/alignment errors.*

**Conclusion:** the domain has weak/absent authentication hygiene (no DMARC), consistent with a burner sending domain spun up purely for a spam blast rather than a legitimate business.

## 3. Sending IP — WHOIS (141.95.0.46)

```
inetnum:      141.95.0.0 - 141.95.1.255
netname:      VPS-DE2
country:      DE
org-name:     OVH GmbH
address:      Oskar-Jäger-Str. 173/6, 50825 Köln, Deutschland
abuse contact: abuse@ovh.net
status:       ASSIGNED PA
```

![WHOIS lookup for 141.95.0.46 showing OVH GmbH VPS hosting in Germany](screenshots/01-whois-ip.png)
*Figure 1 — WHOIS record for the sending IP, showing it belongs to an OVH GmbH VPS block in Germany.*

- The IP belongs to **OVH GmbH**, a well-known low-cost/anonymous VPS hosting provider in Germany.
- Bulk/spam senders very commonly rent cheap VPS blocks from providers like OVH to send high volumes of throwaway mail — this is a strong environmental indicator of spam infrastructure rather than a legitimate marketing platform (e.g., SendGrid, Mailchimp, etc.).

## 4. URL / Redirect Chain Analysis

The email body contains a single obfuscated link reused for "Start Spinning Now," "Unsubscribe," and "Terms": `https://tinyurl.com/mrymsuhv`

**Redirect chain (RedirectChecker):**

| Step | Status | URL |
|---|---|---|
| 1 | 301 | `https://tinyurl.com/mrymsuhv` |
| 2 | 200 (final) | `https://tinyurl.com/app/nospam/tinyurl.com/mrymsuhv` |

![RedirectChecker trace showing the tinyurl.com/mrymsuhv link 301-redirecting to TinyUrl's own /app/nospam/ warning page](screenshots/02-redirect-chain.png)
*Figure 2 — Redirect chain trace: the link resolves not to an external casino site, but to TinyUrl's own spam-interstitial path.*

Interestingly, the final destination resolves to TinyUrl's own **`/app/nospam/`** interstitial/warning path rather than an external casino site — this typically happens when TinyUrl itself has flagged the destination link as spam/abuse and intercepted it with a warning page, rather than forwarding the visitor straight through.

**VirusTotal scan of the final URL:**
- Detection: **1 / 95** vendors flagged it.
- `SafeToOpen` → **Phishing**
- All other engines (Abusix, Acronis, ADMINUSLabs, AlienVault, BitDefender, Blueliv, CINS Army, etc.) → **Clean**
- Host: `tinyurl.com` (`104.18.111.161`, Cloudflare-fronted), Content-Type `text/html`.

![VirusTotal detection results for the final URL, showing 1 of 95 vendors (SafeToOpen) flagging it as Phishing](screenshots/03-virustotal-detection.png)
*Figure 3 — VirusTotal scan: SafeToOpen flags the URL as Phishing while other vendors report it Clean.*

**Conclusion:** Low but non-zero detection. One reputable engine (SafeToOpen) flags it as phishing; the fact that TinyUrl auto-routed the link to its own `/nospam/` warning page independently corroborates that TinyUrl's own abuse systems already consider this link suspicious.

## 5. Content / Social-Engineering Assessment

- Classic **"free spins / no-deposit bonus"** gambling lure — designed to drive click-through with urgency and a "free money" hook.
- Sender name `"OneCasino "` (note trailing space) is a generic, unregistered-looking brand — not a verifiable, licensed operator.
- All three links in the email (CTA, "Unsubscribe," and "Terms") point to the **exact same shortened URL** — a common spam/phishing pattern. Legitimate marketing mail almost never routes "Unsubscribe" through the same tracking link as the main offer; this maximizes click-throughs while faking compliance with anti-spam law (CAN-SPAM/GDPR "unsubscribe" requirement).
- No physical mailing address, no verifiable company registration, no legitimate footer — another CAN-SPAM red flag.

## 6. Overall Risk Rating

| Category | Rating | Rationale |
|---|---|---|
| Sender domain trust | **Low** | Random numeric subdomain, no DMARC |
| Hosting infrastructure | **Low** | Cheap/anonymous OVH VPS block, common for spam |
| URL reputation | **Low–Medium** | 1/95 phishing flag + TinyUrl's own abuse redirect |
| Content/social engineering | **High risk pattern** | Fake urgency, deceptive unsubscribe link |
| **Overall** | **Malicious/Spam — do not click, report & block sender** |

## 7. Recommended Actions

1. Do not click any link in the message, including "Unsubscribe."
2. Report the message as phishing/spam in Gmail (this also feeds Google's spam classifiers).
3. Block the sending domain (`proo55.us.com` and subdomains) and the sending IP (`141.95.0.46`) at the mail-gateway level if managing infrastructure.
4. If this address is used elsewhere, treat it as having been added to a spam list; consider not engaging (not even to unsubscribe) as that can confirm the address is live.

---

## Appendix: Evidence Sources

- WHOIS lookup of `141.95.0.46` — Whois.com (`screenshots/01-whois-ip.png`)
- Redirect chain trace of `https://tinyurl.com/mrymsuhv` — RedirectChecker.com (`screenshots/02-redirect-chain.png`)
- URL reputation scan of final destination — VirusTotal (`screenshots/03-virustotal-detection.png`)
- Header analysis (SPF/DKIM/DMARC summary) — MXToolbox Analyze Headers (`screenshots/04-mxtoolbox-dmarc-spf-dkim-summary.png`)
- SPF/DKIM/DMARC detailed breakdown — MXToolbox SuperTool (`screenshots/05-mxtoolbox-spf-dkim-details.png`)
- Full parsed headers table — MXToolbox Analyze Headers (`screenshots/06-mxtoolbox-headers-found.png`)
- Raw `.eml` source file (`sample1.eml`)

All screenshots are stored in the [`screenshots/`](screenshots/) directory alongside this report.
