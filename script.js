/* =========================================================
   Phishing Email Analyser — client-side analysis logic
   Everything here runs locally in the visitor's browser.
   No network requests are made.
   ========================================================= */

"use strict";

/* ---------- Small helpers ---------- */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function esc(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Returns the first word/phrase from `words` found in `text`, or null.
// Uses word boundaries so short words don't match inside longer words.
function matchAny(text, words) {
  const t = text.toLowerCase();
  for (const w of words) {
    const re = new RegExp("\\b" + esc(w.toLowerCase()) + "\\b");
    if (re.test(t)) return w;
  }
  return null;
}

// Returns the first phrase found (no word-boundary requirement).
function matchPhrase(text, phrases) {
  const t = text.toLowerCase();
  for (const p of phrases) {
    if (t.indexOf(p.toLowerCase()) !== -1) return p;
  }
  return null;
}

// Strip HTML tags and collapse whitespace.
function stripTags(html) {
  return String(html).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

// Extract a hostname from a URL or "www.x" string.
function getHost(u) {
  let s = String(u).trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  s = s.split(/[/?#]/)[0];
  s = s.replace(/^www\./i, "");
  return s.toLowerCase();
}

function isRawIP(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every(function (p) {
    return /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255;
  });
}

// Extract URLs from raw text (body or headers).
function extractUrls(text) {
  const re = /(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    let u = m[0];
    // trim trailing punctuation
    u = u.replace(/[.,;:!?)]+$/, "");
    if (out.indexOf(u) === -1) out.push(u);
  }
  return out;
}

// Extract <a href="...">text</a> links from HTML-ish content.
function extractHtmlLinks(html) {
  const links = [];
  const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a\s*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    links.push({ href: m[1].trim(), text: stripTags(m[2]) });
  }
  return links;
}

function extractEmails(text) {
  const re = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  return text.match(re) || [];
}

/* ---------- Configuration: known brands & shorteners ---------- */

// Well-known brands used to detect "lookalike" domains.
// A domain that contains a brand name but is NOT the real domain is suspicious.
const BRANDS = [
  { brand: "microsoft", domain: "microsoft.com" },
  { brand: "apple", domain: "apple.com" },
  { brand: "icloud", domain: "icloud.com" },
  { brand: "google", domain: "google.com" },
  { brand: "gmail", domain: "gmail.com" },
  { brand: "amazon", domain: "amazon.com" },
  { brand: "paypal", domain: "paypal.com" },
  { brand: "netflix", domain: "netflix.com" },
  { brand: "facebook", domain: "facebook.com" },
  { brand: "instagram", domain: "instagram.com" },
  { brand: "whatsapp", domain: "whatsapp.com" },
  { brand: "linkedin", domain: "linkedin.com" },
  { brand: "dropbox", domain: "dropbox.com" },
  { brand: "dhl", domain: "dhl.com" },
  { brand: "fedex", domain: "fedex.com" },
  { brand: "ups", domain: "ups.com" },
  { brand: "usps", domain: "usps.com" },
  { brand: "hsbc", domain: "hsbc.com" },
  { brand: "barclays", domain: "barclays.co.uk" },
  { brand: "lloyds", domain: "lloydsbank.com" },
  { brand: "santander", domain: "santander.co.uk" },
  { brand: "chase", domain: "chase.com" },
  { brand: "wellsfargo", domain: "wellsfargo.com" },
  { brand: "citibank", domain: "citibank.com" },
];

// Common URL-shortener domains.
const SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "s.id", "rb.gy", "soo.gd"
];

// Suspicious keywords that often appear inside fake/phishing domain names.
const GENERIC_SUSPICIOUS = [
  "login", "verify", "signin", "sign-in", "confirm", "secure", "account",
  "billing", "invoice", "payment", "password", "recover", "unlock",
  "validation", "alert", "update", "review", "resume"
];

/* ---------- The rules ----------
   Each rule is a named warning sign with a fixed point weight.
   `test(ctx)` returns a short snippet of what it matched, or null.
   The total score is the sum of fired rules' weights, capped at 100.
   ---------------------------------------------------------- */

const RULES = [
  // ---- Urgency & pressure ----
  {
    id: "urgency",
    category: "Urgency & Pressure",
    label: "Uses urgent or high-pressure language",
    weight: 8,
    severity: "medium",
    test: function (ctx) {
      return matchAny(ctx.body, [
        "urgent", "urgently", "immediately", "act now", "right away",
        "as soon as possible", "at once", "now!", "hurry", "don't delay"
      ]);
    }
  },
  {
    id: "deadline",
    category: "Urgency & Pressure",
    label: "Creates a tight deadline or time pressure",
    weight: 5,
    severity: "medium",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "within 24 hours", "within 48 hours", "within 12 hours", "within hours",
        "24 hour notice", "limited time", "expires soon", "expiring",
        "final notice", "final reminder", "last warning", "deadline",
        "time is running out", "your access will be lost"
      ]);
    }
  },
  {
    id: "account_threat",
    category: "Threats & Consequences",
    label: "Threatens account suspension, closure or deactivation",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      return matchAny(ctx.body, [
        "suspend", "suspended", "suspension", "deactivate", "deactivated",
        "terminate", "terminated", "locked out", "account closed", "will be closed",
        "will be deleted", "restricted", "access blocked", "mailbox disabled"
      ]);
    }
  },
  {
    id: "legal_threat",
    category: "Threats & Consequences",
    label: "Threatens legal, financial or account-security consequences",
    weight: 6,
    severity: "medium",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "legal action", "we will report you", "police", "authorities",
        "permanent deletion", "your funds", "held liable", "fine", "penalty",
        "shut down your account", "unauthorised activity detected", "unauthorized activity"
      ]);
    }
  },
  {
    id: "password_request",
    category: "Credential Harvesting",
    label: "Requests your password or login credentials",
    weight: 15,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "enter your password", "confirm your password", "verify your password",
        "your password", "re-enter your password", "provide your password",
        "type your password", "confirm your credentials", "re-enter your credentials",
        "verify your login", "sign in to confirm", "log in to verify",
        "re-enter your login details"
      ]);
    }
  },
  {
    id: "mfa_request",
    category: "Credential Harvesting",
    label: "Requests an MFA, verification or one-time code",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "verification code", "verification number", "security code", "one time code",
        "one-time code", "otp", "mfa code", "authentication code", "6-digit code",
        "6 digit code", "confirm the code", "enter the code", "two-factor code"
      ]);
    }
  },
  {
    id: "verify_account",
    category: "Credential Harvesting",
    label: "Asks you to verify, update or re-enter account details",
    weight: 8,
    severity: "medium",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "verify your account", "update your account", "re-verify", "reverify",
        "confirm your details", "confirm your information", "re-activate your account",
        "recover your account", "restore your account", "unlock your account",
        "revalidate", "revalidate your account", "confirm your identity"
      ]);
    }
  },

  // ---- Financial requests ----
  {
    id: "payment_request",
    category: "Financial Requests",
    label: "Requests an unexpected payment or fee",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "make a payment", "outstanding payment", "overdue payment", "unpaid invoice",
        "settle your balance", "pay now", "payment required", "small fee",
        "processing fee", "customs fee", "delivery fee", "pay the amount", "amount due"
      ]);
    }
  },
  {
    id: "gift_card",
    category: "Financial Requests",
    label: "Requests payment via gift cards",
    weight: 18,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "gift card", "giftcard", "itunes card", "apple card", "steam card",
        "amazon gift", "google play card", "prepaid card", "voucher code",
        "scratch off the back", "send the codes"
      ]);
    }
  },
  {
    id: "bank_change",
    category: "Financial Requests",
    label: "Requests a change to bank or payment details",
    weight: 18,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "update your bank details", "change your bank details", "new bank account",
        "updated banking details", "change of bank account", "update payment details",
        "change payment details", "new payment details", "revised bank details",
        "update your direct deposit", "change your routing number"
      ]);
    }
  },
  {
    id: "invoice_lang",
    category: "Financial Requests",
    label: "Unexpected or urgent invoice language",
    weight: 10,
    severity: "medium",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "invoice attached", "attached invoice", "find your invoice", "overdue invoice",
        "past due invoice", "please remit payment", "remit payment", "proforma invoice",
        "wire transfer", "bank transfer", "revised invoice", "outstanding balance"
      ]);
    }
  },

  // ---- Links & URLs ----
  {
    id: "suspicious_url",
    category: "Links & URLs",
    label: "Contains a suspicious or lookalike URL",
    weight: 8,
    severity: "medium",
    test: function (ctx) {
      for (const host of ctx.hosts) {
        if (isRawIP(host)) continue; // handled separately
        for (const b of BRANDS) {
          if (host.indexOf(b.brand) !== -1 &&
              host !== b.domain && host.slice(-(b.domain.length + 1)) !== "." + b.domain) {
            return host;
          }
        }
      }
      const knownDomains = BRANDS.map(function (b) { return b.domain; });
      for (const host of ctx.hosts) {
        const isKnown = knownDomains.some(function (d) {
          return host === d || host.slice(-(d.length + 1)) === "." + d;
        });
        if (isKnown) continue;
        for (const kw of GENERIC_SUSPICIOUS) {
          if (host.indexOf(kw) !== -1) return host;
        }
      }
      return null;
    }
  },
  {
    id: "shortened_url",
    category: "Links & URLs",
    label: "Contains a shortened URL",
    weight: 6,
    severity: "medium",
    test: function (ctx) {
      for (const host of ctx.hosts) {
        for (const s of SHORTENERS) {
          if (host === s || host.slice(-(s.length + 1)) === "." + s) return host;
        }
      }
      return null;
    }
  },
  {
    id: "ip_url",
    category: "Links & URLs",
    label: "Uses a raw IP address in a URL",
    weight: 10,
    severity: "high",
    test: function (ctx) {
      for (const host of ctx.hosts) {
        if (isRawIP(host)) return host;
      }
      return null;
    }
  },
  {
    id: "misleading_link",
    category: "Links & URLs",
    label: "Link text does not match its actual destination",
    weight: 10,
    severity: "high",
    test: function (ctx) {
      for (const link of ctx.htmlLinks) {
        const hrefHost = getHost(link.href);
        const textHost = getHost(link.text.replace(/\s+/g, ""));
        if (textHost && textHost.indexOf(".") !== -1 && textHost !== hrefHost) {
          return "Shown: " + textHost + "  →  Goes to: " + hrefHost;
        }
      }
      return null;
    }
  },

  // ---- Impersonation ----
  {
    id: "impersonation",
    category: "Impersonation",
    label: "Claims to be from a support, IT or security team",
    weight: 6,
    severity: "medium",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "we are the security team", "your it department", "it support",
        "customer support team", "our security team", "account services team",
        "the billing department", "help desk", "helpdesk", "we are contacting you",
        "this is an automated message"
      ]);
    }
  },
  {
    id: "generic_greeting",
    category: "Impersonation",
    label: "Uses a generic greeting instead of your name",
    weight: 4,
    severity: "low",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "dear customer", "dear user", "dear account holder", "dear valued customer",
        "dear member", "dear sir/madam", "dear client", "hello customer",
        "valued customer", "account holder"
      ]);
    }
  },
  {
    id: "brand_spoof",
    category: "Impersonation",
    label: "Sender or text mimics a well-known brand",
    weight: 6,
    severity: "medium",
    test: function (ctx) {
      const fromHost = ctx.fromHost;
      for (const b of BRANDS) {
        if (fromHost && fromHost.indexOf(b.brand) !== -1 &&
            fromHost !== b.domain && fromHost.slice(-(b.domain.length + 1)) !== "." + b.domain) {
          return fromHost;
        }
      }
      return null;
    }
  },

  // ---- Attachments ----
  {
    id: "exec_attachment",
    category: "Attachments",
    label: "Executable or script attachment type",
    weight: 15,
    severity: "high",
    test: function (ctx) {
      const m = ctx.bodyLower.match(/[\w.-]+\.(exe|scr|bat|cmd|com|msi|js|jse|vbs|vbe|ps1|jar|lnk|hta|wsf|reg|pif)\b/);
      return m ? m[0] : null;
    }
  },
  {
    id: "odd_attachment",
    category: "Attachments",
    label: "Unusual or misleading attachment filename",
    weight: 10,
    severity: "medium",
    test: function (ctx) {
      const macro = ctx.bodyLower.match(/[\w.-]+\.(docm|xlsm|pptm)\b/);
      if (macro) return macro[0] + " (macro-enabled document)";
      const m = ctx.bodyLower.match(/[\w.-]+\.(docm|xlsm|pptm|doc|xls|pdf)\.(exe|js|vbs|bat|cmd|scr|zip|rar)\b/);
      if (m) return m[0];
      const m2 = ctx.bodyLower.match(/[\w.-]*\.[a-z]{2,4}\s*\.[a-z]{2,4}\b/);
      return m2 ? m2[0].trim() : null;
    }
  },
  {
    id: "macro_request",
    category: "Attachments",
    label: "Requests you enable macros or content",
    weight: 15,
    severity: "high",
    test: function (ctx) {
      return matchPhrase(ctx.body, [
        "enable macros", "enable content", "enable editing", "macros must be enabled",
        "enable active content", "to view this document you need to enable"
      ]);
    }
  },

  // ---- Email headers / authentication ----
  {
    id: "replyto_mismatch",
    category: "Email Headers",
    label: "Sender (From) and Reply-To addresses differ",
    weight: 8,
    severity: "medium",
    test: function (ctx) {
      if (!ctx.fromEmail || !ctx.replyToEmail) return null;
      const fh = ctx.fromEmail.split("@")[1];
      const rh = ctx.replyToEmail.split("@")[1];
      if (fh && rh && fh.toLowerCase() !== rh.toLowerCase()) {
        return "From: " + ctx.fromEmail + "  /  Reply-To: " + ctx.replyToEmail;
      }
      return null;
    }
  },
  {
    id: "spf_fail",
    category: "Email Headers",
    label: "SPF authentication failed",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      const m = ctx.headersLower.match(/\bspf\s*=\s*(fail|softfail|permerror|neutral)\b/);
      return m ? "spf=" + m[1] : null;
    }
  },
  {
    id: "dkim_fail",
    category: "Email Headers",
    label: "DKIM authentication failed",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      const m = ctx.headersLower.match(/\bdkim\s*=\s*(fail|permerror|neutral|none)\b/);
      return m ? "dkim=" + m[1] : null;
    }
  },
  {
    id: "dmarc_fail",
    category: "Email Headers",
    label: "DMARC authentication failed",
    weight: 12,
    severity: "high",
    test: function (ctx) {
      const m = ctx.headersLower.match(/\bdmarc\s*=\s*(fail|permerror)\b/);
      return m ? "dmarc=" + m[1] : null;
    }
  }
];

/* ---------- Fictional demo emails ----------
   All domains use the reserved ".example" TLD, which can never be
   registered or resolve — so none of these links are real or usable. */

const DEMOS = [
  {
    title: "Obvious phishing (prize)",
    body: "Subject: CONGRATULATIONS!!! You are our lucky winner\n\nDear valued customer,\n\nWe are contacting you because you have been selected as the winner of our international lottery! You have won $1,000,000.00 (one million dollars).\n\nTo claim your prize you MUST act now and reply within 24 hours, otherwise your prize will be forfeited.\n\nYou are required to pay a small processing fee of $120. Please make the payment using a gift card (Apple, Steam or Amazon) and send the codes back to us immediately.\n\nClick here to confirm: http://lottery-prize.example/claim\n\nAlso open the attached \"claim_form.exe\" to register your details.\n\nYours in service,\nThe Prize Award Team\n",
    headers: ""
  },
  {
    title: "Sophisticated phishing (IT review)",
    body: "Subject: Required security review of your account\n\nHello,\n\nOur security team has detected unusual sign-in activity on your account. As part of a routine security review, you are required to re-enter your login details to confirm your identity.\n\nPlease verify your account and confirm your password within 24 hours to avoid having your access restricted.\n\n<a href=\"http://login-verify.example/signin\">microsoft.com/security</a>\n\nThank you,\nThe IT Support Team\n",
    headers: "From: IT Support <security@it-support.example>\nReply-To: support@it-support.example\nSubject: Required security review of your account\n"
  },
  {
    title: "Fake Microsoft 365 warning",
    body: "Subject: Your Microsoft 365 account will be suspended\n\nDear account holder,\n\nWe detected a problem with your Microsoft 365 subscription and your account will be suspended within 24 hours.\n\nTo prevent suspension you must verify your account immediately by entering your password and the 6-digit verification code sent to your phone.\n\nSign in here now: http://login-microsoft.example/verify\n\nThis is an automated message. Do not ignore this final notice.\n\nThe Microsoft Account Services Team\n",
    headers: "From: Microsoft Account Team <noreply@microsoft.example>\nReply-To: billing@microsoft.example\nAuthentication-Results: example.com; spf=fail; dkim=fail; dmarc=fail\n"
  },
  {
    title: "Fake parcel-delivery message",
    body: "Subject: Your parcel could not be delivered\n\nDear customer,\n\nYour parcel is waiting at our depot but a small customs fee of £2.99 is required before we can deliver it.\n\nPay the fee now to arrange redelivery: http://bit.ly/track-parcel-example\n\nYou have 48 hours to pay, after which your parcel will be returned to sender.\n\nThank you,\nThe Delivery Team\n",
    headers: ""
  },
  {
    title: "Fake invoice / BEC style",
    body: "Subject: Urgent — updated invoice and bank details\n\nHello,\n\nPlease find your revised invoice attached. We have changed our bank account, so please update your bank details and send the outstanding balance of £4,850 to the new account below.\n\nInvoice_Oct_revised.docm\n\nNote: to view the full invoice you need to enable macros.\n\nPlease remit payment today to avoid late fees.\n\nRegards,\nAccounts Department\n",
    headers: "From: Accounts <accounts@supplier-payments.example>\nReply-To: ceo@exec-urgent.example\nSubject: Urgent — updated invoice and bank details\n"
  },
  {
    title: "Legitimate email",
    body: "Subject: Team meeting notes and next steps\n\nHi Alex,\n\nThanks for sending over the project update earlier. I've reviewed it and everything looks good.\n\nJust a reminder that our team meeting is on Thursday at 10am in the usual room. Could you bring the printed copies of the agenda?\n\nNo rush — let me know if Thursday doesn't work and we can reschedule.\n\nBest regards,\nSam\n",
    headers: ""
  }
];

/* ---------- Classification ---------- */

function classify(score) {
  if (score >= 60) {
    return {
      label: "High Risk",
      className: "high",
      ring: "var(--high)",
      summary: "Many strong warning signs are present. Treat this email as likely malicious and do not interact with it."
    };
  }
  if (score >= 25) {
    return {
      label: "Suspicious",
      className: "suspicious",
      ring: "var(--suspicious)",
      summary: "Several warning signs are present. Investigate carefully before taking any action."
    };
  }
  return {
    label: "Low Risk",
    className: "low",
    ring: "var(--low)",
    summary: "Few or no common warning signs were found. This does not guarantee safety — always stay alert."
  };
}

/* ---------- Recommendations ---------- */

function buildRecommendations(band, findings) {
  const ids = findings.map(function (f) { return f.id; });
  function has(id) { return ids.indexOf(id) !== -1; }
  const recs = [];

  if (band.className === "high") {
    recs.push("Do not reply, click any link, or open any attachment. If this arrived in a work mailbox, report it to your IT or security team and delete it.");
  } else if (band.className === "suspicious") {
    recs.push("Treat this email with caution. If you were not expecting it, do not act until you have verified it through official channels.");
  } else {
    recs.push("Few warning signs were found, but still verify any request you were not expecting before acting.");
  }

  if (has("password_request") || has("mfa_request") || has("verify_account")) {
    recs.push("Never share your password, MFA code or one-time codes with anyone. No legitimate organisation will ask for them by email.");
  }
  if (has("gift_card") || has("bank_change") || has("payment_request") || has("invoice_lang")) {
    recs.push("Legitimate companies never demand payment by gift card or ask you to change bank details by email. Contact the company using a number or website you already trust.");
  }
  if (has("exec_attachment") || has("odd_attachment") || has("macro_request")) {
    recs.push("Do not open attachments or enable macros. A document that asks you to enable macros is a common malware delivery method.");
  }
  if (has("suspicious_url") || has("shortened_url") || has("ip_url") || has("misleading_link")) {
    recs.push("Hover over links without clicking to inspect the real destination. Do not open suspicious, shortened or IP-address links.");
  }
  if (has("spf_fail") || has("dkim_fail") || has("dmarc_fail") || has("replyto_mismatch")) {
    recs.push("The email's authentication checks (SPF/DKIM/DMARC) failed or the Reply-To address differs, which suggests the sender may be spoofed.");
  }
  if (has("account_threat")) {
    recs.push("Threats that your account will be suspended are a common scare tactic. Sign in directly on the official site to check your account status.");
  }

  recs.push("Verify important messages using the organisation's official website, app, or a known contact — never the links or phone numbers in the email.");
  return recs;
}

/* ---------- Main analysis ---------- */

function analyze() {
  const bodyEl = document.getElementById("email-body");
  const headersEl = document.getElementById("email-headers");
  const body = bodyEl.value;
  const headers = headersEl.value;

  const resultsEl = document.getElementById("results");

  // Empty state
  if (!body.trim() && !headers.trim()) {
    resultsEl.hidden = false;
    const badge = document.getElementById("risk-badge");
    badge.textContent = "Nothing to analyse";
    badge.className = "risk-badge suspicious";
    document.getElementById("risk-summary").textContent =
      "Paste the contents of a suspicious email above, then click “Analyse Email”.";
    document.getElementById("score-value").textContent = "0";
    document.getElementById("score-ring").style.setProperty("--pct", 0);
    document.getElementById("score-note").textContent = "";
    document.getElementById("findings").innerHTML = "";
    document.getElementById("recommendations").innerHTML = "";
    bodyEl.focus();
    return;
  }

  const bodyLower = body.toLowerCase();
  const headersLower = headers.toLowerCase();
  const urls = extractUrls(body + "\n" + headers);
  const hosts = urls.map(getHost).filter(function (h) { return h; });
  const htmlLinks = extractHtmlLinks(body);

  const fromLine = (headers.match(/^from:.*$/im) || [""])[0];
  const replyToLine = (headers.match(/^reply-to:.*$/im) || [""])[0];
  const fromEmail = (extractEmails(fromLine) || [null])[0];
  const replyToEmail = (extractEmails(replyToLine) || [null])[0];
  const fromHost = fromEmail ? fromEmail.split("@")[1] : "";

  const ctx = {
    body: body, bodyLower: bodyLower,
    headers: headers, headersLower: headersLower,
    urls: urls, hosts: hosts, htmlLinks: htmlLinks,
    fromEmail: fromEmail, replyToEmail: replyToEmail, fromHost: fromHost
  };

  const findings = [];
  RULES.forEach(function (rule) {
    const snippet = rule.test(ctx);
    if (snippet) {
      findings.push({
        id: rule.id, category: rule.category, label: rule.label,
        weight: rule.weight, severity: rule.severity, snippet: snippet
      });
    }
  });

  const rawScore = findings.reduce(function (s, f) { return s + f.weight; }, 0);
  const score = Math.min(rawScore, 100);
  const band = classify(score);

  render(score, rawScore, band, findings);
}

/* ---------- Rendering ---------- */

function render(score, rawScore, band, findings) {
  const resultsEl = document.getElementById("results");
  resultsEl.hidden = false;

  const ring = document.getElementById("score-ring");
  ring.style.setProperty("--pct", score);
  ring.style.setProperty("--ring-color", band.ring);
  document.getElementById("score-value").textContent = score;

  const badge = document.getElementById("risk-badge");
  badge.textContent = band.label;
  badge.className = "risk-badge " + band.className;

  document.getElementById("risk-summary").textContent = band.summary;

  let note = "Score based on " + findings.length + " warning sign" + (findings.length === 1 ? "" : "s") + " detected.";
  if (rawScore > 100) note += " (Raw total " + rawScore + " points, capped at 100.)";
  document.getElementById("score-note").textContent = note;

  const findingsEl = document.getElementById("findings");
  findingsEl.innerHTML = "";
  if (findings.length === 0) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No common warning signs were detected. This does not guarantee the email is safe — always stay alert.";
    findingsEl.appendChild(p);
  } else {
    findings.forEach(function (f) {
      const div = document.createElement("div");
      div.className = "finding severity-" + f.severity;
      div.innerHTML =
        '<div class="finding-head">' +
          '<span class="finding-label">' + escapeHtml(f.label) + '</span>' +
          '<span class="finding-points">+' + f.weight + ' points</span>' +
        '</div>' +
        '<div class="finding-cat">' + escapeHtml(f.category) + '</div>' +
        '<div class="finding-match">' + escapeHtml(f.snippet) + '</div>';
      findingsEl.appendChild(div);
    });
  }

  const recs = buildRecommendations(band, findings);
  const recEl = document.getElementById("recommendations");
  recEl.innerHTML = "";
  recs.forEach(function (r) {
    const li = document.createElement("li");
    li.textContent = r;
    recEl.appendChild(li);
  });

  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------- Demo buttons & wiring ---------- */

function initDemoButtons() {
  const container = document.getElementById("demo-buttons");
  DEMOS.forEach(function (demo) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "demo-btn";
    btn.textContent = demo.title;
    btn.addEventListener("click", function () {
      document.getElementById("email-body").value = demo.body;
      document.getElementById("email-headers").value = demo.headers || "";
      document.getElementById("results").hidden = true;
      document.getElementById("email-body").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    container.appendChild(btn);
  });
}

document.getElementById("analyse-btn").addEventListener("click", analyze);
document.getElementById("clear-btn").addEventListener("click", function () {
  document.getElementById("email-body").value = "";
  document.getElementById("email-headers").value = "";
  document.getElementById("results").hidden = true;
  document.getElementById("email-body").focus();
});

initDemoButtons();







