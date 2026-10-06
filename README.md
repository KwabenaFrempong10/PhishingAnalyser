# Phishing Email Analyser — Project Guide

A friendly, plain-English guide to the whole project. Use this to explain any part of it —
what it does, how it works, and the thinking behind each decision.

---

## 1. What is this project?

It is a **web application** that helps people spot warning signs in suspicious emails.
A user pastes the text of an email, clicks **"Analyse Email"**, and the app shows:

1. A **risk score** from 0 to 100.
2. A **classification** — Low Risk, Suspicious, or High Risk.
3. A **list of every warning sign** it found, with the exact text that triggered it.
4. **Practical advice** on what to do next.

The whole point is **education**: it does not block spam or remove viruses. It teaches
people to recognise the tricks used in phishing and social-engineering attacks.

---

## 2. The most important design decision: privacy

This project has one hard rule:

> **Email content is analysed entirely inside the visitor's web browser and is never
> sent anywhere.**

There is:
- No backend server.
- No database.
- No user accounts.
- No external AI or APIs.
- No API keys.
- No analytics, cookies, or telemetry.

The entire app is **static** — just three files that any web server (or even no server at
all) can host. Because all the logic runs in the browser, a user could download the page,
disconnect from the internet, and it would still work perfectly.

This matters because phishing analysis involves very sensitive data (real emails). A good
tool must not make the problem worse by leaking that data to a third party.

---

## 3. The three files (and what each one does)

The whole application is deliberately simple. It has no frameworks and no package
dependencies. It uses only the three native web technologies:

| File | Role |
|------|------|
| `index.html` | The **structure**: the text boxes, buttons, demo examples, and notices. |
| `styles.css` | The **appearance**: colours, layout, the risk score ring, and mobile support. |
| `script.js` | The **brain**: all detection rules, the scoring, and drawing the results. |

**Why three files?** Separation of concerns. Structure, style, and logic are kept apart,
which makes the code easier to read, learn from, and extend. You can change the colours
without touching the logic, and add a new rule without touching the layout.

---

## 4. How the analysis works, step by step

When the user clicks **Analyse Email**, `script.js` does this:

1. **Read** the text from the two boxes (email body, and optional email headers).
2. **Prepare** the text: convert to lowercase and extract useful things such as every
   URL, every domain name, and every `<a>` link.
3. **Run the rules.** It loops through a list of about 25 named warning signs. Each rule
   is a small test that returns *the text it matched*, or nothing.
4. **Add up the points.** Each rule has a fixed point value ("weight"). The points of all
   matched rules are summed and capped at 100.
5. **Classify** the result into Low Risk, Suspicious, or High Risk.
6. **Display** the score, the classification, the list of findings with their points, and
   tailored recommendations.

Because every finding is shown with its points and the matched text, the score is always
**explainable** — there is no mysterious "black box" number.

---

## 5. How the score is calculated

This is the heart of the project, so it is worth understanding well.

- Every warning sign (rule) is worth a **defined number of points**.
- More serious signs are worth more points. For example:
  - "Requests payment via gift cards" = **18 points** (a strong sign of fraud).
  - "Requests your password" = **15 points**.
  - "Uses urgent language" = **8 points** (weak on its own, meaningful in combination).
  - "Uses a generic greeting" = **4 points** (a soft signal).
- The app sums the points of all rules that fired, then **caps the total at 100**.

### The three bands

| Score | Label | Colour | Meaning |
|-------|-------|--------|---------|
| 0–24  | Low Risk | Green | Few or no warning signs found. |
| 25–59 | Suspicious | Amber | Several signs worth investigating. |
| 60–100| High Risk | Red | Many strong signs — treat as likely malicious. |

**Why cap at 100?** A percentage-style number from 0–100 is easy for anyone to understand,
and capping prevents the score from becoming a meaningless large number when an email
contains many overlapping signs.

**Why is the number explainable and not a mystery?** Because the interface lists every
warning sign that fired, next to its exact point value. A user can add up the numbers
themselves and see exactly why they got the score they did.

---

## 6. What warning signs are detected?

The rules are grouped into logical categories:

| Category | Examples of what it looks for |
|----------|-------------------------------|
| Urgency & pressure | "urgent", "act now", "within 24 hours", "final notice" |
| Threats & consequences | account suspension/closure, legal action, "your access will be lost" |
| Credential harvesting | asking for passwords, MFA/verification codes, "verify your account" |
| Financial requests | unexpected payments/fees, gift cards, changing bank details, invoices |
| Links & URLs | lookalike domains, shortened URLs, raw IP addresses, misleading link text |
| Impersonation | claiming to be IT/security/support, generic greetings, brand spoofing |
| Attachments | executable files (`.exe`, `.bat`, `.js`…), macro-enabled documents, double extensions |
| Email headers | sender vs Reply-To mismatch, SPF / DKIM / DMARC failures |

### A note on "suspicious URLs"

Detecting a "lookalike" domain is done with a **heuristic** (a rule of thumb), not with a
live threat database. The app keeps a small list of well-known brands (Microsoft, PayPal,
Amazon, and so on). If a domain contains a brand name but is *not* the brand's real
domain — for example `login-microsoft.example` — the app flags it. This is intentionally
simple and is explained as a *signal*, never as proof.

---

## 7. Email headers, SPF, DKIM and DMARC (advanced, optional)

Most people only paste the visible body of an email. But a phishing email is often exposed
by its **headers** — hidden technical lines that travel with the message.

The app has an optional, clearly-labelled **"email headers"** box. If the user pastes full
headers, the app can detect:

- **Sender vs Reply-To mismatch** — the "From" address looks legitimate, but replies go to a
  different, attacker-controlled address.
- **SPF failure** — the sending server was not authorised to send mail for that domain.
- **DKIM failure** — the message's digital signature is missing or invalid.
- **DMARC failure** — the domain's policy check failed.

These checks only run when headers are provided, and they are explained in plain English
so a beginner can understand what they mean.

---

## 8. The demo emails (and why they are safe)

The app includes six **completely fictional** example emails:

1. Obvious phishing (a "you won a prize" scam)
2. Sophisticated phishing (a fake IT security review)
3. Fake Microsoft 365 account warning
4. Fake parcel-delivery message
5. Fake invoice / Business Email Compromise (BEC) style
6. A legitimate email

Every demo uses the reserved domain ending **`.example`**. This top-level domain is
reserved for documentation and can never be registered or resolve to a real website.
That means none of the "links" in the demos are real or clickable to anything harmful.
This lets a learner safely explore what a high-risk email looks like.

---

## 9. Safety and accuracy — what the tool is and is not

The project is honest about its limits:

- It is an **educational triage tool**, not a definitive security verdict.
- It **never** claims to prove an email is malicious or safe.
- It **warns users not to click links or open attachments just to test them**.
- It tells users to **verify important messages independently** using an organisation's
  official website, app, or a known phone number.

This honesty is a key part of the design: a tool that over-promises ("this email is 100%
safe") would be dangerous, because no text-based rule can ever be certain.

---

## 10. How to run it and how to host it

**To run it locally:** double-click `index.html`. It opens in your browser and works
immediately — no installation, no internet needed.

**To host it (free static hosting):** upload the three files to any static host such as
GitHub Pages, Netlify, Cloudflare Pages, or any simple web server. Because there is no
backend, nothing else is required and it stays free for visitors.

---

## 11. How to extend it (add your own rule)

Adding a new warning sign is easy. In `script.js`, inside the `RULES` array, copy an
existing rule and change three things:

1. `label` — a clear human-readable name.
2. `weight` — how many points it is worth.
3. `test` — the list of trigger phrases (or a custom check).

Example of a brand-new rule that flags the phrase "wire me money":

```js
{
  id: "wire_request",
  category: "Financial Requests",
  label: "Asks you to wire money",
  weight: 14,
  severity: "high",
  test: function (ctx) {
    return matchPhrase(ctx.body, ["wire me money", "send a wire", "wire transfer"]);
  }
}
```

That is the entire pattern. The scoring, classification, and display update automatically.

---

## 12. Glossary (useful terms)

- **Phishing** — a fake message that tries to trick you into revealing secrets (passwords,
  codes, bank details) or into clicking a harmful link / opening a harmful file.
- **Social engineering** — manipulating people rather than breaking computers.
- **MFA (Multi-Factor Authentication)** — a second "proof of identity" step, usually a
  code from an app or SMS. Attackers love to steal these codes.
- **BEC (Business Email Compromise)** — a scam where an attacker impersonates a boss or
  supplier to trick a business into paying a fake invoice or changing bank details.
- **SPF / DKIM / DMARC** — three email authentication standards that help prove a message
  really came from the domain it claims to be from.
- **Lookalike domain** — a fake address designed to resemble a real one, e.g.
  `micros0ft.example` or `paypal-login.example`.
- **Triage** — sorting things by urgency/importance; here, a first quick check, not a full
  investigation.


