# Interview Prep — Phishing Email Analyser

A plain-English guide to help you explain and defend this project in an interview,
even without a programming background. Read it, then practise saying the answers out loud.

---

## Part 1 — Your 90-second project pitch

This is the answer to *"Tell me about your project."* Keep it to about a minute and a half.
Memorise the flow, not the exact words.

> "I built a **Phishing Email Analyser** — a web application that helps people recognise
> phishing and social-engineering warning signs in suspicious emails.
>
> A user pastes the text of an email, and the app gives them a **risk score from 0 to 100**,
> a **classification** of Low Risk, Suspicious or High Risk, a **list of every warning sign
> it detected with the exact text that triggered it**, and **advice on what to do next**.
>
> The most important design decision was **privacy**. Phishing emails are sensitive, so the
> analysis runs **entirely inside the visitor's browser** — the email text is never uploaded
> to a server, an AI provider, or any third party. There's no backend, no database, and no
> tracking. It's built with plain HTML, CSS and JavaScript and can be hosted as a free static
> website.
>
> The part I'm most proud of is that the **score is explainable, not a black box**. The app
> checks the email against around 25 named warning signs — like 'requests a password' or
> 'requests payment by gift card' — each worth a defined number of points. The points are
> added up and capped at 100, and the app shows exactly which rules fired and why."

---

## Part 2 — A structured walkthrough (if they ask "how does it work?")

Walk through it in three layers, in this order:

1. **Input** — the user pastes an email body, and optionally the full email headers.
2. **Analysis** — the app scans the text against a list of warning signs across eight
   categories: urgency, threats, credential requests, financial requests, suspicious links,
   impersonation, dangerous attachments, and email-authentication failures (SPF/DKIM/DMARC).
3. **Output** — it sums the points of everything it found (capped at 100), classifies the
   email into Low/Suspicious/High Risk, and lists each finding with its points plus tailored
   recommendations.

Then name the **key technical ideas** an interviewer wants to hear:

- **Client-side analysis** (everything runs in the browser — privacy by design).
- **Static site** (no server, no database, no dependencies, no API keys).
- **Rule-based, explainable scoring** (weighted rules, not machine learning).
- **Safety honesty** (it never claims to be definitive; it's an educational triage tool).

---

## Part 3 — Anticipated questions and model answers

### Q1. "How does the scoring actually work?"
Every warning sign is a rule with a fixed **point value** ("weight"). More serious signs are
worth more — asking for a gift card is worth more than using urgent language. The app sums
the weights of all rules that matched, **caps the total at 100**, and maps it to three bands:
0–24 Low Risk, 25–59 Suspicious, 60–100 High Risk. Crucially, the interface lists each
detected rule with its points, so the score is fully explainable.

### Q2. "Why did you keep everything in the browser instead of using a server?"
Because the data — real emails — is extremely sensitive. A phishing analyser that uploads
emails would be leaking the very thing it's meant to protect. Running it client-side means
**the email never leaves the user's device**, which is both a privacy win and a security
principle: you can't leak data you never collect. It also makes the app free to host and
maintain.

### Q3. "Why plain HTML, CSS and JavaScript and not a framework like React?"
The project didn't need a framework. The analysis is a set of text-matching rules, which is
small enough to keep simple. Using only native web technologies means **no build step, no
package dependencies, no vulnerabilities from third-party libraries**, and a smaller attack
surface — which is itself a cybersecurity lesson. It also runs fully offline.

### Q4. "What is phishing, and how is it different from social engineering?"
Phishing is a specific type of attack — a fake message (email, text, etc.) designed to trick
someone into revealing secrets or clicking a harmful link. Social engineering is the broader
idea of manipulating people rather than hacking computers. Phishing is one form of social
engineering; other forms include phone scams ("vishing") and pretexting.

### Q5. "What are SPF, DKIM and DMARC, in simple terms?"
They are three email **authentication** standards that help prove a message really came from
the domain it claims to be from. SPF checks whether the sending server is allowed to send for
that domain; DKIM checks a digital signature on the message; DMARC tells the receiving server
what to do if the first two fail. If any of these fail in the email headers, it's a strong
signal the sender address may be spoofed.

### Q6. "What is BEC, and why is it dangerous?"
Business Email Compromise is a scam where an attacker pretends to be a boss or a supplier to
trick a business into paying a fake invoice or changing where money is sent. It's dangerous
because it targets people and processes rather than software, and it often leads to large
financial losses. My app has a whole demo and rules for this ("unexpected invoice", "change
bank details", "sender/Reply-To mismatch").

### Q7. "What is a 'heuristic'?" (they may pick up on this word)
A heuristic is a rule of thumb — a simple, fast, usually-good-enough test, rather than an
exact answer. My "lookalike domain" detection is heuristic: if a URL contains a well-known
brand name but isn't the brand's real domain, I flag it. It's not proof, but it's a useful
signal.

---

### Q8. "Can this tool definitively say an email is malicious?"
No — and I deliberately built it to **never claim that**. Text rules can only find warning
signs; they can't see the real destination of a link or the contents of an attachment. So the
app calls itself an *educational triage tool*, warns users not to click links to test them,
and tells them to verify independently. That honesty is a feature, not a weakness.

### Q9. "What are the limitations of your approach?"
A few I'm upfront about:
- It's **text-only** — it can't follow a link, scan an attachment, or check a live reputation
  database, because that would require sending data to a server.
- The suspicious-URL detection is **heuristic**, so it can miss clever lookalikes or flag
  edge cases.
- There's no machine learning, so it can't learn new patterns over time.
- A low score doesn't guarantee safety.

### Q10. "What would you improve or add next?"
Good, safe answers that respect the privacy requirement:
- More detection rules and a larger, regularly-updated list of phishing indicators.
- Better link analysis that still stays local (e.g. decoding short URLs manually where safe).
- Accessibility improvements and a clearer visual breakdown of the score.
- If privacy could be preserved, optional integration with public reputation feeds — but I'd
  keep that opt-in and never send raw email content.

### Q11. "Did you write all the code yourself?"
Be honest — honesty reads as maturity. Suggested answer:

> "I'm a cybersecurity enthusiast, not a developer, so I used an AI coding assistant and
> treated it as a collaboration — I defined the requirements, the privacy rules and the
> scoring approach, and it generated the code, which I then tested. My focus was on
> understanding *what* the code does and *why* each decision was made, rather than memorising
> syntax. The key concepts — client-side analysis, weighted scoring, and the phishing
> indicators — are mine and I can explain all of them."

### Q12. "What was the hardest part?"
A strong, honest answer:

> "The hardest part was making the score **explainable** rather than a mysterious number. It's
> easy to add up points, but I wanted every result to be defensible — so each warning sign has
> a defined weight, the total is capped at 100, and the interface shows exactly which rules
> fired. The second challenge was honouring the privacy requirement absolutely: no shortcuts
> like calling an external API that would have made the analysis smarter but would have leaked
> the email."

### Q13. "What did you learn from this project?"
> "I learned that good security tools put **privacy first by design** — the safest data is data
> you never collect. I learned how phishing actually works by studying the warning signs, and
> I learned to reason about an explainable scoring model. Most of all I learned to ask
> 'what can this tool *not* do?' and be honest about it."

---

## Part 4 — Quick-fire terms you should be able to define in one sentence

- **Phishing** — a fake message trying to steal secrets or make you click/open something harmful.
- **Spear phishing** — phishing aimed at a specific person.
- **Social engineering** — manipulating people instead of hacking computers.
- **MFA** — a second identity check (a code), which attackers try to steal.
- **BEC** — impersonating a boss/supplier to redirect payments.
- **SPF / DKIM / DMARC** — email authentication standards.
- **Lookalike domain** — a fake address that mimics a real brand.
- **Triage** — a quick first assessment, not a full investigation.
- **Client-side / in-browser** — code that runs on the user's device, not a server.
- **Static website** — fixed files served as-is, no backend.
- **Explainable scoring** — every result can be traced back to the rules that caused it.

---

## Part 5 — Tips for the interview itself

1. **Lead with the privacy decision.** It's your strongest, most memorable point.
2. **Always tie features back to "why".** Not just "I detect urgent language", but "urgent
   language is a classic pressure tactic, so it's worth 8 points".
3. **Volunteer the limitations.** Saying "it's not definitive, and here's why" shows
   maturity and earns trust.
4. **It's fine to say you used AI assistance** — but be ready to explain the *concepts* in
   your own words, which this guide lets you do.
5. **Practise the pitch out loud** until it's smooth but not robotic.


