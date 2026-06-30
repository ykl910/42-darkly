# Flag — Brute-force login

**Category:** OWASP A07:2025 – Authentication Failures
**Sub-type:** No protection against brute-force : no rate-limiting/lock out  + weak password
**Location:** `/?page=signin`

---

## 1. Discovery

After looking around for a while, we noticed the sign-in form is a **GET** form —
the credentials are sent in the URL. That makes it easy to script and brute-force.

We started with the most common username: `admin`. Submitting `admin/admin`:

```bash
curl -s "http://192.168.56.107/?page=signin&username=admin&password=admin&Login=Login"
```

we saw that a failed login returns a response containing `WrongAnswer.gif`. That
string is our **failure marker**: when it is *absent* from the response, the login
is a candidate.

We downloaded a small common-password list
(<https://weakpass.com/wordlists/hashmob.net_2025.small.found>) and wrote a short
shell script (`/Ressources/bruteforce.sh`) that loops over it: for each password,
when `grep WrongAnswer.gif` fails (marker absent), we have a hit.

It found `shadow`. Logging in with `admin` / `shadow` gave us the flag.

## 2. Impact

The login has **no protection against automated guessing** — no rate-limiting, no
account lockout, no delay — so an attacker can try unlimited passwords until one
works.
The GET form makes it even easier, since the whole attempt is a
single URL.

The result is **account takeover**: any account with a guessable password can be
compromised, and an attacker can run the same attack against every username to
harvest valid credentials at scale.

## 3. Remediation

- **Rate-limit and lock out.** Limit the number of failed attempts per account and
  per IP (e.g. temporary lockout or increasing delay after N failures). This is the
  core fix — it makes brute-force impractical.
- **Enforce a strong password policy** (length, complexity) and reject common
  passwords like `shadow`, so guessing has nothing easy to find.
- **Add a second factor (2FA / CAPTCHA)** on the login to break automated scripts.
- **Use POST over HTTPS** instead of GET. This does **not** stop brute-force on its
  own, but it keeps credentials out of the URL, browser history, and server logs —
  a separate, worthwhile improvement.