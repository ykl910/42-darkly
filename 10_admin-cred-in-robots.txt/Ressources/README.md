# Flag — Admin credentials file exposed (via robots.txt)

**Category:** OWASP A02:2025 – Security Misconfiguration
**Sub-type:** Sensitive file exposed in web root + directory listing; compounded by
weak, unsalted MD5 password hashing (A07:2025 – Authentication Failures)
**Location:** `/admin/` (login), via `/whatever/` → `.htpasswd`

---

## 1. Discovery

During our exploration of the VM we looked for an `/admin` page, as many sites have
one. It was indeed there. We tried to brute-force it like the other sign-in page — it
might have worked with more time — but we found a better way.

We looked up `/robots.txt` — a file found on most sites that tells crawlers which
paths not to index. It is **purely informative and blocks nothing**; for an attacker
it simply advertises paths the admin wanted hidden. It showed:

```
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

We went to `/whatever` and downloaded a file named `.htpasswd`. This is the Apache
file used to store credentials for HTTP Basic Auth, as `user:hash` pairs. Its content:

```
root:437394baff5aa33daa618be47b75cb49
```

The hash is a **32-character string → MD5**. Logging in with the raw hash didn't work,
so we **cracked** the MD5 (a very common weak hash on this VM):

```
437394baff5aa33daa618be47b75cb49  →  qwerty123@
```

Logging in to `/admin/` as `root` / `qwerty123@` gave us the flag.

## 2. Impact

A file containing administrator credentials was **downloadable by anyone**, with its
location conveniently advertised in `robots.txt`. No exploit needed — just read a
public file. Two weaknesses chain here:

- the credentials file sits in a **web-accessible directory** (with listing enabled),
- and the password is hashed with **weak, unsalted MD5**, so it cracks instantly to a
  guessable password (`qwerty123@`).

The result is **full administrative access** to the panel, with everything that
implies. Anyone who reads `robots.txt` reaches the same result in a couple of minutes.

## 3. Remediation

- **Never store credential files in a web-accessible location.** Keep `.htpasswd`
  (and any secret) outside the web root, or block access to it in the server config
  (e.g. deny `.ht*` files — Apache does this by default when configured correctly).
- **Disable directory listing** so a folder like `/whatever` can't reveal its files.
- **Don't put sensitive paths in `robots.txt`.** It is public and only advertises
  what you want hidden — it is not an access control. Protect the resources properly
  instead of hiding them.
- **Use strong, salted password hashing** (bcrypt / argon2), never plain MD5, so an
  exposed hash isn't trivially cracked.
- **Enforce strong passwords** — `qwerty123@` is a common, guessable value.
