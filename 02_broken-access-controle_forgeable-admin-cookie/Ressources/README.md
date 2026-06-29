# Flag — Forgeable Admin Cookie

**Category:** OWASP A01:2025 – Broken Access Control
**Sub-type:** Privilege escalation via a forgeable authorization cookie (cookie tampering)
**Location:** Browser cookies (F12 → Storage → Cookies)

---

## 1. Discovery

We inspected the site's cookies to see whether anything could be tampered with:
**F12 → Storage → Cookies**.

There was one cookie:

```
Name : I_am_admin
Value: 68934a3e9455fa72420237eb05902327
```

The value is a **32-character hexadecimal string**, i.e. the signature of an
**MD5 hash**. We cracked it and it turned out to be the MD5 of:

```
false
```

So the application was storing our admin status as `MD5("false")` in a cookie.
The idea followed naturally: compute `MD5("true")` and replace the cookie value
with it:

```
MD5("true") = b326b5062b2f0e69046810717534cb09
```

We edited the cookie value to that hash and reloaded. An alert appeared with the
flag:

```
df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3
```

## 2. Impact

By editing a **single cookie value**, any anonymous visitor can set themselves as
administrator — no account, no password, no login. The admin check is defeated for
two specific reasons:

- The stored value is just `MD5("false")`, and `MD5("true")` is trivial to compute.
  The set of possible values is tiny and public, so the hash is not a secret and
  guarding nothing.
- The cookie carries **no server-side signature**. Nothing ties the value to the
  server, so the server cannot tell a value *it* issued apart from one the attacker
  forged. Whatever the client sends, the app trusts.

Concretely: the entire admin authorization check can be bypassed by anyone, and
every page or feature gated behind the `I_am_admin` flag becomes reachable without
authentication. The control provides no protection at all.

*(Matching CWE: CWE-565 – Reliance on Cookies without Validation and Integrity
Checking.)*

## 3. Remediation

The flaw is that an authorization decision lives on the client. The fixes are
specific to that:

- **Do not derive admin status from a client-side cookie.** `I_am_admin` should not
  exist as a source of authorization. Whether a user is an administrator must be
  decided **server-side**, from an authenticated session — never from a value the
  browser can rewrite.
- The cookie should carry only an **opaque, random session identifier**; the server
  then looks up that session in its own store to know the user's role.
- **If a value must travel in a cookie, sign it** (HMAC + a server-side secret) so a
  forged `MD5("true")` is rejected — any tampering is detected.
- **Never use an unkeyed hash (MD5) as if it were a secret or a signature.**