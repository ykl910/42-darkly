# Flag — Recover Page (hidden field tampering)

**Category:** OWASP A01:2025 – Broken Access Control
**Sub-type:** Client-side parameter tampering (hidden field manipulation) — recovery
e-mail recipient hijacking
**Location:** `/?page=recover`

---


## 1. Discovery

The recover page submits a `POST` form. Opening the inspector (F12), we noticed the
form contained a **hidden input** holding an e-mail address — the address to which
the recovery information would be sent:

```html
<input type="hidden" name="mail" value="webmaster@borntosec.com">
```

That value is set on the **client side**, so we are free to change it. We edited the
hidden field to our own address and submitted the form — and got the flag.

The root issue: the application decides *where to send the recovery information*
based on a value the user fully controls, instead of determining it server-side.

## 2. Impact

**Primary impact — hijacking the recovery information / potential account takeover.**
By changing the destination address, we redirect to ourselves an e-mail that was
meant for someone else. If that e-mail contains a password-reset link (or any
sensitive recovery information), we receive it and can **reset the victim's password
and take over their account** — without ever knowing their current credentials.


**Secondary impact — mail bombing / abuse of the send function.** Because the
endpoint sends an e-mail on demand with an attacker-controlled recipient, it can be
abused to spam an arbitrary address by looping the request:

```bash
curl -s -X POST -d "mail=<target>" -d "Submit=Submit" "<IP>/index.php?page=recover"
```

Run in a loop, this floods the target's inbox (a denial-of-service / abuse vector).

## 3. Remediation

The destination address must **never** come from the client.

- **Derive the recipient server-side.** The application should look up the e-mail
  associated with the account being recovered **in its own database**, and send the
  recovery message there. The user only provides *which account* (e.g. a username or
  the account e-mail to match against), never the destination address to send to.
- **Never trust hidden fields** (or any client-supplied value) for a security
  decision — "hidden" is not "protected"; the client can read and rewrite it freely.
- **Rate-limit** the recovery endpoint (per IP / per account) to prevent the
  mail-bombing abuse, and always return a generic response ("if an account exists, an
  e-mail has been sent") to avoid leaking which accounts exist.