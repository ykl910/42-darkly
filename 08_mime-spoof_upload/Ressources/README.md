# Flag — MIME spoof (file upload)

**Category:** OWASP A05:2025 – Injection
**Sub-type:** Unrestricted File Upload (CWE-434)
**Location:** `/?page=upload`

---

## 1. Discovery

Upon navigating to the upload page, we sensed a flag could be found here.

Looking at the DOM first, we saw a straightforward form with a hidden input:

```html
<input type="hidden" name="MAX_FILE_SIZE" value="100000">
```

which is once again a flaw — we can change the per-file size limit from the client
side — but that wasn't the flag.

Then we tried uploading files:

- `.jpeg` → `/tmp/test.jpeg successfully uploaded`
- `.php` → `Your image was not uploaded` (same for `.jpeg.php`)

So the server rejects our PHP by extension. We then sent a `.php` file while
**declaring its `Content-Type` as a JPEG** directly in the request with curl:

```bash
curl -F "uploaded=@test.php;type=image/jpeg" -F "Upload=Upload" "http://192.168.56.102/?page=upload"
```

- `-F` sends a `multipart/form-data` field.
- `uploaded` is the name of the file input to fill.
- `Upload` is the name of the submit input.
- `;type=image/jpeg` forges the MIME type of the file.

It worked, and the flag was in the HTML response. This tells us the server validates
uploads **only on the client-declared `Content-Type`** — a value the attacker fully
controls — instead of checking the real file content or refusing executable
extensions.

## 2. Impact

The upload filter is trivially bypassed by faking one header. That lets an attacker
upload a **`.php` file the server will execute**

This is a path to **remote code execution (RCE)** and full server compromise: reading
any file (credentials, config), pivoting, etc. It is one of the most severe web
flaws — an image upload turned into command execution.

## 3. Remediation

The core problem is trusting client-supplied metadata. Fixes, combined:

- **Validate the real file content, not the declared MIME.** Check the actual bytes
  (e.g. `getimagesize()` / magic bytes) server-side; never trust the `Content-Type`
  the client sends — it is attacker-controlled.
- **Whitelist safe extensions** and reject executable ones (`.php`, `.phtml`,
  `.php5`, …). Whitelist ("only these are allowed") over blacklist.
- Do not rely on the client-side `MAX_FILE_SIZE`; enforce the size limit server-side.
