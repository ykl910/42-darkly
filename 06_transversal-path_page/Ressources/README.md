# Flag — Local File Inclusion / Path Traversal (page parameter)

**Category:** OWASP A05:2025 – Injection
**Sub-type:** Local File Inclusion (LFI) / Path Traversal (CWE-98)
**Location:** `/?page=../../../../../../../etc/passwd`

---

## 1. Discovery

Almost every page on the site is loaded through `?page=<pagename>`. We assumed the
backend does something like:

```php
include($_GET['page'] . '.php');
```

If user input is dropped straight into `include()`, we can make it include files it
was never meant to — including files outside the web root, via `../` path traversal.

We tried increasing numbers of `../` to climb up to the filesystem root and reach
`/etc/passwd`. The application gives hints ("almost", "still no") depending on how
close the number of `../` is, which guided us to the right depth — and the flag.

```
/?page=../../../../../../../etc/passwd
```

## 2. Impact

When a real LFI is exploitable, an attacker can read **any file the web server can
access** — far beyond the intended pages:

- Configuration files holding **database credentials**.
- System files such as `/etc/passwd`, server logs, etc.

In worse cases, LFI can be escalated to **remote code execution** — e.g. by poisoning
a file the attacker can write to (log files via the `User-Agent`, an upload) with PHP
code, then including it through `page=`.

## 3. Remediation

The flaw is that the user controls which file gets included. 

- **Whitelist the allowed pages** Never include the raw parameter;
  only allow a fixed, known set of page names, and fall back to a default otherwise:

  ```php
  $pages = ['home', 'signin', 'feedback', 'searchimg'];
  $page  = in_array($_GET['page'], $pages, true) ? $_GET['page'] : 'home';
  include $page . '.php';
  ```

  `../../../etc/passwd` is never in the list, so it is never included. 