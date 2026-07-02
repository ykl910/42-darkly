# Flag — Survey hack (vote value tampering)

**Category:** OWASP A06:2025 – Insecure Design
**Sub-type:** Missing server-side input validation — CWE-20
**Location:** `/?page=survey`

---

## 1. Discovery

We went to the survey page and saw you can vote on subjects with a weighted vote —
from 2 to 10 — by picking a value in a `<select>` form.

Picking a number increases the vote count and updates the subject's average grade.
So it should be impossible for any average to be above 10.

The fact that one average was tremendously above 10 made us try to change the value
of an `<option>` inside the `<select>` to a much larger number (editing it directly
in the DOM). After selecting it and submitting, the flag appeared.

The root issue: the allowed range (2–10) is enforced only by the `<option>` values in
the client-side form. The server **accepts whatever value is submitted** without
checking it is within the legitimate range.

## 2. Impact

Any user can submit an **out-of-range vote** (e.g. 999) and skew the results
arbitrarily — the average is pushed above its maximum, results become meaningless,
and the ranking can be manipulated at will. More generally, trusting client-supplied
values without server-side bounds checking corrupts the integrity of the data: what
the application treats as a constrained choice is in fact fully attacker-controlled.

## 3. Remediation

The fix is server-side validation — the client form is not a security boundary.

- **Validate the value server-side** against the allowed range on every submission:
  reject (or clamp) anything outside `2–10` before it is stored or counted.
- **Never trust the `<option>` values** the client sends back; the DOM can be edited
  freely, so the list of choices in the form is not a constraint.
- Prefer a **whitelist of accepted values** (only 2..10 are valid) rather than trying
  to filter out bad ones.
