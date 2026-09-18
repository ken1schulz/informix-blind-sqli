# Blind SQL Injection Against Informix: Validating the Oracle

Informix injection has been documented before. Pentestmonkey tabulated the syntax, F-Secure worked through a blind boolean case in Cisco UCM, and Shea Security published a proof of concept with a working extraction script. What none of them address is whether the oracle is real.

All of that work takes a boolean differential at face value: two inputs produce two different pages, therefore the database is evaluating the injected expression. That inference is usually right and occasionally wrong, and when it is wrong the tooling reports a vulnerability that does not exist.

This post covers the gap. Fingerprinting Informix through a blind channel, establishing a boolean oracle, and then verifying that oracle is actually backed by the database before trusting anything it says.

Testing was done against version 15.0.1.0.3, newer than any version in the existing writeups.

A note on the documentation: Informix sits in a split state where documentation is hosted by HCL while distribution and branding remain IBM. The server banner says IBM Informix Dynamic Server, the container image ships from IBM's registry, everything installs under `/opt/ibm/`, and the syntax reference lives on HCL's site. Searching for it is more annoying than it should be.

## Lab setup

Informix Developer Edition is published as a container image at no cost.

```
docker run -d --name ifx -h ifx \
  -e LICENSE=accept \
  -p 9088:9088 \
  icr.io/informix/informix-developer-database:latest
```

Run it detached. The image's foreground mode holds the container up with a startup shell, and Ctrl+C there stops the container rather than dropping you out of it.

Default credentials are user `informix`, password `in4mix`. Shell in with:

```
docker exec -it ifx bash
```

`dbaccess` is on the path as the `informix` user. The developer image ships no demo schema, so build a throwaway database and a deliberately vulnerable handler in front of it. Every payload below should be validated locally before use anywhere else.

The image initializes with a SMALL sizing profile and a single CPU VP. Fine for syntax work, but worth knowing if you plan to test anything performance sensitive against it.

## Fingerprinting

Confirm the backend before investing in payload construction. Several Informix behaviors are distinctive enough to identify the engine from response differentials alone.

**Concatenation.** The prior work fingerprints on `||` behaving the same as `CONCAT()`. This works but is weaker than it looks, since `||` is also the standard concatenation operator in PostgreSQL, Oracle, and SQLite. Treat it as a first filter, not a confirmation.

**Row limiting.** A common mistake is treating `LIMIT` as a differentiator. It is not. Informix accepts `LIMIT` as a synonym for `FIRST` in the projection clause, and also supports a `LIMIT` clause following `ORDER BY`. A successful `LIMIT` parse rules out nothing.

The distinctive form is the combined skip and first syntax:

```sql
SELECT SKIP 10 FIRST 20 tabname FROM systables
```

**Column subscript notation.** Informix permits subscripting character columns directly:

```sql
SELECT tabname FROM systables WHERE tabname[1,3] = 'sys'
```

This is one of the strongest available fingerprints and it doubles as an extraction primitive. Other engines reject it outright.

**Brace comments.** Informix accepts three comment forms: double hyphen per the ANSI standard, C-style slash-asterisk per SQL-99, and braces as its own extension.

```sql
{ this is a comment }
```

The brace form errors on nearly every other engine, which makes it a clean positive signal. Worth knowing that applications sometimes filter `--` specifically, as SpiderLabs found in a 2013 case where the injection sat inside a FIRST clause, in which case braces are the way through.

**DBINFO.** The function is Informix-specific and exposes useful metadata.

```sql
SELECT FIRST 1 DBINFO('version','full') FROM systables
SELECT FIRST 1 DBINFO('dbname') FROM systables
```

The version parameter returns the full version string as the server startup utility would report it.

**Single-row source.** Informix has no `DUAL`. A `sysdual` table exists under sysmaster in version 11.50 and later, but it is not present in every database by default, so `sysmaster:sysdual` is only conditionally available. The portable form is:

```sql
SELECT 1 FROM systables WHERE tabid = 1
```

Use that in payloads. It works across versions and databases.

## Boolean detection

Standard shape, Informix syntax. A condition that evaluates true or false without erroring either way:

```
' AND 1=1 --
' AND 1=2 --
```

Differential rendering between the two indicates an injectable parameter.

For anything past a yes or no signal, string handling matters. Informix provides `SUBSTR`, `SUBSTRB`, the SQL standard `SUBSTRING ... FROM ... FOR ...` form, and `SUBSTRING_INDEX`, alongside the subscript notation above. Concatenation uses `||` and `LENGTH()` behaves as expected.

### The equals operator question

Shea Security reports that string comparisons cannot be carried out with the equals operator in Informix, which is why that post and the F-Secure one both route everything through `ASCII()` and `SUBSTRING()`.

That is probably narrower than it sounds. Fixed-length CHAR columns pad with trailing spaces, so a comparison against an unpadded literal fails even when the visible content matches. Shea noticed exactly this, describing strings in their environment as ending in a space. If padding is the cause, `=` should work on VARCHAR and on the output of `SUBSTR`, and fail only on raw CHAR column comparisons.

That remains a hypothesis rather than a result. If it holds, the fix is trivial: compare against a padded literal, or wrap the column in `TRIM()`. Worth confirming on a target before assuming `ASCII()` is mandatory.

Direct comparison on a substring result is simple and avoids a function dependency:

```
' AND SUBSTR((SELECT FIRST 1 DBINFO('dbname') FROM systables), 1, 1) = 'a' --
```

The subscript form does the same thing more compactly:

```
' AND (SELECT FIRST 1 DBINFO('dbname') FROM systables)[1,1] = 'a' --
```

The `ASCII()` route, confirmed working by prior work, supports binary search over the character code:

```
' AND ASCII(SUBSTRING(username FROM 1 FOR 1)) > 109 --
```

Binary search is roughly seven requests per character against ninety-odd for linear comparison, so use it where `ASCII()` is available.

## Validating the oracle

This is the part the existing writeups skip, and it is the reason a detection result can be confidently incorrect.

A tautology differential proves that the application renders differently for two inputs. It does not prove the database evaluated anything. An application that branches on input content, a WAF that blocks one string and not another, or a framework that handles a quote differently in two code paths will all produce a clean differential with no SQL execution whatsoever.

The fix is a second confirmation stage using expressions only the database can resolve. Instead of comparing `1=1` against `1=2`, compare two expressions whose truth value depends on database state:

```
' OR (SELECT FIRST 1 tabid FROM systables) = 1 --
' OR (SELECT FIRST 1 tabid FROM systables) = 999999 --
```

Both are structurally identical. Both contain the same keywords, the same quoting, and the same length class. A WAF or an application branch cannot distinguish them. Only the engine can. If the differential holds across this pair as well as the tautology pair, the oracle is real.

Run in sequence, the four checks look like this:

```
[*] Calibrating oracle...
[*] TRUE   len=599 (spread 0)
[*] FALSE  len=376 (spread 0)
[*] separation=223
[*] Oracle: response length
    tautology    true    expected=True  got=True  ok
    tautology    false   expected=False got=False ok
    db-evaluated true    expected=True  got=True  ok
    db-evaluated false   expected=False got=False ok
[+] Oracle confirmed against database-evaluated expressions.
```

The first two checks only show the page looks different for two different inputs. That can happen for reasons that have nothing to do with the database. The last two use expressions the database has to work out for itself, so if those hold up too, something is really running SQL. A run that passes the first pair but fails the second has found a quirk in the application, not an injection.

## Response-length differentials and spread

Response length is a good oracle signal when the application renders deterministically. It is worth measuring spread rather than assuming it.

Sample the true-condition and false-condition responses several times each and record the range. A spread of zero means the page is fully deterministic and any length difference is signal. Nonzero spread means dynamic content is present, timestamps, session tokens, CSRF values, ad slots, and the separation between the two populations must exceed the spread by a comfortable margin before length is usable as an oracle at all.

Sketched out, the viability check is about this much code:

```python
import statistics

def sample_lengths(send, payload, n=8):
    return [len(send(payload)) for _ in range(n)]

def oracle_viable(true_lens, false_lens):
    t_med, f_med = statistics.median(true_lens), statistics.median(false_lens)
    spread = max(max(true_lens) - min(true_lens),
                 max(false_lens) - min(false_lens))
    separation = abs(t_med - f_med)
    return separation > max(spread * 3, 1), separation, spread
```

If length is not viable, fall back to content matching on a stable substring, response code, or timing.

## A note on timing

Informix exposes no SQL-callable sleep function comparable to `SLEEP()` or `pg_sleep()`, so time-based detection has to force expensive work instead. sqlmap already ships Informix payloads for this, built around a heavy query rather than a delay primitive:

```sql
CASE WHEN (condition) THEN (SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR) ELSE 0 END
```

`syspaghdr` scales with stored data rather than schema size, which makes it a better choice than joining catalog tables against themselves.

What is worth adding is calibration. A delay threshold picked in advance produces false positives on any target where network jitter approaches the induced delay. Measure both populations first and place the boundary between them, using median and median absolute deviation rather than mean and standard deviation, since a single slow outlier badly distorts the mean on small samples:

```python
med, mad = baseline(send)
heavy_med = calibrate(send, HEAVY_PAYLOAD)
threshold = med + (heavy_med - med) / 2

if heavy_med - med < 6 * max(mad, 0.05):
    raise RuntimeError("insufficient separation for a timing oracle")
```

The guard matters more than the threshold. A target where the heavy payload adds 200ms against 150ms of natural jitter cannot support a timing oracle at all, and knowing that is better than getting a confident answer from one.

Boolean remains preferable wherever it is available. It is faster, quieter, and places no load on the database.

## Practical notes

Re-baseline periodically during long runs. Load conditions drift, and a threshold calibrated at the start of a session may not hold an hour later.

Expect sqlmap to underperform on enumeration. F-Secure documented it retrieving the current table but failing on other databases and tables, reporting over a thousand users while recovering only one, and failing entirely on password columns. Partial sqlmap output against Informix is not evidence that the injection is limited.

## Closing

None of this is complicated once the pieces are laid out, but the ordering matters. Fingerprint before building payloads, establish the oracle before trusting it, and measure the noise floor before reading anything into a differential. The engine-specific syntax is the easy half. The validation step is what separates a finding from a guess.

The code above is sketched rather than shipped. It comes out of a working tool that is not published, and the fragments are meant to show the shape of the checks rather than to be dropped into anything. Shea Security's post has a complete extraction loop if you want something runnable.

## References

Prior work:

- [Pentestmonkey, Informix SQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet) — tabulated syntax, tested against 11.5
- [Shea Security, Building a proof of concept for blind SQL Injections (2022)](https://sheasecurity.com.au/2022/12/22/ibm-informix-building-a-proof-of-concept-for-blind-sql-injections/) — catalog tables, comment forms, working extraction script
- [SpiderLabs, The Case of an Obscure Injection (2013)](https://www.levelblue.com/blogs/spiderlabs-blog/the-case-of-an-obscure-injection) — injection inside a FIRST clause with `--` filtered
- [sqlmap time-based payloads](https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/payloads/time_blind.xml) — Informix heavy-query payload using `sysmaster:syspaghdr`

Vendor documentation:

- [Row limiting clause: FIRST, SKIP, LIMIT](https://help.hcl-software.com/hclinformix/1410/sqt/ids_sqt_074.html)
- [DBINFO function syntax](https://help.hcl-software.com/hclinformix/15.0.0/sqs/ids_sqs_1484.html)
- [DBINFO 'version' option parameters](https://help.hcl-software.com/hclinformix/1410/sqs/ids_sqs_1491.html)
- [SQL comment indicators](https://help.hcl-software.com/hclinformix/15.0/sqs/ids_sqs_0209.html)
- [System-Monitoring Interface tables](https://help.hcl-software.com/hclinformix/1410/adr/ids_adr_0210.html)
