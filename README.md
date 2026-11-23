# File upload to RCE: a lab walkthrough

A write-up of how three ordinary web weaknesses, an authenticated file upload, a Local File Inclusion, and default PHP session handling, combine into remote code execution.

I built the lab myself and ran every step against it. No third-party systems are involved, and this write-up contains no certification exam material. The point is the technique and, just as much, how a defender would catch it.

## The lab

A small PHP application with three issues that each look minor on their own:

- An authenticated upload form that saves files under `/var/www/html/uploads/` and rejects a short denylist of extensions (`.php`, `.phtml`).
- A router that includes a page by name: `include("pages/" . $_GET['page'] . ".php");`.
- Default PHP sessions on disk at `/var/lib/php/sessions/sess_<id>`, with the session id in the `PHPSESSID` cookie.

```
Upload (denylist)   +   include($_GET['page'])   +   predictable session file
        |                        |                            |
        +------------------------+----------------------------+
                                 v
                   attacker-controlled code runs as www-data
```

None of these is critical by itself. The upload filter blocks the obvious payload, the include only serves local pages, and sessions are a normal PHP feature. Chained, they reach code execution.

## Stage 1: get attacker-controlled text onto disk

The include is the sink, so I need PHP code written somewhere on the host. Two paths work in this lab.

#### Path A: the upload

The denylist blocks `.php` and `.phtml` but not every handler extension. Depending on the server config, `.pht` or a double extension slips past the check while still being parsed as PHP. The filter reads the last dot or a fixed list, so a name the filter does not recognize but the web server does is enough.

#### Path B: the session file

I do not even need a file that the server will execute directly. PHP writes session data to a predictable path, and it writes values I control. If I put PHP source into a value that lands in the session, the session file on disk now holds my code. The classic carrier is a header the app stores, for example the `User-Agent`, reflected into `$_SESSION`.

Path B matters because it works even when the upload is locked down. The weakness is that I can write bytes I choose to a path I can predict, and the upload is only one way to do that.

## Stage 2: Local File Inclusion

The router trusts `$_GET['page']`:

```
GET /index.php?page=../../../../etc/passwd%00
GET /index.php?page=php://filter/convert.base64-encode/resource=config
```

Directory traversal reaches files outside `pages/`, and PHP wrappers read source I could not otherwise see. On older or misconfigured setups a null byte truncates the appended `.php`. On its own this is file read, not code execution. It becomes execution once it points at the bytes from Stage 1.

## Stage 3: from read to execution

```
GET /index.php?page=/var/lib/php/sessions/sess_<my-session-id>
```

The include pulls in the session file, and PHP executes the source I planted in Stage 1. A minimal payload turns the request into a command runner:

```
<?php system($_GET['c']); ?>
```

From there, `?page=<session-file>&c=id` runs commands as the web server user. The same result follows from including the uploaded file in Path A. Either way, a read primitive plus controlled content on disk equals execution.

## Why each control failed

- The upload used a denylist, so it only had to miss one parsable extension. An allowlist fails closed; a denylist fails open.
- The include passed user input straight into a filesystem path. Any value that walks the path or names another file is now in scope.
- Sessions were written to a predictable location with attacker-influenced content, which turned a normal feature into a writable staging area.

Severity comes from the chain. A triage that rates each issue low in isolation misses the path that connects them.

## How a defender would catch this

This is the half I care about most, because it is where the offensive view pays off on the blue side.

- A stored file whose extension and content type disagree, or a non-image written into an uploads directory. Maps to MITRE ATT&CK T1505.003 (web shell).
- `include`/`require` resolving to a path outside the application root, or to `/var/lib/php/sessions/`, `/etc/`, or a `php://` wrapper. Visible in application logs and in file-access telemetry.
- The web server process (`www-data`, `php-fpm`) spawning `/bin/sh`, `id`, `whoami`, or a network tool. A web server rarely has a legitimate reason to start a shell, so this is the loudest and most reliable signal in the chain. Maps to T1059 (command and scripting interpreter).

A SOC that alerts on "web service process spawned a shell" catches this chain at the last stage even if every earlier step was missed.

## How to fix it

- Allowlist upload extensions, verify content type, store uploads outside the web root, and rename files to random identifiers.
- Never put user input into `include`/`require`. Map a fixed set of page names to fixed files, and reject anything not in the map.
- Harden PHP: `allow_url_include=Off`, and keep session storage off any path the application will include.

## What I took from this

A read primitive is not harmless once an attacker can also write chosen bytes to a known location. The interesting work is connecting weaknesses, and the same mental model that finds the chain also tells a defender which single event to alert on.

---

Scope and ethics: every step here ran against a lab I built and control. No third-party or production systems were tested, and this includes no certification exam content.
