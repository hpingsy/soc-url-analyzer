# soc-url-analyzer

Python 3.13 URL threat analysis lab. Analysis is entirely offline: it performs
no HTTP requests, DNS lookups, redirects, or reputation-service calls.

Create a virtual environment and install the package and development tools:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m ruff format --check .
```

```python
import json
from soc_url_analyzer import analyze_url

print(json.dumps(analyze_url("https://example.com/path"), indent=2))
```

```json
{
  "url": "https://example.com/path",
  "valid": true,
  "scheme": "https",
  "hostname": "example.com",
  "suspicious": false,
  "findings": [],
  "errors": []
}
```

`analyze_url()` accepts an absolute HTTP or HTTPS URL. It validates the hostname,
port (1–65535), authority, and percent escapes, rejecting raw whitespace, control
characters, and backslashes. Domain names are returned as lowercase IDNA ASCII;
IP addresses are canonicalized. A trailing domain dot is removed. Single-label
hosts are accepted. Encoded hostnames, IPv6 zone IDs, and abbreviated numeric
IPv4 forms are rejected. This is a strict input policy, not full browser URL parsing.

Invalid input returns `valid: false`, explanatory `errors`, null scheme/hostname,
and no findings. Non-string input also returns a null `url`. All results can be
serialized with `json.dumps()`.

Each finding has a stable `code` and an explanatory `message`:

| Code | Pattern |
| --- | --- |
| `unencrypted_http` | HTTP scheme |
| `embedded_credentials` | User information before `@` |
| `ip_literal` | IPv4 or IPv6 hostname |
| `idn_hostname` | IDNA/punycode hostname label |
| `many_labels` | More than four hostname labels, excluding IPs |
| `long_url` | More than 2048 characters |
| `unusual_port` | Explicit port other than 80 for HTTP or 443 for HTTPS |
| `executable_path` | Once-decoded path ending in .exe, .scr, .bat, .cmd, .ps1, .msi, .vbs, or .js |

`suspicious` means at least one heuristic matched. Findings are advisory and can
flag legitimate URLs; an empty list does not establish safety. This analyzer does
not inspect remote content or establish whether a URL is malicious.
