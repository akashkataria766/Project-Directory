# Web Security Analyzer

> **Disclaimer:** This tool is for education and quick triage. A `safe` result does not prove that a website is trustworthy, and an `unsafe` result does not prove criminal activity. Do not enter passwords, payment details, or private information into a site based only on this report. Verify important links through a trusted source.

This local web app reviews a domain, URL, or IPv4 address. It performs explainable local checks and, when configured, asks Google Safe Browsing whether the address is a known malware or social-engineering threat.

## What it checks

The report shows every check and its reason:

- Address format and invalid ports
- HTTP versus encrypted HTTPS
- Direct IPv4 addresses
- Suspicious words such as `login`, `verify`, or `bank`
- Too many subdomains
- Embedded usernames or passwords
- Unusual ports
- Punycode domains that can hide lookalike characters
- Encoded control characters and backslashes
- Very long or difficult-to-read addresses
- Brand lookalikes such as `go0gle.com` compared with `google.com`
- Google Safe Browsing, if its API is available

The score is a **risk signal**, not a mathematical probability. A warning also appears when an external check could not run, so an API failure is never reported as safe.

## Basic steps to run

### 1. Install Python

Install Python 3.11 or newer from:

<https://www.python.org/downloads/>

During installation, enable **Add Python to PATH** if the installer offers that option.

### 2. Open the project

Extract the project, open the extracted folder in VS Code, and open **Terminal > New Terminal**.

The terminal must be in the folder containing `app.py`, `requirements.txt`, and `start.bat`.

### 3. Install dependencies

Run:

```powershell
python -m pip install -r requirements.txt
```

If `python` is not recognized on Windows, use your installed Python path, for example:

```powershell
C:/Python313/python.exe -m pip install -r requirements.txt
```

### 4. Start the app

The easiest option is to double-click:

```text
start.bat
```

Or run:

```powershell
python app.py
```

### 5. Open the website

Go to:

<http://127.0.0.1:5000>

Try inputs such as:

```text
google.com
https://example.com
 go0gle.com
192.168.1.1
http://user:password@example.com:8080/login
```

The leading space in the third example is only for readability; enter `go0gle.com` without it.

To stop the app, return to the terminal and press `Ctrl+C`.

## Google Safe Browsing API setup

Google Safe Browsing is an external Google service. The app can still run local checks without it, but the Google check will show as unavailable.

If you want the Google check:

1. Open <https://console.cloud.google.com/>.
2. Create or select a Google Cloud project.
3. Open **APIs & Services > Library**.
4. Find and enable **Safe Browsing API**.
5. Open **APIs & Services > Credentials**.
6. Create an API key.
7. Restrict the key to the Safe Browsing API and set usage or billing alerts where available.
8. Store the key as a Windows user environment variable named exactly:

   ```text
   GOOGLE_SAFE_BROWSING_API_KEY
   ```

9. Completely close and reopen VS Code so new terminals receive the variable.
10. Start `start.bat` again.

The value must be the key only. Do not enter the variable name, equals sign, or quotation marks as part of the value.

To check the setup without revealing the key:

```powershell
if ([string]::IsNullOrWhiteSpace($env:GOOGLE_SAFE_BROWSING_API_KEY)) { "Missing" } else { "Configured" }
```

A Google `401`, `403`, or `400` response normally means the key is invalid, the Safe Browsing API is not enabled, or the key restrictions do not allow this API. A `429` means quota was exceeded.

## Test the project

From the project folder, run:

```powershell
python -m pytest -q
```

The tests are local and deterministic; they do not need a Google API key or a live network connection.

## Keep GitHub uploads safe

Before uploading or publishing this project:

1. Revoke any key that was pasted into chat, code, screenshots, or a public repository.
2. Keep the real key in Windows Environment Variables or a hosting provider's secret settings.
3. Never commit `.env`; the included `.gitignore` excludes it.
4. `.env.example` is only a placeholder and must never contain a real key.
5. Search the project for `AIza`, passwords, tokens, and connection strings before publishing.
6. Do not copy the key into HTML, JavaScript, README files, or batch files.
7. Do not enable Flask debug mode on a public server.
8. If a key was exposed, revoke it immediately. Restricting an exposed key is not a replacement for revoking it.

## GitHub Pages limitation

GitHub Pages serves static files only. It cannot run this Flask app and cannot safely keep a private Google API key in browser JavaScript.

A future public deployment needs this structure:

```text
GitHub Pages frontend -> private hosted backend -> Google Safe Browsing API
```

The backend should store the key as a hosting secret, validate input, apply rate limits, and never return the key to the browser.

## Project files

- `app.py`: Flask web server and page route
- `url_checker.py`: normalization, local checks, scoring, and Google API call
- `templates/index.html`: desktop-first responsive interface
- `test_api.py`: local automated tests
- `requirements.txt`: Python dependencies
- `start.bat`: Windows one-step launcher
- `.gitignore`: prevents local secrets and generated files from being committed
- `.env.example`: safe placeholder showing the variable name

## Responsible use

Only analyze links you are authorized to inspect. Do not use this project to collect credentials, bypass security controls, or make definitive claims about a person or organization. Treat the report as one input in a broader security review.
