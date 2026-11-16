"""Nuclei teaching scanner. Serve locally; scan only allowed origins."""
import json
import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, render_template, request

ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = ROOT / "nuclei-templates"   # was: TEMPLATE = ... / "http-missing-security-headers.yaml"
RESULTS = ROOT / "results"
DEFAULT_ORIGINS = "http://127.0.0.1:8000,http://localhost:8000"
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096


from collections import Counter




def origin(value):
    if not value:
        raise ValueError("Please enter a URL to scan.")
    if len(value) > 2048:
        raise ValueError("URL is too long (limit is 2048 characters).")
    if any(c.isspace() for c in value):
        raise ValueError("URL must not contain spaces.")
    if "\\" in value:
        raise ValueError("URL must not contain backslashes.")
    try:                      # only the parsing that can actually raise
        u = urlsplit(value)
        port = u.port
        host = u.hostname
    except (ValueError, UnicodeError) as exc:
        raise ValueError("URL or port is malformed (ports must be 1-65535).") from exc
    if u.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https:// "
                         "(for example http://127.0.0.1:8000).")
    if not host:
        raise ValueError("URL is missing a hostname.")
    if u.username is not None or u.password is not None:
        raise ValueError("URLs containing a username or password are not allowed.")
    if u.fragment:
        raise ValueError("Remove the #fragment from the URL.")
    if "%" in u.netloc or host.endswith("."):
        raise ValueError("Hostname contains unsupported characters.")
    return u.scheme, host.lower(), port or (443 if u.scheme == "https" else 80)
def validate_target(target):
    candidate = origin(target)
    allowed = set()
    entries = os.environ.get("ALLOWED_ORIGINS", DEFAULT_ORIGINS)
    for item in entries.split(","):
        item = item.strip()
        if not item:
            continue
        u = urlsplit(item)
        if u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("ALLOWED_ORIGINS must contain exact origins, not paths.")
        allowed.add(origin(item))
    if candidate not in allowed:
        names = ", ".join(sorted(f"{s}://{h}:{p}" for s, h, p in allowed))
        raise ValueError(f"Target not authorized. Allowed lab origins: {names}")
    return target


def scan_target(target):
    if not TEMPLATES_DIR.is_dir() or not any(TEMPLATES_DIR.rglob("*.yaml")):
        raise RuntimeError("No Nuclei templates found in nuclei-templates/.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    output = RESULTS / ("scan_" + uuid.uuid4().hex + ".jsonl")
    cmd = [
        os.environ.get("NUCLEI_BIN", "nuclei"), "-u", target,
        "-t", str(TEMPLATES_DIR), "-jsonl", "-o", str(output),
        "-c", "1", "-rl", "1", "-timeout", "10", "-retries", "0",
        "-silent", "-duc", "-ni", "-no-color", "-dr", "-no-stdin",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=90)
    except FileNotFoundError as exc:
        raise RuntimeError("Nuclei not found. Check PATH or NUCLEI_BIN.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nuclei exceeded the 90-second scan limit.") from exc
    except OSError as exc:
        raise RuntimeError("Cannot start Nuclei: " + str(exc)) from exc

    message = (proc.stderr or "").strip()[:3000]
    if proc.returncode:
        raise RuntimeError("Nuclei failed (exit " + str(proc.returncode) + "): " + message)
    findings = []
    if output.is_file():
        try:
            with output.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        finding = json.loads(line)
                        if not isinstance(finding, dict):
                            raise ValueError("JSONL item is not an object")
                        findings.append(finding)
        except (OSError, ValueError) as exc:
            raise RuntimeError("Invalid Nuclei JSONL output: " + str(exc)) from exc
    return findings, message

@app.get("/")
def home():
    return render_template("index.html")


@app.post("/scan")
def scan():
    target = request.form.get("target", "").strip()
    try:
        validate_target(target)
    except ValueError as exc:
        return render_template("index.html", target=target, error=str(exc)), 400
    try:
        findings, stderr = scan_target(target)
    except RuntimeError as exc:
        return render_template("index.html", target=target, error=str(exc)), 502
    return render_template("index.html", target=target, findings=findings,
                           stderr=stderr, completed=True,
                           summary=summarize(findings))
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_DESCRIPTIONS = {
    "critical": "Likely directly exploitable with severe impact. Fix immediately.",
    "high": "Serious weakness that is probably exploitable. Fix soon.",
    "medium": "Real weakness, but exploiting it usually needs extra conditions.",
    "low": "Minor weakness or hardening gap with limited impact.",
    "info": "Informational observation, such as a missing header. It may not be a vulnerability on its own.",
    "unknown": "The scanner did not report a recognized severity.",
}


def summarize(findings):
    counts = Counter()
    for f in findings:
        sev = str(f.get("info", {}).get("severity", "unknown")).lower()
        counts[sev if sev in SEVERITY_DESCRIPTIONS else "unknown"] += 1
    return [
        {"severity": s, "count": counts[s], "description": SEVERITY_DESCRIPTIONS[s]}
        for s in SEVERITY_ORDER if counts[s]
    ]
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="127.0.0.1", port=int(os.environ.get("PORT", "10000")))