"""DELIBERATELY INSECURE teaching site. Binds to 127.0.0.1 only. All secrets are fake.
Never deploy this or expose it to a network."""
from flask import Flask, request, make_response

app = Flask(__name__)


@app.after_request
def weak_headers(resp):
    # Version disclosure (low) + permissive CORS that reflects any Origin (medium)
    resp.headers["Server"] = "Apache/2.2.8 (Teaching Lab)"
    resp.headers["X-Powered-By"] = "PHP/5.2.17"
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp  # note: no security headers are ever added


@app.get("/")
def index():
    resp = make_response("<h1>Vulnerable Teaching Lab</h1>"
                         "<p>Intentionally insecure. Scan me with Nuclei.</p>")
    # Cookie missing Secure, HttpOnly and SameSite
    resp.headers["Set-Cookie"] = "session_id=FAKE-SESSION-12345; Path=/"
    return resp


@app.get("/.env")  # HIGH: exposed secrets file (all values fake)
def env_file():
    return ("APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=root\n"
            "DB_PASSWORD=FAKE-hunter2-not-real\nAWS_SECRET_KEY=FAKE-AKIAEXAMPLE0000\n",
            200, {"Content-Type": "text/plain"})


@app.get("/.git/config")  # MEDIUM: exposed repository metadata
def git_config():
    return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
            "[remote \"origin\"]\n\turl = https://example.invalid/lab/app.git\n",
            200, {"Content-Type": "text/plain"})


@app.get("/backup/")  # MEDIUM: directory listing
def backup_listing():
    return ("<html><head><title>Index of /backup</title></head><body>"
            "<h1>Index of /backup</h1><ul><li>db_dump.sql</li>"
            "<li>site_2024.zip</li></ul></body></html>")


@app.get("/admin/")  # HIGH: admin panel with no authentication
def admin():
    return "<h1>Admin Panel - Users</h1><p>No login required.</p>"


@app.get("/search")  # MEDIUM: reflected XSS (input echoed unescaped)
def search():
    q = request.args.get("q", "")
    return "<h1>Results for " + q + "</h1>"


@app.get("/api/profile")  # used by the CORS check
def profile():
    return {"user": "demo", "email": "demo@example.invalid"}


@app.route("/login", methods=["GET", "POST"])  # CRITICAL: default credentials
def login():
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "admin":
            return "<p>Welcome, admin</p>"
        return "<p>Invalid login</p>", 401
    return ("<form method=post><input name=username><input name=password "
            "type=password><button>Login</button></form>")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
