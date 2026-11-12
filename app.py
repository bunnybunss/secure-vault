import os
import sqlite3
import secrets
import uuid
import datetime
import hashlib
from io import BytesIO


from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, send_file
)
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# ─── App Setup ────────────────────────────────────────────────────────────────

load_dotenv()  # Load SECRET_KEY & JWT_SECRET_KEY from .env

app = Flask(__name__)

app.config.update({
    "SECRET_KEY":         os.getenv("SECRET_KEY") or secrets.token_hex(32),
    "JWT_SECRET_KEY":     os.getenv("JWT_SECRET_KEY") or secrets.token_hex(32),
    "JWT_TOKEN_LOCATION": ["headers"],
    "JWT_HEADER_NAME":    "x-access-token",
    "JWT_HEADER_TYPE":    "",
    "MAX_CONTENT_LENGTH":  16 * 1024 * 1024,
    "SHARE_FOLDER":       os.path.join(os.getcwd(), "uploads", "shares")
})
os.makedirs(app.config["SHARE_FOLDER"], exist_ok=True)

jwt = JWTManager(app)


# ─── Database Helpers ────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_email(email: str):
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    return dict(row) if row else None

FILE_MAGIC = b"SVLT\x01"
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)


def seal(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    header = FILE_MAGIC + salt + nonce
    key = derive_key(password, salt, KDF_ITERATIONS)
    return header + AESGCM(key).encrypt(nonce, data, header)


def unseal(data: bytes, password: str) -> bytes:
    if data.startswith(FILE_MAGIC):
        salt_end = len(FILE_MAGIC) + SALT_SIZE
        header_end = salt_end + NONCE_SIZE
        header = data[:header_end]
        key = derive_key(password, data[len(FILE_MAGIC):salt_end], KDF_ITERATIONS)
        return AESGCM(key).decrypt(data[salt_end:header_end], data[header_end:], header)

    # Files created by the original prototype used a fixed salt.
    key = derive_key(password, b"fixed-salt", 100_000)
    return AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)


def download(data: bytes, filename: str):
    response = send_file(BytesIO(data), mimetype="application/octet-stream",
                         as_attachment=True, download_name=filename)
    response.headers["Cache-Control"] = "no-store"
    return response


# ─── Public Page Routes (no JWT required) ──────────────────────────────────

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")

    user = get_user_by_email(email)
    if not user or not check_password_hash(user["password_hash"], pw):
        return jsonify(success=False, message="Invalid credentials"), 401

    token = create_access_token(identity=email)
    return jsonify(success=True, token=token)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    data     = request.get_json()
    email    = data.get("email", "").strip().lower()   # Fixed .strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify(success=False, message="Email and password required"), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, generate_password_hash(password))
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(success=False, message="Email already registered"), 400

    return jsonify(success=True)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    return render_template("encrypt.html")

@app.route("/decrypt", methods=["GET"])
def decrypt_page():
    return render_template("decrypt.html")

@app.route("/share", methods=["GET"])
def share_page():
    return render_template("share.html")

# ✅ Add your logout route here
@app.route("/logout")
def logout():
    return render_template("logout.html")


# ─── Protected API Endpoints ────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
@jwt_required()
def encrypt_file():
    f  = request.files.get("file")
    pw = request.form.get("password", "")
    if not f or not pw:
        return jsonify(success=False, message="File + password required"), 400

    filename = secure_filename(f.filename) or "download"
    return download(seal(f.read(), pw), filename + ".enc")


@app.route("/decrypt", methods=["POST"])
@jwt_required()
def decrypt_file():
    f = request.files.get("file")
    pw = request.form.get("password", "")
    if not f or not pw:
        return jsonify(success=False, message="File + password required"), 400

    try:
        plaintext = unseal(f.read(), pw)
    except (InvalidTag, ValueError):
        return jsonify(success=False, message="Decryption failed"), 400

    filename = secure_filename(f.filename).removesuffix(".enc") or "download"
    return download(plaintext, filename)


@app.route("/share", methods=["POST"])
@jwt_required()
def create_share():
    f      = request.files.get("file")
    pw     = request.form.get("password", "")
    expiry = request.form.get("expiry", type=int)

    if not f or not pw or expiry is None or not 1 <= expiry <= 10080:
        return jsonify(success=False, message="File, password and expiry between 1 and 10080 minutes required"), 400

    # Save the file
    filename = secure_filename(f.filename) or "download"
    token = uuid.uuid4().hex
    share_dir = os.path.join(app.config["SHARE_FOLDER"], token)
    os.makedirs(share_dir)
    with open(os.path.join(share_dir, filename), "wb") as output:
        output.write(seal(f.read(), pw))

    # Hash password and set expiry
    pwd_hash   = generate_password_hash(pw)
    expires_at = (datetime.datetime.now(datetime.UTC)
                  + datetime.timedelta(minutes=expiry)
                 ).isoformat()

    # Insert share record
    db = get_db()
    db.execute(
        "INSERT INTO shares (token, filename, pwd_hash, expires_at) VALUES (?,?,?,?)",
        (token, filename, pwd_hash, expires_at)
    )
    db.commit()

    link = url_for("access_share", token=token, _external=True)
    return jsonify(success=True, link=link)

@app.route("/share/<token>", methods=["GET", "POST"])
def access_share(token):
    row = get_db().execute(
        "SELECT filename, pwd_hash, expires_at FROM shares WHERE token = ?",
        (token,)
    ).fetchone()
    if not row:
        return render_template("access_share.html", error="Invalid link")

    if request.method == "POST":
        pw = request.form.get("password", "")
        if not pw:
            return render_template("access_share.html", error="Password required")

        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        if now_iso > row["expires_at"]:
            return render_template("access_share.html", error="Link expired")

        if not check_password_hash(row["pwd_hash"], pw):
            return render_template("access_share.html", error="Incorrect password")

        path = os.path.join(app.config["SHARE_FOLDER"], token, row["filename"])
        try:
            with open(path, "rb") as encrypted:
                plaintext = unseal(encrypted.read(), pw)
        except (FileNotFoundError, InvalidTag, ValueError):
            return render_template("access_share.html", error="File unavailable"), 404
        return download(plaintext, row["filename"])

    return render_template("access_share.html", filename=row["filename"])


@app.errorhandler(HTTPException)
def handle_http_error(error):
    return jsonify(success=False, message=error.description), error.code


# ─── Run Server ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run()
