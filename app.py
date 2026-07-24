import os
import secrets
import sqlite3
import uuid
from datetime import timedelta
from functools import wraps
import click
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort, jsonify, send_from_directory
)
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit, join_room
from PIL import Image, UnidentifiedImageError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["WTF_CSRF_ENABLED"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
csrf = CSRFProtect(app)
socketio = SocketIO(app, async_mode="threading")

DB_PATH = os.path.join(app.root_path, "shopping.db")
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def save_product_image(file):
    if not file or not file.filename:
        return None
    safe_name = secure_filename(file.filename)
    if "." not in safe_name:
        raise ValueError("이미지 파일만 업로드할 수 있습니다.")
    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("PNG, JPG, GIF, WEBP 이미지만 업로드할 수 있습니다.")
    try:
        image = Image.open(file.stream)
        image.verify()
        file.stream.seek(0)
        image = Image.open(file.stream)
        if image.width * image.height > 20_000_000:
            raise ValueError("이미지 해상도가 너무 큽니다.")
        image.thumbnail((4096, 4096))
        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGBA" if "transparency" in image.info else "RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise ValueError("파일 내용이 올바른 이미지가 아닙니다.")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.webp"
    image.save(os.path.join(UPLOAD_FOLDER, filename), "WEBP", quality=88, method=6)
    return filename


def remove_product_image(filename):
    if not filename:
        return
    for folder in (UPLOAD_FOLDER, os.path.join(app.root_path, "static", "uploads")):
        path = os.path.join(folder, filename)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                app.logger.warning("상품 이미지 파일을 정리하지 못했습니다: %s", filename)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        balance INTEGER NOT NULL DEFAULT 100000 CHECK(balance >= 0),
        role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
        is_blocked INTEGER NOT NULL DEFAULT 0 CHECK(is_blocked IN (0,1)),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        image_filename TEXT,
        price INTEGER NOT NULL CHECK(price >= 0),
        seller_id INTEGER NOT NULL,
        is_blocked INTEGER NOT NULL DEFAULT 0 CHECK(is_blocked IN (0,1)),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER,
        product_id INTEGER,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS chat_blocks (
        blocker_id INTEGER NOT NULL,
        blocked_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(blocker_id, blocked_id),
        CHECK(blocker_id != blocked_id),
        FOREIGN KEY(blocker_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(blocked_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS hidden_chats (
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        partner_id INTEGER NOT NULL,
        hidden_through_id INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(user_id, product_id, partner_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
        FOREIGN KEY(partner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
        action TEXT NOT NULL,
        client_key TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup
        ON rate_limits(action, client_key, created_at);

    CREATE TABLE IF NOT EXISTS security_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        details TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        amount INTEGER NOT NULL CHECK(amount > 0),
        request_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        target_type TEXT NOT NULL CHECK(target_type IN ('user','product')),
        target_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(reporter_id, target_type, target_id),
        FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE
    );

    """)

    # 기존 데이터베이스도 삭제 없이 새 기능에 맞게 확장합니다.
    product_columns = {row[1] for row in db.execute("PRAGMA table_info(products)")}
    if "image_filename" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN image_filename TEXT")
    message_columns = {row[1] for row in db.execute("PRAGMA table_info(messages)")}
    if "product_id" not in message_columns:
        db.execute("ALTER TABLE messages ADD COLUMN product_id INTEGER REFERENCES products(id) ON DELETE CASCADE")
    transfer_columns = {row[1] for row in db.execute("PRAGMA table_info(transfers)")}
    if "request_token" not in transfer_columns:
        db.execute("ALTER TABLE transfers ADD COLUMN request_token TEXT")
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_request_token
        ON transfers(request_token) WHERE request_token IS NOT NULL
    """)
    report_columns = {row[1] for row in db.execute("PRAGMA table_info(reports)")}
    if "status" not in report_columns:
        db.execute("ALTER TABLE reports ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if "resolved_by" not in report_columns:
        db.execute("ALTER TABLE reports ADD COLUMN resolved_by INTEGER REFERENCES users(id)")
    if "resolved_at" not in report_columns:
        db.execute("ALTER TABLE reports ADD COLUMN resolved_at TIMESTAMP")

    # 기존 배포본의 관리자 자격 증명을 최초 1회 전부 무효화합니다.
    migration = db.execute(
        "SELECT 1 FROM security_migrations WHERE name='invalidate_legacy_admins'"
    ).fetchone()
    if not migration:
        db.execute(
            "UPDATE users SET password_hash=? WHERE role='admin'",
            (generate_password_hash(secrets.token_urlsafe(48)),)
        )
        db.execute(
            "INSERT INTO security_migrations(name) VALUES ('invalidate_legacy_admins')"
        )
    db.commit()
    db.close()


def rate_limit(action, client_key, limit, window_seconds):
    db = get_db()
    now = int(__import__("time").time())
    cutoff = now - window_seconds
    db.execute("DELETE FROM rate_limits WHERE created_at < ?", (cutoff,))
    count = db.execute(
        "SELECT COUNT(*) FROM rate_limits WHERE action=? AND client_key=? AND created_at>=?",
        (action, client_key, cutoff)
    ).fetchone()[0]
    if count >= limit:
        db.commit()
        return False
    db.execute(
        "INSERT INTO rate_limits(action, client_key, created_at) VALUES (?, ?, ?)",
        (action, client_key, now)
    )
    db.commit()
    return True


def write_audit(db, action, target_type=None, target_id=None, details="", actor_id=None):
    if actor_id is None and getattr(g, "user", None):
        actor_id = g.user["id"]
    db.execute(
        "INSERT INTO audit_logs(actor_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)",
        (actor_id, action, target_type, target_id, details[:300])
    )


@app.before_request
def prepare_security_context():
    g.csp_nonce = secrets.token_urlsafe(18)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.get('csp_nonce', '')}'; "
        "style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if session.get("user_id"):
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.cli.command("create-admin")
@click.argument("username")
@click.password_option(confirmation_prompt=True)
def create_admin(username, password):
    """환경에 비밀번호를 남기지 않고 관리자 계정을 생성하거나 갱신합니다."""
    username = username.strip()
    if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
        raise click.ClickException("아이디는 영문·숫자·밑줄로 3~20자여야 합니다.")
    if len(password) < 12:
        raise click.ClickException("관리자 비밀번호는 12자 이상이어야 합니다.")
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        db.execute(
            "UPDATE users SET password_hash=?, role='admin', is_blocked=0 WHERE id=?",
            (generate_password_hash(password), existing["id"])
        )
    else:
        db.execute(
            "INSERT INTO users(username,password_hash,role) VALUES (?,?,'admin')",
            (username, generate_password_hash(password))
        )
    write_audit(db, "admin_created_or_reset", "user", existing["id"] if existing else None, username)
    db.commit()
    click.echo(f"관리자 계정 '{username}'이(가) 설정되었습니다.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("login"))
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or user["is_blocked"]:
            session.clear()
            flash("차단되었거나 존재하지 않는 계정입니다.", "danger")
            return redirect(url_for("login"))
        g.user = user
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return {"current_user": user}


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    db = get_db()
    if q:
        products = db.execute("""
            SELECT p.*, u.username
            FROM products p JOIN users u ON p.seller_id = u.id
            WHERE p.is_blocked = 0 AND (p.title LIKE ? OR p.description LIKE ?)
            ORDER BY p.id DESC
        """, (f"%{q}%", f"%{q}%")).fetchall()
    else:
        products = db.execute("""
            SELECT p.*, u.username
            FROM products p JOIN users u ON p.seller_id = u.id
            WHERE p.is_blocked = 0
            ORDER BY p.id DESC
        """).fetchall()
    return render_template("index.html", products=products, q=q)


@app.route("/product-image/<path:filename>")
def product_image(filename):
    image = get_db().execute(
        "SELECT 1 FROM products WHERE image_filename=? AND is_blocked=0", (filename,)
    ).fetchone()
    if not image:
        abort(404)
    if os.path.isfile(os.path.join(UPLOAD_FOLDER, filename)):
        return send_from_directory(UPLOAD_FOLDER, filename, max_age=3600)
    legacy_folder = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(legacy_folder, filename, max_age=3600)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not rate_limit("register", request.remote_addr or "unknown", 5, 3600):
            flash("회원가입 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "danger")
            return redirect(url_for("register"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
            flash("아이디는 영문·숫자·밑줄로 3~20자여야 합니다.", "danger")
            return redirect(url_for("register"))
        if len(password) < 12:
            flash("비밀번호는 12자 이상이어야 합니다.", "danger")
            return redirect(url_for("register"))
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("이미 존재하는 아이디입니다.", "danger")
            return redirect(url_for("register"))
        flash("회원가입이 완료되었습니다.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        limiter_key = f"{request.remote_addr or 'unknown'}:{username.casefold()}"
        if not rate_limit("login", limiter_key, 5, 300):
            flash("로그인 시도가 너무 많습니다. 5분 후 다시 시도하세요.", "danger")
            return redirect(url_for("login"))
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
            return redirect(url_for("login"))
        if user["is_blocked"]:
            flash("차단된 계정입니다.", "danger")
            return redirect(url_for("login"))
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        flash("로그인되었습니다.", "success")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("index"))


@app.route("/product/new", methods=["GET", "POST"])
@login_required
def product_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        if not (1 <= len(title) <= 80) or not (1 <= len(description) <= 1000):
            flash("상품명과 설명 길이를 확인하세요.", "danger")
            return redirect(url_for("product_new"))
        try:
            price = int(price_raw)
            if price < 0 or price > 100000000:
                raise ValueError
        except ValueError:
            flash("가격은 0~100,000,000 사이 정수여야 합니다.", "danger")
            return redirect(url_for("product_new"))
        try:
            image_filename = save_product_image(request.files.get("image"))
        except ValueError as error:
            flash(str(error), "danger")
            return redirect(url_for("product_new"))
        db = get_db()
        db.execute(
            "INSERT INTO products(title, description, price, seller_id, image_filename) VALUES (?, ?, ?, ?, ?)",
            (title, description, price, g.user["id"], image_filename)
        )
        db.commit()
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for("index"))
    return render_template("product_new.html")


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = get_db().execute("""
        SELECT p.*, u.username, u.bio
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.id = ? AND p.is_blocked = 0
    """, (product_id,)).fetchone()
    if not product:
        abort(404)
    return render_template("product_detail.html", product=product)


@app.route("/product/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
def product_edit(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)
    if product["seller_id"] != g.user["id"] and g.user["role"] != "admin":
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        try:
            price = int(request.form.get("price", ""))
            if not (1 <= len(title) <= 80 and 1 <= len(description) <= 1000 and 0 <= price <= 100000000):
                raise ValueError
        except ValueError:
            flash("입력값을 확인하세요.", "danger")
            return redirect(url_for("product_edit", product_id=product_id))
        try:
            image_filename = save_product_image(request.files.get("image"))
        except ValueError as error:
            flash(str(error), "danger")
            return redirect(url_for("product_edit", product_id=product_id))
        if image_filename:
            old_image = product["image_filename"]
            db.execute("UPDATE products SET title=?, description=?, price=?, image_filename=? WHERE id=?",
                       (title, description, price, image_filename, product_id))
        else:
            db.execute("UPDATE products SET title=?, description=?, price=? WHERE id=?",
                       (title, description, price, product_id))
        db.commit()
        if image_filename:
            remove_product_image(old_image)
        flash("상품이 수정되었습니다.", "success")
        return redirect(url_for("product_detail", product_id=product_id))
    return render_template("product_edit.html", product=product)


@app.post("/product/<int:product_id>/delete")
@login_required
def product_delete(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)
    if product["seller_id"] != g.user["id"] and g.user["role"] != "admin":
        abort(403)
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    write_audit(db, "product_deleted", "product", product_id, product["title"])
    db.commit()
    remove_product_image(product["image_filename"])
    flash("상품이 삭제되었습니다.", "info")
    return redirect(url_for("index"))


@app.route("/chat")
@login_required
def chat():
    db = get_db()
    rooms = db.execute("""
        WITH room_messages AS (
            SELECT m.*, p.seller_id,
                   CASE WHEN m.sender_id=p.seller_id THEN m.receiver_id ELSE m.sender_id END AS partner_id
            FROM messages m
            JOIN products p ON p.id=m.product_id
            WHERE m.product_id IS NOT NULL
              AND m.receiver_id IS NOT NULL
              AND (m.sender_id=? OR m.receiver_id=?)
        )
        SELECT rm.id, rm.product_id, rm.partner_id, rm.content, rm.created_at,
               p.title, p.image_filename, u.username AS partner_name
        FROM room_messages rm
        JOIN products p ON p.id=rm.product_id
        JOIN users u ON u.id=rm.partner_id
        WHERE rm.id=(
            SELECT MAX(newest.id) FROM room_messages newest
            WHERE newest.product_id=rm.product_id AND newest.partner_id=rm.partner_id
        )
          AND rm.id > COALESCE((
            SELECT h.hidden_through_id FROM hidden_chats h
            WHERE h.user_id=? AND h.product_id=rm.product_id AND h.partner_id=rm.partner_id
          ), 0)
        ORDER BY rm.id DESC
    """, (g.user["id"], g.user["id"], g.user["id"])).fetchall()
    return render_template("chat.html", rooms=rooms)


def get_chat_room(db, product_id, partner_id, user_id):
    product = db.execute("""
        SELECT p.*, u.username AS seller_name
        FROM products p JOIN users u ON u.id=p.seller_id
        WHERE p.id=? AND p.is_blocked=0
    """, (product_id,)).fetchone()
    partner = db.execute(
        "SELECT id, username FROM users WHERE id=? AND is_blocked=0", (partner_id,)
    ).fetchone()
    if not product or not partner or partner_id == product["seller_id"]:
        abort(404)
    if user_id not in (product["seller_id"], partner_id):
        abort(403)
    return product, partner


def socket_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_db().execute(
        "SELECT * FROM users WHERE id=? AND is_blocked=0", (user_id,)
    ).fetchone()
    if user:
        g.user = user
    return user


def socket_room_name(product_id, partner_id):
    return f"product:{product_id}:partner:{partner_id}"


@socketio.on("connect")
def socket_connect(auth=None):
    if not socket_user():
        return False


@socketio.on("join_chat")
def socket_join_chat(data):
    user = socket_user()
    if not user or not isinstance(data, dict):
        return {"ok": False, "error": "인증이 필요합니다."}
    try:
        product_id = int(data.get("product_id"))
        partner_id = int(data.get("partner_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "잘못된 채팅방입니다."}
    try:
        get_chat_room(get_db(), product_id, partner_id, user["id"])
    except Exception:
        return {"ok": False, "error": "채팅방에 접근할 수 없습니다."}
    join_room(socket_room_name(product_id, partner_id))
    return {"ok": True}


@socketio.on("send_message")
def socket_send_message(data):
    user = socket_user()
    if not user or not isinstance(data, dict):
        return {"ok": False, "error": "인증이 필요합니다."}
    try:
        product_id = int(data.get("product_id"))
        partner_id = int(data.get("partner_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "잘못된 채팅방입니다."}
    content = data.get("content")
    if not isinstance(content, str):
        return {"ok": False, "error": "메시지 형식이 올바르지 않습니다."}
    content = content.strip()
    if not 1 <= len(content) <= 300:
        return {"ok": False, "error": "메시지는 1~300자여야 합니다."}
    if not rate_limit("socket_chat", str(user["id"]), 30, 60):
        return {"ok": False, "error": "메시지를 너무 빠르게 보내고 있습니다."}
    db = get_db()
    try:
        product, _partner = get_chat_room(db, product_id, partner_id, user["id"])
    except Exception:
        return {"ok": False, "error": "채팅방에 접근할 수 없습니다."}
    other_id = partner_id if user["id"] == product["seller_id"] else product["seller_id"]
    blocked = db.execute("""
        SELECT 1 FROM chat_blocks
        WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)
    """, (user["id"], other_id, other_id, user["id"])).fetchone()
    if blocked:
        return {"ok": False, "error": "차단된 상대와는 메시지를 주고받을 수 없습니다."}
    cursor = db.execute(
        "INSERT INTO messages(sender_id,receiver_id,product_id,content) VALUES (?,?,?,?)",
        (user["id"], other_id, product_id, content)
    )
    db.commit()
    message = db.execute("""
        SELECT m.id,m.sender_id,m.content,m.created_at,u.username AS sender_name
        FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?
    """, (cursor.lastrowid,)).fetchone()
    payload = dict(message)
    emit("new_message", payload, to=socket_room_name(product_id, partner_id))
    return {"ok": True}


@app.route("/chat/<int:product_id>/<int:partner_id>")
@login_required
def chat_room(product_id, partner_id):
    db = get_db()
    product, partner = get_chat_room(db, product_id, partner_id, g.user["id"])
    other_name = partner["username"] if g.user["id"] == product["seller_id"] else product["seller_name"]
    other_id = partner_id if g.user["id"] == product["seller_id"] else product["seller_id"]
    blocked_by_me = db.execute(
        "SELECT 1 FROM chat_blocks WHERE blocker_id=? AND blocked_id=?",
        (g.user["id"], other_id)
    ).fetchone() is not None
    blocked_by_other = db.execute(
        "SELECT 1 FROM chat_blocks WHERE blocker_id=? AND blocked_id=?",
        (other_id, g.user["id"])
    ).fetchone() is not None
    return render_template(
        "chat_room.html", product=product, partner=partner, other_name=other_name,
        other_id=other_id, blocked_by_me=blocked_by_me, blocked_by_other=blocked_by_other
    )


@app.route("/chat/<int:product_id>/<int:partner_id>/messages", methods=["GET", "POST"])
@login_required
def product_messages(product_id, partner_id):
    db = get_db()
    product, _partner = get_chat_room(db, product_id, partner_id, g.user["id"])

    if request.method == "POST":
        if not rate_limit("chat", str(g.user["id"]), 30, 60):
            return jsonify({"error": "메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요."}), 429
        other_id = partner_id if g.user["id"] == product["seller_id"] else product["seller_id"]
        blocked = db.execute("""
            SELECT 1 FROM chat_blocks
            WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)
        """, (g.user["id"], other_id, other_id, g.user["id"])).fetchone()
        if blocked:
            return jsonify({"error": "차단된 상대와는 메시지를 주고받을 수 없습니다."}), 403
        content = request.form.get("content", "").strip()
        if not (1 <= len(content) <= 300):
            return jsonify({"error": "메시지는 1~300자여야 합니다."}), 400
        receiver_id = partner_id if g.user["id"] == product["seller_id"] else product["seller_id"]
        db.execute(
            "INSERT INTO messages(sender_id, receiver_id, product_id, content) VALUES (?, ?, ?, ?)",
            (g.user["id"], receiver_id, product_id, content)
        )
        db.commit()
        return jsonify({"ok": True}), 201

    after = request.args.get("after", "0")
    after_id = int(after) if after.isdigit() else 0
    hidden_through = db.execute("""
        SELECT hidden_through_id FROM hidden_chats
        WHERE user_id=? AND product_id=? AND partner_id=?
    """, (g.user["id"], product_id, partner_id)).fetchone()
    visible_after = max(after_id, hidden_through["hidden_through_id"] if hidden_through else 0)
    rows = db.execute("""
        SELECT m.id, m.sender_id, m.content, m.created_at, u.username AS sender_name
        FROM messages m JOIN users u ON m.sender_id=u.id
        WHERE m.product_id=? AND m.id>?
          AND ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
        ORDER BY m.id ASC LIMIT 100
    """, (
        product_id, visible_after,
        product["seller_id"], partner_id, partner_id, product["seller_id"]
    )).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/chat/<int:product_id>/<int:partner_id>/delete")
@login_required
def chat_room_delete(product_id, partner_id):
    db = get_db()
    product, _partner = get_chat_room(db, product_id, partner_id, g.user["id"])
    last_message = db.execute("""
        SELECT COALESCE(MAX(id), 0) AS id FROM messages
        WHERE product_id=?
          AND ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
    """, (product_id, product["seller_id"], partner_id, partner_id, product["seller_id"])).fetchone()
    db.execute("""
        INSERT INTO hidden_chats(user_id,product_id,partner_id,hidden_through_id)
        VALUES (?,?,?,?)
        ON CONFLICT(user_id,product_id,partner_id)
        DO UPDATE SET hidden_through_id=excluded.hidden_through_id
    """, (g.user["id"], product_id, partner_id, last_message["id"]))
    write_audit(db, "chat_hidden", "product", product_id, f"partner_id={partner_id}")
    db.commit()
    flash("채팅을 내 목록에서 삭제했습니다. 상대방의 내역은 유지됩니다.", "success")
    return redirect(url_for("chat"))


@app.post("/chat/<int:product_id>/<int:partner_id>/block")
@login_required
def chat_user_block(product_id, partner_id):
    db = get_db()
    product, _partner = get_chat_room(db, product_id, partner_id, g.user["id"])
    other_id = partner_id if g.user["id"] == product["seller_id"] else product["seller_id"]
    db.execute(
        "INSERT OR IGNORE INTO chat_blocks(blocker_id, blocked_id) VALUES (?, ?)",
        (g.user["id"], other_id)
    )
    write_audit(db, "chat_user_blocked", "user", other_id)
    db.commit()
    flash("상대방을 차단했습니다. 기존 대화는 유지되지만 새 메시지는 주고받을 수 없습니다.", "success")
    return redirect(url_for("chat_room", product_id=product_id, partner_id=partner_id))


@app.post("/chat/<int:product_id>/<int:partner_id>/unblock")
@login_required
def chat_user_unblock(product_id, partner_id):
    db = get_db()
    product, _partner = get_chat_room(db, product_id, partner_id, g.user["id"])
    other_id = partner_id if g.user["id"] == product["seller_id"] else product["seller_id"]
    db.execute(
        "DELETE FROM chat_blocks WHERE blocker_id=? AND blocked_id=?",
        (g.user["id"], other_id)
    )
    write_audit(db, "chat_user_unblocked", "user", other_id)
    db.commit()
    flash("차단을 해제했습니다.", "success")
    return redirect(url_for("chat_room", product_id=product_id, partner_id=partner_id))


@app.route("/mypage", methods=["GET", "POST"])
@login_required
def mypage():
    db = get_db()
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        new_password = request.form.get("new_password", "")
        if len(bio) > 300:
            flash("소개글은 300자 이하여야 합니다.", "danger")
            return redirect(url_for("mypage"))
        db.execute("UPDATE users SET bio=? WHERE id=?", (bio, g.user["id"]))
        if new_password:
            current_password = request.form.get("current_password", "")
            if not check_password_hash(g.user["password_hash"], current_password):
                flash("현재 비밀번호가 올바르지 않습니다.", "danger")
                return redirect(url_for("mypage"))
            if len(new_password) < 12:
                flash("새 비밀번호는 12자 이상이어야 합니다.", "danger")
                return redirect(url_for("mypage"))
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new_password), g.user["id"]))
            write_audit(db, "password_changed", "user", g.user["id"])
        db.commit()
        flash("프로필이 수정되었습니다.", "success")
        return redirect(url_for("mypage"))
    products = db.execute("SELECT * FROM products WHERE seller_id=? ORDER BY id DESC",
                          (g.user["id"],)).fetchall()
    return render_template("mypage.html", products=products)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    db = get_db()
    if request.method == "POST":
        if not rate_limit("transfer", str(g.user["id"]), 5, 300):
            flash("포인트 전송 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "danger")
            return redirect(url_for("transfer"))
        request_token = request.form.get("request_token", "")
        expected_token = session.pop("transfer_token", None)
        if not expected_token or not secrets.compare_digest(request_token, expected_token):
            flash("만료되었거나 중복된 요청입니다. 다시 시도하세요.", "danger")
            return redirect(url_for("transfer"))
        if not check_password_hash(g.user["password_hash"], request.form.get("password", "")):
            flash("현재 비밀번호가 올바르지 않습니다.", "danger")
            return redirect(url_for("transfer"))
        receiver_name = request.form.get("receiver", "").strip()
        try:
            amount = int(request.form.get("amount", ""))
            if not 1 <= amount <= 100000:
                raise ValueError
        except ValueError:
            flash("전송액은 1~100,000 포인트 사이 정수여야 합니다.", "danger")
            return redirect(url_for("transfer"))
        receiver = db.execute(
            "SELECT id FROM users WHERE username=? AND is_blocked=0", (receiver_name,)
        ).fetchone()
        if not receiver or receiver["id"] == g.user["id"]:
            flash("받는 사용자를 확인하세요.", "danger")
            return redirect(url_for("transfer"))
        sent_today = db.execute("""
            SELECT COALESCE(SUM(amount),0) FROM transfers
            WHERE sender_id=? AND created_at>=datetime('now','-1 day')
        """, (g.user["id"],)).fetchone()[0]
        if sent_today + amount > 100000:
            flash("24시간 전송 한도는 100,000 포인트입니다.", "danger")
            return redirect(url_for("transfer"))
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE users SET balance=balance-? WHERE id=? AND balance>=?",
                (amount, g.user["id"], amount)
            )
            if cursor.rowcount != 1:
                raise ValueError("잔액 부족")
            db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, receiver["id"]))
            db.execute(
                "INSERT INTO transfers(sender_id,receiver_id,amount,request_token) VALUES(?,?,?,?)",
                (g.user["id"], receiver["id"], amount, request_token)
            )
            write_audit(db, "points_transferred", "user", receiver["id"], f"amount={amount}")
            db.commit()
        except (sqlite3.Error, ValueError):
            db.rollback()
            flash("잔액이 부족하거나 이미 처리된 요청입니다.", "danger")
            return redirect(url_for("transfer"))
        flash(f"{receiver_name}님에게 {amount:,} 포인트를 전송했습니다.", "success")
        return redirect(url_for("mypage"))

    session["transfer_token"] = secrets.token_urlsafe(32)
    return render_template("transfer.html", request_token=session["transfer_token"])


@app.route("/report/<target_type>/<int:target_id>", methods=["GET", "POST"])
@login_required
def report(target_type, target_id):
    if target_type not in ("user", "product"):
        abort(404)
    if request.method == "POST":
        if not rate_limit("report", str(g.user["id"]), 10, 3600):
            flash("신고 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "danger")
            return redirect(url_for("index"))
        reason = request.form.get("reason", "").strip()
        if not (5 <= len(reason) <= 300):
            flash("신고 사유는 5~300자로 작성하세요.", "danger")
            return redirect(request.url)
        db = get_db()
        table = "users" if target_type == "user" else "products"
        if not db.execute(f"SELECT id FROM {table} WHERE id=?", (target_id,)).fetchone():
            abort(404)
        try:
            db.execute(
                "INSERT INTO reports(reporter_id,target_type,target_id,reason) VALUES(?,?,?,?)",
                (g.user["id"], target_type, target_id, reason)
            )
            report_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            write_audit(db, "report_submitted", "report", report_id, f"{target_type}:{target_id}")
            db.commit()
        except sqlite3.IntegrityError:
            flash("이미 신고한 대상입니다.", "warning")
            return redirect(url_for("index"))

        flash("신고가 접수되었습니다.", "success")
        return redirect(url_for("index"))
    return render_template("report.html", target_type=target_type, target_id=target_id)


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    products = db.execute("""
        SELECT p.*, u.username FROM products p JOIN users u ON p.seller_id=u.id
        ORDER BY p.id DESC
    """).fetchall()
    reports = db.execute("""
        SELECT r.*, u.username AS reporter_name
        FROM reports r JOIN users u ON r.reporter_id=u.id
        ORDER BY r.id DESC
    """).fetchall()
    audit_logs = db.execute("""
        SELECT a.*, u.username AS actor_name
        FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
        ORDER BY a.id DESC LIMIT 100
    """).fetchall()
    return render_template(
        "admin.html", users=users, products=products,
        reports=reports, audit_logs=audit_logs
    )


@app.post("/admin/user/<int:user_id>/toggle")
@admin_required
def admin_toggle_user(user_id):
    if user_id == g.user["id"]:
        flash("관리자 본인 계정은 차단할 수 없습니다.", "warning")
        return redirect(url_for("admin"))
    db = get_db()
    target = db.execute("SELECT is_blocked FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        abort(404)
    db.execute("UPDATE users SET is_blocked = CASE is_blocked WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (user_id,))
    write_audit(
        db, "user_unblocked" if target["is_blocked"] else "user_blocked", "user", user_id
    )
    db.commit()
    return redirect(url_for("admin"))


@app.post("/admin/product/<int:product_id>/toggle")
@admin_required
def admin_toggle_product(product_id):
    db = get_db()
    product = db.execute("SELECT is_blocked,title FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        abort(404)
    db.execute(
        "UPDATE products SET is_blocked=CASE is_blocked WHEN 1 THEN 0 ELSE 1 END WHERE id=?",
        (product_id,)
    )
    write_audit(
        db, "product_unblocked" if product["is_blocked"] else "product_blocked",
        "product", product_id, product["title"]
    )
    db.commit()
    return redirect(url_for("admin"))


@app.post("/admin/report/<int:report_id>/resolve")
@admin_required
def admin_resolve_report(report_id):
    db = get_db()
    report_row = db.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone()
    if not report_row:
        abort(404)
    db.execute("""
        UPDATE reports SET status='resolved',resolved_by=?,resolved_at=CURRENT_TIMESTAMP
        WHERE id=?
    """, (g.user["id"], report_id))
    write_audit(db, "report_resolved", "report", report_id)
    db.commit()
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="페이지를 찾을 수 없습니다."), 404


@app.errorhandler(500)
def internal_error(_e):
    db = g.pop("db", None)
    if db is not None:
        db.rollback()
        db.close()
    return render_template(
        "error.html", code=500, message="요청을 처리하지 못했습니다. 잠시 후 다시 시도하세요."
    ), 500


# `flask run`이나 WSGI 서버로 실행해도 기존 DB 스키마를 먼저 갱신합니다.
init_db()


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
