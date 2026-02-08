#!/usr/bin/env python3
"""Lumière Seconds — Luxury Pre-Owned Store"""

import json
import os
import uuid
import hashlib
import hmac
import secrets
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from http.cookies import SimpleCookie

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATA_FILE = os.path.join(DATA_DIR, "products.json")
ADMINS_FILE = os.path.join(DATA_DIR, "admins.json")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "images", "products")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ── Auth helpers ──────────────────────────────────────────────

SECRET_KEY = None
SESSIONS = {}  # token -> {"user": username, "expires": timestamp}


def get_secret_key():
    """Persistent secret key for HMAC signing."""
    global SECRET_KEY
    if SECRET_KEY:
        return SECRET_KEY
    key_file = os.path.join(DATA_DIR, ".secret_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            SECRET_KEY = f.read().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        with open(key_file, "w") as f:
            f.write(SECRET_KEY)
    return SECRET_KEY


def hash_password(password, salt=None):
    """Hash password with PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored_hash):
    """Verify password against stored hash."""
    if "$" not in stored_hash:
        return False
    salt, _ = stored_hash.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored_hash)


def load_admins():
    if not os.path.exists(ADMINS_FILE):
        # Create default admin on first run
        default_hash = hash_password("lumiere2026")
        admins = [{"username": "admin", "password_hash": default_hash, "created_at": datetime.now().isoformat()}]
        save_admins(admins)
        return admins
    with open(ADMINS_FILE, "r") as f:
        return json.load(f)


def save_admins(admins):
    with open(ADMINS_FILE, "w") as f:
        json.dump(admins, f, indent=2)


def create_session(username):
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"user": username, "expires": time.time() + 86400}  # 24h
    return token


def validate_session(cookie_header):
    if not cookie_header:
        return None
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" not in cookie:
        return None
    token = cookie["session"].value
    session = SESSIONS.get(token)
    if not session:
        return None
    if time.time() > session["expires"]:
        del SESSIONS[token]
        return None
    return session["user"]


def destroy_session(cookie_header):
    if not cookie_header:
        return
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" in cookie:
        token = cookie["session"].value
        SESSIONS.pop(token, None)


# ── Data helpers ──────────────────────────────────────────────

def load_products():
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_products(products):
    with open(DATA_FILE, "w") as f:
        json.dump(products, f, indent=2)


def render_template(template_name, **ctx):
    path = os.path.join(os.path.dirname(__file__), "templates", template_name)
    with open(path, "r") as f:
        html = f.read()
    for key, value in ctx.items():
        html = html.replace("{{" + key + "}}", str(value))
    return html


# ── Page builders ─────────────────────────────────────────────

def product_card_html(p):
    badge = '<span class="badge">New</span>' if p.get("is_new") else ""
    img = p["images"][0] if p.get("images") else "https://via.placeholder.com/400x500?text=No+Image"
    return f'''<a href="/product/{p["id"]}" class="product-card">
      <div class="product-image">
        <img src="{img}" alt="{p["name"]}" loading="lazy">
        {badge}
      </div>
      <div class="product-info">
        <span class="product-brand">{p["brand"]}</span>
        <span class="product-name">{p["name"]}</span>
        <span class="product-price">AED {p["price"]:,.2f}</span>
      </div>
    </a>'''


def build_home(products):
    new_products = [p for p in products if p.get("is_new")]
    featured_products = [p for p in products if p.get("is_featured")]
    new_html = "".join(product_card_html(p) for p in new_products)
    featured_html = "".join(product_card_html(p) for p in featured_products)
    return render_template("home.html",
                           new_products=new_html,
                           featured_products=featured_html)


def build_products_page(products, query="", category=""):
    filtered = products
    if query:
        q = query.lower()
        filtered = [p for p in filtered
                    if q in p["name"].lower()
                    or q in p["brand"].lower()
                    or q in p.get("description", "").lower()]
    if category and category != "All":
        filtered = [p for p in filtered if p.get("category") == category]

    categories = sorted(set(p.get("category", "Other") for p in products))
    cat_options = '<button class="filter-btn active" data-cat="All">All</button>'
    for c in categories:
        active = "active" if c == category else ""
        cat_options += f'<button class="filter-btn {active}" data-cat="{c}">{c}</button>'

    cards = "".join(product_card_html(p) for p in filtered)
    empty = '<p class="empty-state">No products found.</p>' if not filtered else ""

    return render_template("products.html",
                           product_cards=cards + empty,
                           category_filters=cat_options,
                           search_value=query)


def build_product_detail(product):
    if not product:
        return render_template("404.html")

    imgs_html = ""
    for i, img in enumerate(product.get("images", [])):
        active = "active" if i == 0 else ""
        imgs_html += f'<div class="slide {active}"><img src="{img}" alt="{product["name"]}"></div>'
    if not imgs_html:
        imgs_html = '<div class="slide active"><img src="https://via.placeholder.com/600x750?text=No+Image" alt="No image"></div>'

    thumb_html = ""
    for i, img in enumerate(product.get("images", [])):
        active = "active" if i == 0 else ""
        thumb_html += f'<button class="thumb {active}" onclick="goSlide({i})"><img src="{img}" alt="thumb"></button>'

    badge = '<span class="detail-badge">New Arrival</span>' if product.get("is_new") else ""
    wa_msg = f"Hi, I'm interested in the {product['brand']} {product['name']} (AED {product['price']:,.2f}) listed on Lumière Seconds."
    wa_link = f"https://wa.me/971544783154?text={wa_msg.replace(' ', '%20')}"

    return render_template("product_detail.html",
                           name=product["name"],
                           brand=product["brand"],
                           price=f"{product['price']:,.2f}",
                           description=product.get("description", ""),
                           condition=product.get("condition", "N/A"),
                           category=product.get("category", "N/A"),
                           badge=badge,
                           images=imgs_html,
                           thumbnails=thumb_html,
                           whatsapp_link=wa_link,
                           product_id=product["id"],
                           reference=product["id"][:8].upper())


def build_contact():
    return render_template("contact.html")


def build_about():
    return render_template("about.html")


def build_login(error=""):
    alert = f'<div class="alert alert-error">{error}</div>' if error else ""
    return render_template("login.html", alert=alert)


def build_admin(products, msg="", username="admin"):
    rows = ""
    for p in products:
        img = p["images"][0] if p.get("images") else "https://via.placeholder.com/60x60?text=?"
        new_badge = '<span class="status-badge status-new">New</span>' if p.get("is_new") else ""
        feat_badge = '<span class="status-badge status-feat">Featured</span>' if p.get("is_featured") else ""
        badges = f"{new_badge} {feat_badge}".strip()
        rows += f'''<tr>
          <td data-label="Image" class="td-image"><img src="{img}" alt="{p["name"]}" class="admin-thumb"></td>
          <td data-label="Product" class="td-product">
            <span class="td-brand">{p["brand"]}</span>
            <span class="td-name">{p["name"]}</span>
          </td>
          <td data-label="Price" class="td-price">AED {p["price"]:,.2f}</td>
          <td data-label="Category">{p.get("category","")}</td>
          <td data-label="Status" class="td-status">{badges if badges else '<span class="status-badge status-none">—</span>'}</td>
          <td data-label="Actions" class="actions-cell">
            <a href="/admin/edit/{p["id"]}" class="btn-sm">Edit</a>
            <form method="POST" action="/admin/delete/{p["id"]}" class="inline-form"
                  onsubmit="return confirm('Delete this product?')">
              <button type="submit" class="btn-sm btn-danger">Delete</button>
            </form>
          </td>
        </tr>'''

    alert = f'<div class="alert">{msg}</div>' if msg else ""

    # Build admin user list
    admins = load_admins()
    admin_rows = ""
    for a in admins:
        is_current = " (you)" if a["username"] == username else ""
        delete_btn = ""
        if a["username"] != username:
            delete_btn = f'''<form method="POST" action="/admin/users/delete" class="inline-form"
                  onsubmit="return confirm('Remove admin {a["username"]}?')">
              <input type="hidden" name="username" value="{a["username"]}">
              <button type="submit" class="btn-sm btn-danger">Remove</button>
            </form>'''
        admin_rows += f'''<tr>
          <td>{a["username"]}{is_current}</td>
          <td>{a.get("created_at", "—")[:10]}</td>
          <td class="actions-cell">{delete_btn}</td>
        </tr>'''

    return render_template("admin.html",
                           product_rows=rows,
                           alert=alert,
                           admin_username=username,
                           admin_user_rows=admin_rows)


def build_admin_form(product=None):
    if product:
        imgs = product.get("images", [])
        preview = ""
        if imgs:
            thumbs = "".join(f'<img src="{img}" alt="Product image" class="form-preview-img">' for img in imgs)
            preview = f'<div class="form-group"><label>Current Images</label><div class="form-preview-row">{thumbs}</div></div>'
        return render_template("admin_form.html",
                               form_title="Edit Product",
                               action=f"/admin/edit/{product['id']}",
                               name=product.get("name", ""),
                               brand=product.get("brand", ""),
                               price=str(product.get("price", "")),
                               description=product.get("description", ""),
                               category=product.get("category", ""),
                               condition=product.get("condition", ""),
                               is_new_checked="checked" if product.get("is_new") else "",
                               is_featured_checked="checked" if product.get("is_featured") else "",
                               current_images=", ".join(imgs),
                               image_preview=preview,
                               submit_label="Save Changes")
    return render_template("admin_form.html",
                           form_title="Add New Product",
                           action="/admin/add",
                           name="", brand="", price="", description="",
                           category="", condition="",
                           is_new_checked="", is_featured_checked="",
                           current_images="", image_preview="",
                           submit_label="Add Product")


def parse_multipart(body, content_type):
    """Simple multipart form parser."""
    boundary = content_type.split("boundary=")[1].encode()
    parts = body.split(b"--" + boundary)
    fields = {}
    files = []

    for part in parts:
        if b"Content-Disposition" not in part:
            continue
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        header = part[:header_end].decode("utf-8", errors="replace")
        data = part[header_end + 4:]
        if data.endswith(b"\r\n"):
            data = data[:-2]

        name_start = header.find('name="') + 6
        name_end = header.find('"', name_start)
        field_name = header[name_start:name_end]

        if "filename=" in header:
            fn_start = header.find('filename="') + 10
            fn_end = header.find('"', fn_start)
            filename = header[fn_start:fn_end]
            if filename and len(data) > 0:
                files.append((field_name, filename, data))
        else:
            fields[field_name] = data.decode("utf-8", errors="replace")

    return fields, files


def parse_form_body(body):
    fields = dict(parse_qs(body.decode()))
    return {k: v[0] for k, v in fields.items()}


# ── Server ────────────────────────────────────────────────────

MIME_TYPES = {
    ".css": "text/css", ".js": "application/javascript",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
    ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Handler(BaseHTTPRequestHandler):

    def get_user(self):
        return validate_session(self.headers.get("Cookie"))

    def require_auth(self):
        user = self.get_user()
        if not user:
            self.send_redirect("/admin/login")
            return None
        return user

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            params = parse_qs(parsed.query)
            products = load_products()

            # Public pages
            if path == "/":
                self.send_page(build_home(products))
            elif path == "/products":
                q = params.get("q", [""])[0]
                cat = params.get("category", [""])[0]
                self.send_page(build_products_page(products, q, cat))
            elif path.startswith("/product/"):
                pid = path.split("/product/")[1]
                prod = next((p for p in products if p["id"] == pid), None)
                self.send_page(build_product_detail(prod))
            elif path == "/contact":
                self.send_page(build_contact())
            elif path == "/about":
                self.send_page(build_about())

            # Auth pages
            elif path == "/admin/login":
                if self.get_user():
                    self.send_redirect("/admin")
                else:
                    self.send_page(build_login())
            elif path == "/admin/logout":
                destroy_session(self.headers.get("Cookie"))
                self.send_response(303)
                self.send_header("Location", "/admin/login")
                self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
                self.end_headers()

            # Protected admin pages
            elif path == "/admin":
                user = self.require_auth()
                if not user:
                    return
                msg = params.get("msg", [""])[0]
                self.send_page(build_admin(products, msg, user))
            elif path == "/admin/add":
                if not self.require_auth():
                    return
                self.send_page(build_admin_form())
            elif path.startswith("/admin/edit/"):
                if not self.require_auth():
                    return
                pid = path.split("/admin/edit/")[1]
                prod = next((p for p in products if p["id"] == pid), None)
                if prod:
                    self.send_page(build_admin_form(prod))
                else:
                    self.send_redirect("/admin?msg=Product+not+found")

            elif path.startswith("/static/"):
                self.serve_static(path)
            else:
                self.send_page(render_template("404.html"), code=404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_page(f"<h1>Server Error</h1><pre>{e}</pre>", code=500)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            content_type = self.headers.get("Content-Type", "")

            # ── Login ──
            if path == "/admin/login":
                fields = parse_form_body(body)
                username = fields.get("username", "").strip()
                password = fields.get("password", "")
                admins = load_admins()
                admin = next((a for a in admins if a["username"] == username), None)
                if admin and verify_password(password, admin["password_hash"]):
                    token = create_session(username)
                    self.send_response(303)
                    self.send_header("Location", "/admin")
                    self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Strict")
                    self.end_headers()
                else:
                    self.send_page(build_login("Invalid username or password."))
                return

            # All other POST routes require auth
            user = self.require_auth()
            if not user:
                return

            products = load_products()

            if path == "/admin/add":
                if "multipart" in content_type:
                    fields, files = parse_multipart(body, content_type)
                else:
                    fields = parse_form_body(body)
                    files = []

                new_id = str(uuid.uuid4())[:8]
                images = []
                for _, filename, data in files:
                    ext = os.path.splitext(filename)[1] or ".jpg"
                    save_name = f"{new_id}_{uuid.uuid4().hex[:6]}{ext}"
                    save_path = os.path.join(UPLOAD_DIR, save_name)
                    with open(save_path, "wb") as f:
                        f.write(data)
                    images.append(f"/static/images/products/{save_name}")

                if not images and fields.get("image_urls", "").strip():
                    images = [u.strip() for u in fields["image_urls"].split(",") if u.strip()]

                product = {
                    "id": new_id,
                    "name": fields.get("name", ""),
                    "brand": fields.get("brand", ""),
                    "price": float(fields.get("price", 0)),
                    "currency": "AED",
                    "description": fields.get("description", ""),
                    "category": fields.get("category", ""),
                    "condition": fields.get("condition", ""),
                    "is_new": "is_new" in fields,
                    "is_featured": "is_featured" in fields,
                    "images": images,
                    "created_at": datetime.now().strftime("%Y-%m-%d"),
                }
                products.insert(0, product)
                save_products(products)
                self.send_redirect("/admin?msg=Product+added+successfully")

            elif path.startswith("/admin/edit/"):
                pid = path.split("/admin/edit/")[1]
                if "multipart" in content_type:
                    fields, files = parse_multipart(body, content_type)
                else:
                    fields = parse_form_body(body)
                    files = []

                for p in products:
                    if p["id"] == pid:
                        new_images = []
                        for _, filename, data in files:
                            ext = os.path.splitext(filename)[1] or ".jpg"
                            save_name = f"{pid}_{uuid.uuid4().hex[:6]}{ext}"
                            save_path = os.path.join(UPLOAD_DIR, save_name)
                            with open(save_path, "wb") as f:
                                f.write(data)
                            new_images.append(f"/static/images/products/{save_name}")

                        if not new_images and fields.get("image_urls", "").strip():
                            new_images = [u.strip() for u in fields["image_urls"].split(",") if u.strip()]

                        p["name"] = fields.get("name", p["name"])
                        p["brand"] = fields.get("brand", p["brand"])
                        p["price"] = float(fields.get("price", p["price"]))
                        p["description"] = fields.get("description", p["description"])
                        p["category"] = fields.get("category", p["category"])
                        p["condition"] = fields.get("condition", p["condition"])
                        p["is_new"] = "is_new" in fields
                        p["is_featured"] = "is_featured" in fields
                        if new_images:
                            p["images"] = new_images
                        break

                save_products(products)
                self.send_redirect("/admin?msg=Product+updated+successfully")

            elif path.startswith("/admin/delete/"):
                pid = path.split("/admin/delete/")[1]
                products = [p for p in products if p["id"] != pid]
                save_products(products)
                self.send_redirect("/admin?msg=Product+deleted")

            elif path == "/admin/users/add":
                if "multipart" in content_type:
                    fields, _ = parse_multipart(body, content_type)
                else:
                    fields = parse_form_body(body)
                new_user = fields.get("new_username", "").strip().lower()
                new_pass = fields.get("new_password", "")
                if not new_user or not new_pass:
                    self.send_redirect("/admin?msg=Username+and+password+required")
                    return
                if len(new_pass) < 6:
                    self.send_redirect("/admin?msg=Password+must+be+at+least+6+characters")
                    return
                admins = load_admins()
                if any(a["username"] == new_user for a in admins):
                    self.send_redirect("/admin?msg=Username+already+exists")
                    return
                admins.append({
                    "username": new_user,
                    "password_hash": hash_password(new_pass),
                    "created_at": datetime.now().isoformat()
                })
                save_admins(admins)
                self.send_redirect(f"/admin?msg=Admin+{new_user}+added+successfully")

            elif path == "/admin/users/delete":
                if "multipart" in content_type:
                    fields, _ = parse_multipart(body, content_type)
                else:
                    fields = parse_form_body(body)
                target = fields.get("username", "").strip()
                if target == user:
                    self.send_redirect("/admin?msg=Cannot+remove+yourself")
                    return
                admins = load_admins()
                admins = [a for a in admins if a["username"] != target]
                save_admins(admins)
                self.send_redirect(f"/admin?msg=Admin+{target}+removed")

            else:
                self.send_redirect("/")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_page(f"<h1>Server Error</h1><pre>{e}</pre>", code=500)

    def serve_static(self, path):
        file_path = os.path.join(BASE_DIR, path.lstrip("/"))
        if not os.path.isfile(file_path):
            self.send_response(404)
            self.end_headers()
            return
        ext = os.path.splitext(file_path)[1].lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")
        with open(file_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def send_page(self, html, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def send_redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


if __name__ == "__main__":
    get_secret_key()  # Initialize on startup
    # Ensure default admin exists
    load_admins()
    port = int(os.environ.get("PORT", 8000))
    server = HTTPServer(("", port), Handler)
    print(f"\n  Lumière Seconds is running at http://localhost:{port}")
    print(f"  Admin panel: http://localhost:{port}/admin")
    print(f"  Default login: admin / lumiere2026\n")
    server.serve_forever()
