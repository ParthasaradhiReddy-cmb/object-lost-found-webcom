import os
import re
import sqlite3
import uuid
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template_string,
    session, redirect, url_for, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# --------------------------------------------------
# FLASK CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Set SECRET_KEY in your environment variables.")

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)

DATABASE = os.environ.get("DATABASE_PATH", "lost_found.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")

Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            location TEXT NOT NULL,
            item_type TEXT NOT NULL,
            phone TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active',
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            image_filename TEXT
        )
    """)

    # Migrate older databases if columns are missing.
    columns = [
        row["name"]
        for row in cur.execute("PRAGMA table_info(items)").fetchall()
    ]

    migrations = {
        "phone": "ALTER TABLE items ADD COLUMN phone TEXT DEFAULT ''",
        "user_id": "ALTER TABLE items ADD COLUMN user_id INTEGER",
        "created_at": "ALTER TABLE items ADD COLUMN created_at TIMESTAMP",
        "image_filename": "ALTER TABLE items ADD COLUMN image_filename TEXT"
    }

    for column, sql in migrations.items():
        if column not in columns:
            cur.execute(sql)

    # Create or update the administrator from environment variables.
    admin_username = os.environ.get(
        "ADMIN_USERNAME", "Parthasaradhi Reddy"
    ).strip()

    admin_password = os.environ.get("ADMIN_PASSWORD")

    if not admin_password:
        raise RuntimeError(
            "Set ADMIN_PASSWORD in your environment variables."
        )

    admin_email = (
        re.sub(r"[^a-z0-9]", "", admin_username.lower())
        + "@admin.local"
    )

    existing_admin = cur.execute(
        "SELECT * FROM users WHERE username = ?",
        (admin_username,)
    ).fetchone()

    password_hash = generate_password_hash(admin_password)

    if existing_admin:
        cur.execute("""
            UPDATE users
            SET password_hash = ?, role = 'admin'
            WHERE username = ?
        """, (password_hash, admin_username))
    else:
        email_owner = cur.execute(
            "SELECT id FROM users WHERE email = ?",
            (admin_email,)
        ).fetchone()

        if email_owner:
            admin_email = (
                re.sub(r"[^a-z0-9]", "", admin_username.lower())
                + str(uuid.uuid4().hex[:8])
                + "@admin.local"
            )

        cur.execute("""
            INSERT INTO users
            (username, email, password_hash, role)
            VALUES (?, ?, ?, 'admin')
        """, (admin_username, admin_email, password_hash))

    conn.commit()
    conn.close()


# --------------------------------------------------
# AUTHENTICATION HELPERS
# --------------------------------------------------

def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, email, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    return user


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Please login first."}), 401
        return function(*args, **kwargs)
    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_current_user()

        if not user or user["role"] != "admin":
            return jsonify({"error": "Admin access required."}), 403

        return function(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def mask_phone(phone):
    """Mask a valid Indian mobile number for visitors."""
    if not phone:
        return "Not provided"

    phone = str(phone)

    if re.fullmatch(r"\+91[6-9][0-9]{9}", phone):
        return "+91******" + phone[-4:]

    return "Hidden"


# --------------------------------------------------
# ITEM DATA
# --------------------------------------------------

def item_to_dict(row):
    data = dict(row)

    # Logged-in students and admin see the full number.
    # Visitors see only the masked number.
    if session.get("user_id"):
        data["phone"] = data.get("phone") or "Not provided"
    else:
        data["phone"] = mask_phone(data.get("phone"))

    filename = data.get("image_filename")

    data["image_url"] = (
        url_for("uploaded_file", filename=filename)
        if filename else None
    )

    data["is_mine"] = (
        data.get("user_id") == session.get("user_id")
    )

    data.pop("user_id", None)

    return data


# --------------------------------------------------
# MAIN WEBSITE HTML
# --------------------------------------------------

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Campus Lost and Found</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            margin: 0;
            color: #1e293b;
        }

        header {
            background: #123b63;
            color: white;
            padding: 22px;
            text-align: center;
        }

        nav {
            background: #0f2942;
            padding: 12px;
            text-align: center;
        }

        nav a, nav button {
            color: white;
            margin: 8px;
            text-decoration: none;
            font-size: 15px;
            background: none;
            border: none;
            cursor: pointer;
        }

        .container {
            max-width: 1100px;
            margin: 25px auto;
            padding: 15px;
        }

        .card {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 12px;
            box-shadow: 0 3px 12px #00000012;
        }

        input, textarea, select {
            width: 100%;
            padding: 12px;
            margin: 8px 0 15px;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
            font-size: 15px;
        }

        button {
            background: #1769aa;
            color: white;
            border: none;
            padding: 11px 17px;
            border-radius: 7px;
            cursor: pointer;
        }

        button:hover {
            background: #0e4e85;
        }

        .danger {
            background: #dc2626;
        }

        .success {
            background: #15803d;
        }

        .items {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 18px;
        }

        .item {
            background: white;
            padding: 18px;
            border-radius: 12px;
            box-shadow: 0 3px 12px #00000012;
        }

        .item img {
            width: 100%;
            max-height: 210px;
            object-fit: cover;
            border-radius: 8px;
        }

        .status {
            font-weight: bold;
            color: #15803d;
        }

        .recovered {
            color: #64748b;
        }

        .hidden {
            display: none;
        }

        .message {
            padding: 12px;
            background: #e0f2fe;
            border-radius: 7px;
            margin-bottom: 15px;
        }

        footer {
            background: #123b63;
            color: white;
            padding: 18px;
            text-align: center;
            margin-top: 35px;
        }
    </style>
</head>

<body>

<header>
    <h1>Campus Lost and Found</h1>
    <p>Helping students find their lost belongings</p>
</header>

<nav>
    <a href="/">Home</a>
    {% if user %}
        <span>Welcome, {{ user["username"] }}</span>
        {% if user["role"] == "admin" %}
            <a href="/admin">Admin Dashboard</a>
        {% endif %}
        <button onclick="logout()">Logout</button>
    {% else %}
        <a href="/login">Login</a>
        <a href="/register">Register</a>
        <a href="/admin/login">Admin Login</a>
    {% endif %}
</nav>

<div class="container">

    {% with messages = get_flashed_messages() %}
        {% for message in messages %}
            <div class="message">{{ message }}</div>
        {% endfor %}
    {% endwith %}

    {% if user %}
    <div class="card">
        <h2>Report Lost or Found Item</h2>

        <form id="itemForm" enctype="multipart/form-data">

            <label>Item Name</label>
            <input type="text" name="name" required
                   placeholder="Example: College ID card">

            <label>Description</label>
            <textarea name="description"
                      placeholder="Describe the item"></textarea>

            <label>Location</label>
            <input type="text" name="location" required
                   placeholder="Where was it lost or found?">

            <label>Item Type</label>
            <select name="item_type" required>
                <option value="Lost">Lost</option>
                <option value="Found">Found</option>
            </select>

            <label>Indian Mobile Number (+91)</label>
            <input
                type="tel"
                name="phone"
                pattern="\+91[6-9][0-9]{9}"
                maxlength="13"
                minlength="13"
                required
                placeholder="+919876543210"
                title="Enter +91 followed by a valid 10-digit Indian mobile number"
            >

            <label>Upload Item Image (Optional)</label>
            <input type="file" name="image"
                   accept=".jpg,.jpeg,.png,.gif,.webp">

            <button type="submit">Submit Report</button>
        </form>
    </div>
    {% else %}
    <div class="card">
        <h2>Welcome!</h2>
        <p>Please login or register to report a lost or found item.</p>
        <a href="/login"><button>Login</button></a>
        <a href="/register"><button>Register</button></a>
    </div>
    {% endif %}

    <div class="card">
        <h2>Search Lost and Found Items</h2>

        <input type="text" id="search"
               placeholder="Search by item name or location..."
               oninput="loadItems()">

        <select id="filter" onchange="loadItems()">
            <option value="">All Items</option>
            <option value="Lost">Lost Items</option>
            <option value="Found">Found Items</option>
        </select>
    </div>

    <h2>Reported Items</h2>
    <div id="items" class="items"></div>

</div>

<footer>
    <p>Campus Lost and Found Website</p>
</footer>

<script>

async function loadItems() {
    const search = document.getElementById("search").value;
    const filter = document.getElementById("filter").value;

    const response = await fetch(
        "/api/items?search=" + encodeURIComponent(search) +
        "&type=" + encodeURIComponent(filter)
    );

    const items = await response.json();

    const container = document.getElementById("items");
    container.innerHTML = "";

    if (!items.length) {
        container.innerHTML = "<p>No items found.</p>";
        return;
    }

    items.forEach(item => {
        const card = document.createElement("div");
        card.className = "item";

        const title = document.createElement("h3");
        title.textContent = item.name;

        const type = document.createElement("p");
        type.textContent = "Type: " + item.item_type;

        const description = document.createElement("p");
        description.textContent = "Description: " + (item.description || "");

        const location = document.createElement("p");
        location.textContent = "Location: " + item.location;

        const phone = document.createElement("p");
        phone.textContent = "Contact: " + (item.phone || "Not provided");

        const status = document.createElement("p");
        status.textContent = "Status: " + item.status;
        status.className = item.status === "Recovered"
            ? "recovered" : "status";

        card.appendChild(title);
        card.appendChild(type);
        card.appendChild(description);
        card.appendChild(location);
        card.appendChild(phone);

        if (item.image_url) {
            const img = document.createElement("img");
            img.src = item.image_url;
            img.alt = "Reported item image";
            card.appendChild(img);
        }

        card.appendChild(status);

        if (item.status !== "Recovered" && item.can_recover) {
            const recoverButton = document.createElement("button");
            recoverButton.textContent = "Mark as Recovered";
            recoverButton.className = "success";
            recoverButton.onclick = () => recoverItem(item.id);
            card.appendChild(recoverButton);
        }

        if (item.can_delete) {
            const deleteButton = document.createElement("button");
            deleteButton.textContent = "Delete Report";
            deleteButton.className = "danger";
            deleteButton.onclick = () => deleteItem(item.id);
            card.appendChild(deleteButton);
        }

        container.appendChild(card);
    });
}


document.getElementById("itemForm")?.addEventListener(
    "submit", async function(event) {

    event.preventDefault();

    const formData = new FormData(this);

    const response = await fetch("/api/items", {
        method: "POST",
        body: formData
    });

    const result = await response.json();

    if (response.ok) {
        alert("Item reported successfully!");
        this.reset();
        loadItems();
    } else {
        alert(result.error || "Unable to submit report.");
    }
});


async function recoverItem(id) {
    if (!confirm("Mark this item as recovered?")) return;

    const response = await fetch("/api/items/" + id + "/recover", {
        method: "POST"
    });

    const result = await response.json();

    if (response.ok) {
        alert("Item marked as recovered.");
        loadItems();
    } else {
        alert(result.error || "Unable to update item.");
    }
}


async function deleteItem(id) {
    if (!confirm("Are you sure you want to delete this report?")) return;

    const response = await fetch("/api/items/" + id, {
        method: "DELETE"
    });

    const result = await response.json();

    if (response.ok) {
        alert("Report deleted.");
        loadItems();
    } else {
        alert(result.error || "Unable to delete report.");
    }
}


async function logout() {
    await fetch("/api/logout", {method: "POST"});
    window.location.href = "/";
}

loadItems();

</script>

</body>
</html>
"""


# --------------------------------------------------
# LOGIN AND REGISTER HTML
# --------------------------------------------------

AUTH_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial;
            background: #eef2f7;
            padding: 20px;
        }

        .box {
            background: white;
            max-width: 400px;
            margin: 60px auto;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 15px #0002;
        }

        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 7px;
        }

        .password-box {
            position: relative;
            width: 100%;
        }

        .password-box input {
            padding-right: 50px;
        }

        .eye-button {
            position: absolute;
            right: 5px;
            top: 17px;
            width: 40px;
            padding: 7px;
            background: transparent;
            color: #333;
            font-size: 18px;
        }

        .eye-button:hover {
            background: transparent;
        }

        button {
            width: 100%;
            padding: 12px;
            background: #1769aa;
            color: white;
            border: none;
            border-radius: 7px;
            cursor: pointer;
        }

        a {
            display: block;
            margin-top: 15px;
            text-align: center;
        }
    </style>
</head>

<body>

<div class="box">

    <h2>{{ title }}</h2>

    {% with messages = get_flashed_messages() %}
        {% for message in messages %}
            <p>{{ message }}</p>
        {% endfor %}
    {% endwith %}

    <form method="POST">

        {% if register %}
            <input name="username" placeholder="Username" required>
            <input name="email" type="email" placeholder="Email" required>
        {% else %}
            <input name="username" placeholder="Username" required>
        {% endif %}

        <div class="password-box">
            <input
                id="password"
                name="password"
                type="password"
                placeholder="Password"
                required
            >

            <button
                type="button"
                class="eye-button"
                onclick="togglePassword()"
                aria-label="Show password"
            >👁</button>
        </div>

        <button type="submit">{{ title }}</button>
    </form>

    {% if register %}
        <a href="/login">Already registered? Login</a>
    {% else %}
        <a href="/register">Create student account</a>
    {% endif %}

    <a href="/">Back to Home</a>

</div>

<script>
function togglePassword() {
    const password = document.getElementById("password");
    const eye = document.querySelector(".eye-button");

    if (password.type === "password") {
        password.type = "text";
        eye.textContent = "🙈";
        eye.setAttribute("aria-label", "Hide password");
    } else {
        password.type = "password";
        eye.textContent = "👁";
        eye.setAttribute("aria-label", "Show password");
    }
}
</script>

</body>
</html>
"""


# --------------------------------------------------
# ADMIN DASHBOARD HTML
# --------------------------------------------------

ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial;
            background: #f1f5f9;
            margin: 0;
            padding: 20px;
        }

        .box {
            max-width: 1000px;
            margin: auto;
            background: white;
            padding: 20px;
            border-radius: 12px;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        th, td {
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }

        th {
            background: #123b63;
            color: white;
        }

        button {
            padding: 8px 12px;
            background: #dc2626;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        a {
            display: inline-block;
            margin: 10px 0;
        }
    </style>
</head>

<body>

<div class="box">

    <h1>Admin Dashboard</h1>

    <p>Welcome, {{ user["username"] }}</p>

    <a href="/">Back to Website</a>
    <button onclick="logout()">Logout</button>

    <h2>Registered Students</h2>

    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Action</th>
            </tr>
        </thead>

        <tbody id="users"></tbody>
    </table>

</div>

<script>

async function loadUsers() {
    const response = await fetch("/api/admin/users");

    if (!response.ok) {
        alert("Unable to load registered students. Please login again.");
        return;
    }

    const users = await response.json();

    const tbody = document.getElementById("users");
    tbody.innerHTML = "";

    users.forEach(user => {
        const row = document.createElement("tr");

        const id = document.createElement("td");
        id.textContent = user.id;

        const username = document.createElement("td");
        username.textContent = user.username;

        const email = document.createElement("td");
        email.textContent = user.email;

        const action = document.createElement("td");

        const button = document.createElement("button");

        if (user.role === "admin") {
            button.textContent = "Admin";
            button.disabled = true;
        } else {
            button.textContent = "Delete User";
            button.onclick = () => deleteUser(user.id);
        }

        action.appendChild(button);

        row.appendChild(id);
        row.appendChild(username);
        row.appendChild(email);
        row.appendChild(action);

        tbody.appendChild(row);
    });
}


async function deleteUser(id) {
    if (!confirm("Delete this student account?")) return;

    const response = await fetch("/api/admin/users/" + id, {
        method: "DELETE"
    });

    const result = await response.json();

    if (response.ok) {
        alert("Student account deleted.");
        loadUsers();
    } else {
        alert(result.error || "Unable to delete user.");
    }
}


async function logout() {
    await fetch("/api/logout", {method: "POST"});
    window.location.href = "/";
}

loadUsers();

</script>

</body>
</html>
"""


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    user = get_current_user()
    return render_template_string(HTML, user=user)


# --------------------------------------------------
# STUDENT REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO users
                (username, email, password_hash, role)
                VALUES (?, ?, ?, 'user')
            """, (
                username,
                email,
                generate_password_hash(password)
            ))

            conn.commit()

            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username or email already exists.")

        finally:
            conn.close()

    return render_template_string(
        AUTH_HTML,
        title="Student Registration",
        register=True
    )


# --------------------------------------------------
# STUDENT LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and user["role"] == "user" and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("home"))

        flash("Invalid student username or password.")

    return render_template_string(
        AUTH_HTML,
        title="Student Login",
        register=False
    )


# --------------------------------------------------
# SEPARATE ADMIN LOGIN
# --------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and user["role"] == "admin" and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin username or password.")

    return render_template_string(
        AUTH_HTML,
        title="Admin Login",
        register=False
    )


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
def admin_dashboard():

    user = get_current_user()

    if not user or user["role"] != "admin":
        return redirect(url_for("admin_login"))

    return render_template_string(ADMIN_HTML, user=user)


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})


# --------------------------------------------------
# IMAGE UPLOAD ACCESS
# --------------------------------------------------

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# --------------------------------------------------
# ADD AND VIEW ITEMS
# --------------------------------------------------

@app.route("/api/items", methods=["GET", "POST"])
def items():

    if request.method == "POST":

        if not session.get("user_id"):
            return jsonify({"error": "Please login first."}), 401

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        item_type = request.form.get("item_type", "").strip()
        phone = request.form.get("phone", "").strip()

        if not name or not location or not phone:
            return jsonify({"error": "Please fill all required fields."}), 400

        if not re.fullmatch(r"\+91[6-9][0-9]{9}", phone):
            return jsonify({
                "error": (
                    "Enter a valid Indian mobile number starting with "
                    "+91 followed by 10 digits."
                )
            }), 400

        if item_type not in ("Lost", "Found"):
            return jsonify({"error": "Invalid item type."}), 400

        image_filename = None
        uploaded_image = request.files.get("image")

        if uploaded_image and uploaded_image.filename:

            if not allowed_file(uploaded_image.filename):
                return jsonify({
                    "error": "Only JPG, JPEG, PNG, GIF and WEBP images are allowed."
                }), 400

            original_name = secure_filename(uploaded_image.filename)

            if "." not in original_name:
                return jsonify({"error": "Invalid image filename."}), 400

            extension = original_name.rsplit(".", 1)[1].lower()
            image_filename = str(uuid.uuid4()) + "." + extension

            uploaded_image.save(
                os.path.join(UPLOAD_FOLDER, image_filename)
            )

        conn = get_db()

        conn.execute("""
            INSERT INTO items
            (name, description, location, item_type,
             phone, user_id, image_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            description,
            location,
            item_type,
            phone,
            session["user_id"],
            image_filename
        ))

        conn.commit()
        conn.close()

        return jsonify({"message": "Item added successfully."})

    search = request.args.get("search", "").strip()
    item_type = request.args.get("type", "").strip()

    conn = get_db()

    query = "SELECT * FROM items WHERE 1=1"
    params = []

    if search:
        query += " AND (name LIKE ? OR location LIKE ? OR description LIKE ?)"
        term = "%" + search + "%"
        params.extend([term, term, term])

    if item_type in ("Lost", "Found"):
        query += " AND item_type = ?"
        params.append(item_type)

    query += " ORDER BY id DESC"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    user = get_current_user()
    is_admin = bool(user and user["role"] == "admin")

    result = []

    for row in rows:
        data = item_to_dict(row)

        data["can_recover"] = bool(
            user and (
                is_admin or row["user_id"] == user["id"]
            )
        )

        data["can_delete"] = is_admin

        result.append(data)

    return jsonify(result)


# --------------------------------------------------
# MARK ITEM AS RECOVERED
# --------------------------------------------------

@app.route("/api/items/<int:item_id>/recover", methods=["POST"])
@login_required
def recover_item(item_id):

    user = get_current_user()

    conn = get_db()

    item = conn.execute(
        "SELECT * FROM items WHERE id = ?",
        (item_id,)
    ).fetchone()

    if not item:
        conn.close()
        return jsonify({"error": "Item not found."}), 404

    if user["role"] != "admin" and item["user_id"] != user["id"]:
        conn.close()
        return jsonify({
            "error": "Only the report owner or admin can recover this item."
        }), 403

    conn.execute(
        "UPDATE items SET status = 'Recovered' WHERE id = ?",
        (item_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "Item marked as recovered."})


# --------------------------------------------------
# ADMIN DELETE ITEM
# --------------------------------------------------

@app.route("/api/items/<int:item_id>", methods=["DELETE"])
@admin_required
def delete_item(item_id):

    conn = get_db()

    item = conn.execute(
        "SELECT image_filename FROM items WHERE id = ?",
        (item_id,)
    ).fetchone()

    if not item:
        conn.close()
        return jsonify({"error": "Item not found."}), 404

    filename = item["image_filename"]

    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    if filename:
        image_path = os.path.join(UPLOAD_FOLDER, filename)

        if os.path.exists(image_path):
            os.remove(image_path)

    return jsonify({"message": "Item deleted successfully."})


# --------------------------------------------------
# ADMIN VIEW STUDENTS
# --------------------------------------------------

@app.route("/api/admin/users")
@admin_required
def admin_users():

    conn = get_db()

    users = conn.execute("""
        SELECT id, username, email, role
        FROM users
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return jsonify([dict(user) for user in users])


# --------------------------------------------------
# ADMIN DELETE STUDENT
# --------------------------------------------------

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User not found."}), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({"error": "Admin accounts cannot be deleted here."}), 403

    # Remove the user's reports and uploaded images.
    items = conn.execute(
        "SELECT image_filename FROM items WHERE user_id = ?",
        (user_id,)
    ).fetchall()

    conn.execute("DELETE FROM items WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    for item in items:
        filename = item["image_filename"]

        if filename:
            image_path = os.path.join(UPLOAD_FOLDER, filename)

            if os.path.exists(image_path):
                os.remove(image_path)

    return jsonify({"message": "Student account deleted."})


# --------------------------------------------------
# FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "Image is too large. Maximum file size is 5 MB."
    }), 413


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

create_tables()

if __name__ == "__main__":
    app.run(debug=False)
