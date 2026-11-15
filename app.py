"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3

from flask import Flask, g, jsonify, request
from security import hash_password, verify_password
from dotenv import load_dotenv
import os
import jwt
from datetime import datetime, timedelta
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is missing")

from functools import wraps


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401

        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Authorization header must use Bearer <token>"
            }), 401

        token = parts[1]

        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid token"}), 401

        if payload.get("sub") is None or payload.get("role") is None:
            return jsonify({"error": "Invalid token payload"}), 401

        g.user_id = payload["sub"]
        g.role = payload["role"]

        return f(*args, **kwargs)

    return wrapper

DATABASE = "recipes.db"

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
@require_auth
def create_recipe():
   
    user_id = g.user_id


    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,  # 👈 stamp the owner here
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201
    
@app.post("/users")
def create_user():
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not all(
        isinstance(data.get(field), str) and data[field].strip()
        for field in ("username", "email", "password")
    ):
        return jsonify({
            "error": "username, email, and password are required"
        }), 400

    username = data["username"].strip()
    email = data["email"].strip()
    password_hash = hash_password(data["password"])

    db = get_db()

    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash)"
            " VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({
            "error": "username or email already exists"
        }), 409

    return jsonify({
        "id": cur.lastrowid,
        "username": username,
        "email": email,
    }), 201

@app.post("/login")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not all(
        isinstance(data.get(field), str) and data[field].strip()
        for field in ("username", "password")
    ):
        return jsonify({
            "error": "username and password are required"
        }), 400

    row = get_db().execute(
        "SELECT id, username, email, password_hash, role FROM users "
        "WHERE username = ?",
        (data["username"].strip(),),
    ).fetchone()

    if row is None:
        return jsonify({"error": "invalid credentials"}), 401

    from security import verify_password

    if not verify_password(row["password_hash"], data["password"]):
        return jsonify({"error": "invalid credentials"}), 401

    # --- NEW: build JWT payload ---
    payload = {
        "sub": str(row["id"]),  # user id as string
        "role": row["role"],
        "exp": datetime.utcnow() + timedelta(hours=2),
    }

    # --- NEW: sign the token ---
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # --- UPDATED: return token with existing data ---
    return jsonify({
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "token": token,
    }), 200

@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    user_id = g.user_id
    role = g.role

    db = get_db()

    # 🔐 1) Load the recipe and check ownership
    recipe_row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if recipe_row is None:
        return jsonify({"error": "recipe not found"}), 404

     # 🔐 owner OR admin check
    if str(recipe_row["owner_id"]) != user_id and role != "admin":
        return jsonify(
            {"error": "you do not have permission to modify this recipe"}
            ), 403
    # ✅ 2) From here on, we know the user owns this recipe
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400

    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    values.append(recipe_id)

    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))

@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    user_id = g.user_id
    role = g.role

    db = get_db()

    recipe_row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()

    if recipe_row is None:
        return jsonify({"error": "recipe not found"}), 404

    # Only the recipe owner or an admin can delete it.
    if str(recipe_row["owner_id"]) != user_id and role != "admin":
        return jsonify({
            "error": "you do not have permission to delete this recipe"
        }), 403

    db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()

    return "", 204


if __name__ == "__main__":
    app.run(debug=True)
