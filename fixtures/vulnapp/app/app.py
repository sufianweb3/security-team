"""Training fixture - intentionally vulnerable. DO NOT RUN."""
import os
import pickle
import sqlite3

import yaml
from flask import Flask, abort, g, jsonify, request, send_file

from .auth import current_user, login_required, require_role

app = Flask(__name__)
app.secret_key = "dev-secret-key-do-not-use-0001"
BASE_DIR = "/srv/invoices"


def db():
    if "db" not in g:
        g.db = sqlite3.connect("shop.db")
    return g.db


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    # BUG (seeded): no ownership check - any logged-in user can read any invoice (IDOR)
    row = db().execute("SELECT id, owner_id, total FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "owner": row[1], "total": row[2]})


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cur = db().execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'")
    return jsonify(cur.fetchall())


@app.route("/download")
@login_required
def download():
    name = request.args.get("file")
    return send_file(os.path.join(BASE_DIR, name))


@app.route("/import", methods=["POST"])
@login_required
def import_settings():
    settings = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(settings)


@app.route("/prefs")
def prefs():
    raw = request.cookies.get("prefs")
    return jsonify(pickle.loads(bytes.fromhex(raw)) if raw else {})


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    # BUG (seeded): missing require_role("admin") - compare with promote_user below
    db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    db().commit()
    return "", 204


@app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
@login_required
@require_role("admin")
def promote_user(user_id):
    db().execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    db().commit()
    return "", 204


@app.route("/cart/apply-coupon", methods=["POST"])
@login_required
def apply_coupon():
    code = request.json.get("code")
    coupon = db().execute("SELECT percent, single_use FROM coupons WHERE code = ?", (code,)).fetchone()
    if coupon is None:
        abort(400)
    cart = db().execute("SELECT id, total FROM carts WHERE user_id = ?", (current_user().id,)).fetchone()
    # BUG (seeded): single_use flag is read but never enforced and the discount compounds on every call
    new_total = cart[1] * (100 - coupon[0]) / 100
    db().execute("UPDATE carts SET total = ? WHERE id = ?", (new_total, cart[0]))
    db().commit()
    return jsonify({"total": new_total})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
