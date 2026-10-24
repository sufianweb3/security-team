"""Training fixture - intentionally vulnerable. DO NOT RUN."""
from functools import wraps

from flask import abort, g, session


def current_user():
    return g.user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


def require_role(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if getattr(g.user, "role", None) != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco
