import sqlite3
import os
import secrets
import hashlib
from datetime import datetime

DB = "payroll.db"


def connect():
    # Parameterized SQL is used for values to reduce SQL injection risk.
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), 310_000).hex()


def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS employees (
        employee_id TEXT PRIMARY KEY, name TEXT NOT NULL, age INTEGER NOT NULL CHECK(age>=18),
        contact TEXT NOT NULL, education TEXT NOT NULL, department TEXT NOT NULL,
        designation TEXT NOT NULL, joining_date TEXT NOT NULL,
        basic_salary REAL NOT NULL CHECK(basic_salary>=0), bank_last4 TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        pay_month TEXT NOT NULL, basic_pay REAL NOT NULL, allowances REAL NOT NULL,
        deductions REAL NOT NULL, net_salary REAL NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(employee_id,pay_month),
        FOREIGN KEY(employee_id) REFERENCES employees(employee_id) ON DELETE CASCADE)""")
        c.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        event_type TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)""")


def create_user(username, password):
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(password, salt)
    with connect() as c:
        c.execute("INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                  (username, pwd_hash, salt))


def get_user(username):
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def log_event(username, event_type, details):
    # Do not put passwords, full bank account numbers, or other secrets in logs.
    with connect() as c:
        c.execute("INSERT INTO audit_events(username,event_type,details,created_at) VALUES(?,?,?,?)",
                  (username, event_type, details[:250],
                   datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


def get_recent_events(limit=50):
    with connect() as c:
        rows = c.execute(
            "SELECT username,event_type,details,created_at FROM audit_events ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_employee(eid):
    with connect() as c:
        row = c.execute("SELECT * FROM employees WHERE employee_id=?", (eid,)).fetchone()
    return dict(row) if row else None


def add_employee(e):
    with connect() as c:
        c.execute("""INSERT INTO employees VALUES
        (:employee_id,:name,:age,:contact,:education,:department,:designation,
         :joining_date,:basic_salary,:bank_last4)""", e)


def all_employees():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM employees ORDER BY name")]


def update_employee(eid, changes):
    allowed = {"name","contact","education","department","designation","joining_date","basic_salary"}
    changes = {k:v for k,v in changes.items() if k in allowed}
    if not changes:
        return
    changes["eid"] = eid
    sql = ", ".join(f"{k}=:{k}" for k in changes if k != "eid")
    with connect() as c:
        c.execute(f"UPDATE employees SET {sql} WHERE employee_id=:eid", changes)


def delete_employee(eid):
    with connect() as c:
        c.execute("DELETE FROM employees WHERE employee_id=?", (eid,))


def record_payment(eid, month, basic, allowances, deductions, net):
    try:
        with connect() as c:
            c.execute("""INSERT INTO payments
            (employee_id,pay_month,basic_pay,allowances,deductions,net_salary,status,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (eid,month,basic,allowances,deductions,net,"SIMULATED_CREDIT",
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        return True
    except sqlite3.IntegrityError:
        return False


def payments(eid):
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT pay_month,net_salary,status,created_at FROM payments WHERE employee_id=? ORDER BY pay_month DESC",
            (eid,))]
