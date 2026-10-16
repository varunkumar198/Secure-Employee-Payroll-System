"""Employee Payroll System - security-focused beginner project.

Run locally with: python app.py
This is a console learning project, not a production payroll service.
"""
import getpass
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from database import (
    init_db, add_employee, get_employee, all_employees,
    update_employee, delete_employee, record_payment, payments,
    create_user, get_user, log_event, get_recent_events
)

MAX_ATTEMPTS = 5
LOCK_SECONDS = 60
FAILED_ATTEMPTS = {}
SESSION_TIMEOUT_SECONDS = 15 * 60
DB_FILE = Path("payroll.db")


def read_text(prompt, required=True, max_length=120):
    while True:
        value = input(prompt).strip()
        if value or not required:
            if len(value) > max_length:
                print(f"Please use at most {max_length} characters.")
                continue
            return value
        print("This field is required.")


def read_number(prompt, minimum=0, integer=False):
    while True:
        try:
            value = int(input(prompt)) if integer else float(input(prompt))
            if value < minimum:
                print(f"Enter a value greater than or equal to {minimum}.")
                continue
            return value
        except ValueError:
            print("Invalid number. Please try again.")


def password_rules(password):
    return (
        len(password) >= 12
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


def setup_admin():
    if get_user("admin"):
        return
    print("\nFirst-time setup: create the local administrator account.")
    while True:
        password = getpass.getpass("Create admin password (12+ chars, upper/lower/digit/symbol): ")
        if not password_rules(password):
            print("Use at least 12 characters with uppercase, lowercase, a digit, and a symbol.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            continue
        create_user("admin", password)
        log_event("SYSTEM", "ADMIN_CREATED", "Initial admin account created")
        print("Administrator created.")
        return


def login():
    setup_admin()
    username = read_text("Username: ", max_length=40)
    now = time.time()
    attempts, locked_until = FAILED_ATTEMPTS.get(username, (0, 0))
    if now < locked_until:
        print(f"Too many attempts. Try again in {int(locked_until-now)} seconds.")
        return None

    password = getpass.getpass("Password: ")
    user = get_user(username)
    # Check a password hash only; never store or log plain-text passwords.
    ok = bool(user and hmac.compare_digest(user["password_hash"], hash_password(password, user["salt"])))
    if not ok:
        attempts += 1
        lock = now + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
        FAILED_ATTEMPTS[username] = (0 if lock else attempts, lock)
        log_event(username, "LOGIN_FAILED", "Invalid login attempt")
        print("Invalid username or password.")
        return None
    FAILED_ATTEMPTS.pop(username, None)
    log_event(username, "LOGIN_SUCCESS", "Administrator signed in")
    return {"username": username, "last_activity": time.time()}


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), 310_000
    ).hex()


def check_session(session):
    if time.time() - session["last_activity"] > SESSION_TIMEOUT_SECONDS:
        log_event(session["username"], "SESSION_TIMEOUT", "Session expired after inactivity")
        print("Session expired. Please log in again.")
        return False
    session["last_activity"] = time.time()
    return True


def show_employee(e):
    if not e:
        print("Employee not found.")
        return
    for key, value in e.items():
        if key == "bank_last4":
            value = "****" if value else "Not provided"
        print(f"{key.replace('_', ' ').title()}: {value}")


def add_employee_menu(user):
    eid = read_text("Employee ID: ", max_length=30)
    if get_employee(eid):
        print("That employee ID already exists.")
        return
    employee = {
        "employee_id": eid,
        "name": read_text("Full name: ", max_length=100),
        "age": read_number("Age (18+): ", 18, True),
        "contact": read_text("Contact number: ", max_length=25),
        "education": read_text("Education: ", max_length=100),
        "department": read_text("Department: ", max_length=80),
        "designation": read_text("Designation: ", max_length=80),
        "joining_date": read_text("Joining date (YYYY-MM-DD): ", max_length=10),
        "basic_salary": read_number("Monthly basic salary (Rs): "),
        "bank_last4": read_text("Last 4 bank-account digits (optional): ", False, 4)
    }
    if employee["bank_last4"] and (
        len(employee["bank_last4"]) != 4 or not employee["bank_last4"].isdigit()
    ):
        print("Enter exactly four digits or leave blank.")
        return
    try:
        datetime.strptime(employee["joining_date"], "%Y-%m-%d")
    except ValueError:
        print("Date must be a valid YYYY-MM-DD date.")
        return
    add_employee(employee)
    log_event(user, "EMPLOYEE_ADDED", f"Employee ID: {eid}")
    print("Employee added.")


def search_menu(user):
    eid = read_text("Employee ID: ", max_length=30)
    show_employee(get_employee(eid))
    log_event(user, "EMPLOYEE_SEARCHED", f"Employee ID: {eid}")


def list_menu(user):
    rows = all_employees()
    if not rows:
        print("No employee records.")
    for e in rows:
        print(f"{e['employee_id']} | {e['name']} | {e['department']} | Rs {e['basic_salary']:.2f}")
    log_event(user, "EMPLOYEE_LIST_VIEWED", f"Count: {len(rows)}")


def update_menu(user):
    eid = read_text("Employee ID to update: ", max_length=30)
    e = get_employee(eid)
    if not e:
        print("Employee not found.")
        return
    changes = {}
    for field in ("name", "contact", "education", "department", "designation", "joining_date"):
        value = input(f"{field.title()} [{e[field]}] (Enter to keep): ").strip()
        if value:
            if len(value) > 120:
                print("Value is too long.")
                return
            changes[field] = value
    salary = input(f"Basic salary [{e['basic_salary']}] (Enter to keep): ").strip()
    if salary:
        try:
            amount = float(salary)
            if amount < 0: raise ValueError()
            changes["basic_salary"] = amount
        except ValueError:
            print("Invalid salary.")
            return
    update_employee(eid, changes)
    log_event(user, "EMPLOYEE_UPDATED", f"Employee ID: {eid}")
    print("Employee updated.")


def delete_menu(user):
    eid = read_text("Employee ID to delete: ", max_length=30)
    if not get_employee(eid):
        print("Employee not found.")
        return
    if input("Type DELETE to confirm: ") == "DELETE":
        delete_employee(eid)
        log_event(user, "EMPLOYEE_DELETED", f"Employee ID: {eid}")
        print("Employee deleted; associated demo payment history was also deleted.")
    else:
        print("Cancelled.")


def payroll_menu(user):
    eid = read_text("Employee ID: ", max_length=30)
    e = get_employee(eid)
    if not e:
        print("Employee not found.")
        return
    days = read_number("Days worked (0-30): ", 0, True)
    if days > 30:
        print("Days cannot exceed 30 in this demo.")
        return
    allowances = read_number("Total allowances (Rs): ")
    deductions = read_number("Total deductions (Rs): ")
    basic = e["basic_salary"] * days / 30
    gross = basic + allowances
    net = gross - deductions
    if net < 0:
        print("Deductions exceed gross pay.")
        return
    print(f"\nBasic pay: Rs {basic:.2f}")
    print(f"Allowances: Rs {allowances:.2f}")
    print(f"Gross pay: Rs {gross:.2f}")
    print(f"Deductions: Rs {deductions:.2f}")
    print(f"NET SALARY: Rs {net:.2f}")
    month = read_text("Payroll month (YYYY-MM): ", max_length=7)
    try:
        datetime.strptime(month, "%Y-%m")
    except ValueError:
        print("Month must be in YYYY-MM format.")
        return
    if input("Record simulated salary credit? (y/n): ").lower() == "y":
        if record_payment(eid, month, basic, allowances, deductions, net):
            log_event(user, "PAYMENT_RECORDED", f"Employee ID: {eid}; month: {month}")
            print("Simulated payment recorded. No real bank transfer occurred.")
        else:
            log_event(user, "DUPLICATE_PAYMENT_BLOCKED", f"Employee ID: {eid}; month: {month}")
            print("A payment already exists for this employee and month.")


def history_menu(user):
    eid = read_text("Employee ID: ", max_length=30)
    if not get_employee(eid):
        print("Employee not found.")
        return
    rows = payments(eid)
    for row in rows:
        print(f"{row['pay_month']} | Net Rs {row['net_salary']:.2f} | {row['status']} | {row['created_at']}")
    log_event(user, "PAYMENT_HISTORY_VIEWED", f"Employee ID: {eid}")


def audit_menu(user):
    for row in get_recent_events():
        print(f"{row['created_at']} | {row['username']} | {row['event_type']} | {row['details']}")
    log_event(user, "AUDIT_LOG_VIEWED", "Recent security events viewed")


def main():
    init_db()
    print("Security note: this is a local educational demo; protect your computer and backups.")
    session = login()
    if not session:
        return
    actions = {
        "1": ("Add employee", lambda: add_employee_menu(session["username"])),
        "2": ("Search employee", lambda: search_menu(session["username"])),
        "3": ("List employees", lambda: list_menu(session["username"])),
        "4": ("Update employee", lambda: update_menu(session["username"])),
        "5": ("Delete employee", lambda: delete_menu(session["username"])),
        "6": ("Calculate salary / simulated credit", lambda: payroll_menu(session["username"])),
        "7": ("View payment history", lambda: history_menu(session["username"])),
        "8": ("View security audit log", lambda: audit_menu(session["username"])),
    }
    while True:
        if not check_session(session):
            return
        print("\n===== SECURE EMPLOYEE PAYROLL SYSTEM =====")
        for key, (label, _) in actions.items():
            print(f"{key}. {label}")
        print("0. Log out")
        choice = input("Choose: ").strip()
        if choice == "0":
            log_event(session["username"], "LOGOUT", "Administrator signed out")
            break
        if choice in actions:
            try:
                actions[choice][1]()
            except sqlite3.IntegrityError:
                print("Database rejected the operation because of a constraint.")
            except (ValueError, KeyError) as error:
                print("Operation failed:", error)
        else:
            print("Choose a valid menu option.")


if __name__ == "__main__":
    main()
