# Secure Employee Payroll System

A beginner-friendly Python + SQLite command-line project that demonstrates basic security practices.

## Features
- Administrator login created on first run
- Passwords are salted and hashed using PBKDF2-HMAC-SHA256 (not stored as plain text)
- Basic temporary lockout after repeated failed logins (per application run)
- Session inactivity timeout
- Parameterized SQL queries for values
- Input length checks, numeric checks, date/month format checks
- Duplicate employee and monthly payment protections
- Masked bank-account digits in displayed employee details
- Audit log for selected administrative actions
- Employee records, payroll calculations, simulated payment history

## Run
Requires Python 3.9+; no third-party packages needed.

```bash
python app.py
```
Windows alternative: `py app.py`. macOS/Linux: `python3 app.py`.

On first run, create an administrator password with 12+ characters, including uppercase, lowercase, number and symbol. Then log in with username `admin`.

## Demo salary rule
The example assumes 30 payable days:
- Basic pay = monthly basic salary × days worked / 30
- Gross pay = basic pay + allowances
- Net salary = gross pay − deductions

## Security limitations
This is a learning demonstration, not production-ready payroll software. The login lockout is memory-only and resets when the program restarts. SQLite file access is controlled by your operating-system account. It has no encrypted database, multi-user roles, remote network controls, secure deployment, professional security audit, or real bank integration. Keep `payroll.db` private and never commit it to GitHub. Do not enter real employee or bank data. For real use, seek a security review and follow applicable privacy, payroll and employment laws.

## GitHub safety
The `.gitignore` excludes `payroll.db`, virtual environments, Python cache files and `.env`. Check `git status` before pushing. If real secrets or personal data are accidentally committed, deleting the file in a later commit does not remove it from Git history; rotate secrets and clean the history.
