"""
init_db.py — builds worldmonitor.db with mock data.
Run once: python init_db.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "worldmonitor.db")

SCHEMA = """
DROP TABLE IF EXISTS news;
DROP TABLE IF EXISTS cii;
DROP TABLE IF EXISTS finance;
DROP TABLE IF EXISTS users;

CREATE TABLE news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,      -- world / tech / finance / energy
    source TEXT NOT NULL,
    published_at TEXT NOT NULL
);

CREATE TABLE cii (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country TEXT NOT NULL,
    score INTEGER NOT NULL,      -- 0-100, higher = more unstable
    trend TEXT NOT NULL          -- up / down / flat
);

CREATE TABLE finance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticker TEXT NOT NULL,
    price REAL NOT NULL,
    change_pct REAL NOT NULL
);

-- IDOR target: user records with mildly sensitive-looking fields
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    internal_notes TEXT NOT NULL
);
"""

NEWS = [
    ("Border talks stall after third round", "Negotiators from both delegations left without a joint statement.", "world", "Reuters Wire", "2026-09-08 09:12"),
    ("Central bank holds rates amid inflation worries", "The move was widely expected by analysts polled last week.", "finance", "MarketPulse", "2026-09-08 07:40"),
    ("New chip export controls take effect", "The rules target advanced fabrication equipment bound for three countries.", "tech", "TechWire", "2026-09-07 18:05"),
    ("Grid operator warns of winter capacity gap", "Officials say demand could outstrip supply during peak cold spells.", "energy", "EnergyDesk", "2026-09-07 14:22"),
    ("Regional coalition announces joint patrol", "The agreement covers shared maritime routes for the next fiscal year.", "world", "Global Signal", "2026-09-06 11:30"),
    ("Startup raises Series B for satellite imaging", "The funding will go toward expanding its low-orbit constellation.", "tech", "TechWire", "2026-09-06 09:15"),
    ("Oil prices dip on demand forecast revision", "Traders cited a softer outlook from the latest agency report.", "energy", "EnergyDesk", "2026-09-05 16:48"),
    ("Currency slides after surprise policy signal", "Analysts are divided on whether the move was intentional.", "finance", "MarketPulse", "2026-09-05 08:03"),
    ("Cyber unit reports rise in scanning activity", "The advisory notes a spike in reconnaissance traffic against utilities.", "world", "Global Signal", "2026-09-04 19:11"),
    ("Battery recycling plant breaks ground", "The facility is expected to process regional EV battery waste.", "energy", "EnergyDesk", "2026-09-04 10:27"),
]

CII = [
    ("Country Alpha", 72, "up"),
    ("Country Bravo", 41, "flat"),
    ("Country Charlie", 88, "up"),
    ("Country Delta", 23, "down"),
    ("Country Echo", 56, "up"),
    ("Country Foxtrot", 34, "down"),
]

FINANCE = [
    ("IDX-COMP", 6421.30, -0.42),
    ("ENRG-FUT", 78.55, 1.13),
    ("GLD-SPOT", 2384.10, 0.08),
    ("TECH-100", 15230.77, -1.05),
    ("BOND-10Y", 4.32, 0.02),
]

USERS = [
    ("nilanjan_dev", "nilanjan@example.local", "admin", "Full platform access, on-call for CII pipeline."),
    ("priya_analyst", "priya@example.local", "analyst", "Reviews finance radar anomalies weekly."),
    ("rahul_intern", "rahul@example.local", "intern", "Read-only access, onboarding until Q4."),
    ("guest_demo", "guest@example.local", "guest", "Demo account for SIH presentation."),
]

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(SCHEMA)
    cur.executemany("INSERT INTO news (title, content, category, source, published_at) VALUES (?, ?, ?, ?, ?)", NEWS)
    cur.executemany("INSERT INTO cii (country, score, trend) VALUES (?, ?, ?)", CII)
    cur.executemany("INSERT INTO finance (ticker, price, change_pct) VALUES (?, ?, ?)", FINANCE)
    cur.executemany("INSERT INTO users (username, email, role, internal_notes) VALUES (?, ?, ?, ?)", USERS)
    conn.commit()
    conn.close()
    print(f"Database created at {DB_PATH}")

if __name__ == "__main__":
    main()
