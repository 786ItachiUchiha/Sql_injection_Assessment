import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Drop table if exists
cursor.execute("DROP TABLE IF EXISTS users")

# Create table
cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

# Seed data (15+ entries)
users = [
    ("admin", "admin123"),
    ("administrator", "root"),
    ("root", "toor"),
    ("user", "user123"),
    ("guest", "guest"),
    ("test", "test123"),
    ("demo", "demo123"),
    ("john", "johnpass"),
    ("jane", "jane123"),
    ("alice", "alicepwd"),
    ("bob", "bobsecure"),
    ("charlie", "charlie123"),
    ("david", "dav!d"),
    ("eve", "evepass"),
    ("mallory", "hackme"),
    ("oscar", "oscar123"),
    ("peggy", "peggy456"),
    ("trent", "trent789"),
    ("victor", "victor321"),
    ("walter", "walterpwd"),

    # Edge cases (useful for SQLi behavior testing)
    ("admin'--", "nopass"),
    ("' OR '1'='1", "injected"),
    ("normal_user", "password"),
]

cursor.executemany(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    users
)

conn.commit()
conn.close()

print(f"Database seeded with {len(users)} users.")
