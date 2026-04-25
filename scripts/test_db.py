import sqlite3
conn = sqlite3.connect(r'c:\Users\rr2k1\OneDrive\Desktop\Sentinel\Shared\logs\sentinel.db')
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', [t[0] for t in tables])
for t in tables:
    count = conn.execute(f'SELECT COUNT(*) FROM {t[0]}').fetchone()[0]
    print(f'  {t[0]}: {count} rows')
print('PRAGMA journal_mode:', conn.execute('PRAGMA journal_mode').fetchone()[0])
conn.close()
print('DB Schema OK')
