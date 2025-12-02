import sqlite3
from werkzeug.security import generate_password_hash

db = 'users.db'
conn = sqlite3.connect(db)
cur = conn.cursor()

email = 'professor@iimidr.ac.in'
password = 'password123'
name = 'Saurabh Kumar'
department = 'Information Systems'
designation = 'Associate Professor'
student_id = 'PROF001'

try:
    h = generate_password_hash(password)
    cur.execute('''INSERT OR REPLACE INTO users (email, password_hash, role, full_name, student_id, department, designation) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                (email, h, 'professor', name, student_id, department, designation))
    conn.commit()
    print(f'✓ Professor account created!')
    print(f'Email: {email}')
    print(f'Password: {password}')
except Exception as e:
    print(f'Error: {e}')
finally:
    conn.close()
