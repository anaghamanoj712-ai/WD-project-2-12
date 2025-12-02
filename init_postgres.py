import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
load_dotenv('.env.local')

# Neon connection string
NEON_DSN = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_aG0AXHZwe1Fb@ep-little-hill-adfj9zrj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')

def get_neon_conn():
    return psycopg2.connect(NEON_DSN)

def create_tables(cursor):
    print("Creating tables...")
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            department TEXT,
            designation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Chamber hours table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chamber_hours (
            id SERIAL PRIMARY KEY,
            professor_id INTEGER NOT NULL,
            day_of_week TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            room_number TEXT,
            is_available INTEGER DEFAULT 1,
            FOREIGN KEY (professor_id) REFERENCES users(id)
        )
    ''')
    
    # Appointments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL,
            professor_id INTEGER NOT NULL,
            chamber_hour_id INTEGER NOT NULL,
            appointment_date DATE NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (professor_id) REFERENCES users(id),
            FOREIGN KEY (chamber_hour_id) REFERENCES chamber_hours(id)
        )
    ''')
    
    # Password resets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Feedbacks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedbacks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            course TEXT,
            q1 INTEGER,
            q2 INTEGER,
            q3 INTEGER,
            q4 INTEGER,
            q5 INTEGER,
            remarks TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Venue bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            venue_type TEXT,
            block TEXT,
            room_number TEXT,
            purpose TEXT,
            date TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Study materials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS study_materials (
            id SERIAL PRIMARY KEY,
            course_code TEXT NOT NULL,
            course_name TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            file_name TEXT,
            file_size INTEGER,
            uploaded_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    ''')

    # Announcements
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS announcements (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Announcement reads
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS announcement_reads (
            id SERIAL PRIMARY KEY,
            announcement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(announcement_id, user_id)
        )
    ''')

    # Leaves table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leaves (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            leave_type TEXT,
            start_date TEXT,
            end_date TEXT,
            contact TEXT,
            reason TEXT,
            status TEXT,
            approver_notes TEXT,
            created_at TEXT
        )
    ''')
    print("Tables created.")

def init_db():
    try:
        print(f"Connecting to {NEON_DSN}...")
        conn = get_neon_conn()
        print("Connected.")
        cursor = conn.cursor()
        create_tables(cursor)
        conn.commit()
        conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")

if __name__ == '__main__':
    init_db()
