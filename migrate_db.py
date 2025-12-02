import sqlite3
import psycopg2
import os

# SQLite DB path
SQLITE_DB = 'users.db'

# Neon connection string
NEON_DSN = 'postgresql://neondb_owner:npg_aG0AXHZwe1Fb@ep-little-hill-adfj9zrj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'

def get_sqlite_conn():
    return sqlite3.connect(SQLITE_DB)

def get_neon_conn():
    return psycopg2.connect(NEON_DSN)

def create_tables(cursor):
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

def migrate_data():
    if not os.path.exists(SQLITE_DB):
        print(f"SQLite database {SQLITE_DB} not found.")
        return

    sqlite_conn = get_sqlite_conn()
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cursor = sqlite_conn.cursor()
    
    try:
        neon_conn = get_neon_conn()
        neon_cursor = neon_conn.cursor()
    except Exception as e:
        print(f"Failed to connect to Neon DB: {e}")
        return
    
    print("Creating tables in Neon...")
    try:
        create_tables(neon_cursor)
        neon_conn.commit()
    except Exception as e:
        print(f"Error creating tables: {e}")
        neon_conn.rollback()
        return
    
    # Fix for missing chamber_hour_id=1
    # Check if chamber_hour 1 exists in Neon
    try:
        neon_cursor.execute("SELECT 1 FROM chamber_hours WHERE id = 1")
        if not neon_cursor.fetchone():
            print("Inserting dummy chamber hour 1 to satisfy FK...")
            # We need a valid professor_id. Let's use 7 as seen in the appointment, or 1 if 7 doesn't exist.
            # But we should check if user 7 exists in Neon first.
            neon_cursor.execute("SELECT 1 FROM users WHERE id = 7")
            if neon_cursor.fetchone():
                prof_id = 7
            else:
                # Fallback to first user
                neon_cursor.execute("SELECT id FROM users LIMIT 1")
                res = neon_cursor.fetchone()
                if res:
                    prof_id = res[0]
                else:
                    print("No users found! Cannot create dummy chamber hour.")
                    return

            # Insert dummy chamber hour
            # (id, professor_id, day_of_week, start_time, end_time, room_number, is_available)
            neon_cursor.execute("""
                INSERT INTO chamber_hours (id, professor_id, day_of_week, start_time, end_time, room_number, is_available)
                VALUES (1, %s, 'Dummy', '00:00', '00:00', 'N/A', 0)
            """, (prof_id,))
            neon_conn.commit()
    except Exception as e:
        print(f"Error checking/inserting dummy chamber hour: {e}")
        neon_conn.rollback()

    tables = [
        'users', 'chamber_hours', 'appointments', 'password_resets', 
        'feedbacks', 'bookings', 'study_materials', 'announcements', 'announcement_reads'
    ]
    
    for table in tables:
        print(f"Migrating table: {table}")
        
        # Check if table exists in SQLite
        try:
            sqlite_cursor.execute(f"SELECT * FROM {table}")
            rows = sqlite_cursor.fetchall()
        except sqlite3.OperationalError:
            print(f"Table {table} not found in SQLite, skipping.")
            continue
            
        if not rows:
            print(f"Table {table} is empty.")
            continue
            
        # Get column names
        col_names = [description[0] for description in sqlite_cursor.description]
        cols_str = ', '.join(col_names)
        placeholders = ', '.join(['%s'] * len(col_names))
        
        query = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT (id) DO NOTHING"
        
        for row in rows:
            # Convert row to tuple
            values = tuple(row)
            try:
                neon_cursor.execute(query, values)
            except Exception as e:
                print(f"Error inserting row into {table}: {e}")
                neon_conn.rollback()
                continue
        neon_conn.commit()
        
        # Reset sequence
        try:
            neon_cursor.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), coalesce(max(id), 0) + 1, false) FROM {table};")
            neon_conn.commit()
        except Exception as e:
            # Some tables might not have a sequence or id might not be serial if we messed up, but here they are all SERIAL
            print(f"Error resetting sequence for {table}: {e}")
            neon_conn.rollback()

    sqlite_conn.close()
    neon_conn.close()
    print("Migration complete.")

if __name__ == '__main__':
    migrate_data()
