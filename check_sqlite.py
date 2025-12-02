import sqlite3

def check_counts():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    tables = ['users', 'chamber_hours', 'appointments']
    for table in tables:
        try:
            cursor.execute(f"SELECT count(*) FROM {table}")
            print(f"{table}: {cursor.fetchone()[0]}")
            if table == 'chamber_hours':
                cursor.execute("SELECT * FROM chamber_hours")
                print("Chamber hours data:", cursor.fetchall())
        except Exception as e:
            print(f"{table}: error {e}")
            
    conn.close()

if __name__ == '__main__':
    check_counts()
