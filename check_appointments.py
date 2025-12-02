import sqlite3

def check_appointments():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments")
    print("Appointments:", cursor.fetchall())
    conn.close()

if __name__ == '__main__':
    check_appointments()
