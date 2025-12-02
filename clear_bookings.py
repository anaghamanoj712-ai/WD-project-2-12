import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
load_dotenv('.env.local')

db_url = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_aG0AXHZwe1Fb@ep-little-hill-adfj9zrj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')

try:
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    print("Deleting all venue bookings...")
    cur.execute("DELETE FROM bookings")
    conn.commit()
    print("Venue bookings deleted.")
    conn.close()
except Exception as e:
    print(f"Error: {e}")
