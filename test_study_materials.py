"""
Test script to verify study materials database queries
"""
import os
import psycopg2
import psycopg2.extras

# Get database URL from environment
database_url = os.environ.get('DATABASE_URL', 'postgresql://neondb_owner:npg_aG0AXHZwe1Fb@ep-little-hill-adfj9zrj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')

if not database_url:
    print("ERROR: DATABASE_URL environment variable is not set")
    exit(1)

print(f"Connecting to database...")

try:
    conn = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.DictCursor)
    cursor = conn.cursor()
    
    print("\n=== Testing study_materials table ===")
    
    # Test 1: Check if table exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'study_materials'
        )
    """)
    table_exists = cursor.fetchone()[0]
    print(f"Table exists: {table_exists}")
    
    if not table_exists:
        print("ERROR: study_materials table does not exist!")
        exit(1)
    
    # Test 2: Get table structure
    print("\n=== Table Structure ===")
    cursor.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'study_materials'
        ORDER BY ordinal_position
    """)
    columns = cursor.fetchall()
    for col in columns:
        print(f"  {col['column_name']}: {col['data_type']}")
    
    # Test 3: Count total materials
    cursor.execute("SELECT COUNT(*) FROM study_materials")
    count = cursor.fetchone()[0]
    print(f"\n=== Total materials in database: {count} ===")
    
    # Test 4: Get all materials with uploader info
    print("\n=== All Study Materials ===")
    cursor.execute("""
        SELECT sm.*, u.full_name as uploader_name 
        FROM study_materials sm 
        LEFT JOIN users u ON sm.uploaded_by = u.id 
        ORDER BY sm.created_at DESC
        LIMIT 10
    """)
    materials = cursor.fetchall()
    
    if not materials:
        print("No materials found in database")
    else:
        for mat in materials:
            print(f"\nID: {mat['id']}")
            print(f"  Course: {mat['course_code']} - {mat['course_name']}")
            print(f"  Title: {mat['title']}")
            print(f"  File Path: {mat['file_path']}")
            print(f"  Uploader: {mat.get('uploader_name', 'N/A')}")
            print(f"  Created: {mat['created_at']}")
    
    # Test 5: Get distinct courses
    print("\n=== Distinct Courses with Materials ===")
    cursor.execute("""
        SELECT DISTINCT course_code, course_name 
        FROM study_materials 
        WHERE course_code IS NOT NULL AND TRIM(course_code) != ''
        ORDER BY course_name
    """)
    courses = cursor.fetchall()
    
    if not courses:
        print("No courses found")
    else:
        for course in courses:
            print(f"  {course['course_code']}: {course['course_name']}")
    
    # Test 6: Test case-insensitive query (like the actual route)
    if courses:
        test_code = courses[0]['course_code']
        print(f"\n=== Testing query for course: {test_code} ===")
        cursor.execute("""
            SELECT sm.*, u.full_name as uploader_name 
            FROM study_materials sm 
            LEFT JOIN users u ON sm.uploaded_by = u.id 
            WHERE UPPER(sm.course_code) = UPPER(%s)
            ORDER BY sm.created_at DESC
        """, (test_code,))
        course_materials = cursor.fetchall()
        print(f"Found {len(course_materials)} material(s) for {test_code}")
        
        for mat in course_materials:
            print(f"\n  Title: {mat['title']}")
            print(f"  Link: {mat['file_path']}")
            print(f"  Description: {mat.get('description', 'N/A')}")
    
    conn.close()
    print("\n=== All tests completed successfully! ===")
    
except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
