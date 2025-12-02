import sqlite3, urllib.parse, urllib.request

con = sqlite3.connect('users.db')
row = con.execute("SELECT email FROM users LIMIT 1").fetchone()
if not row:
    print('No users found in users.db')
else:
    email = row[0]
    print('Using email:', email)
    data = urllib.parse.urlencode({'email': email}).encode()
    req = urllib.request.Request('http://127.0.0.1:5000/forgot-password', data=data, method='POST')
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        print('POST status:', resp.getcode())
        body = resp.read().decode(errors='ignore')
        print('Response body (truncated to 200 chars):')
        print(body[:200])
    except Exception as e:
        print('Request error:', e)
