import flask, apsw, sys, os, secrets, json
from datetime import date
from http import HTTPStatus
from typing import Any
import hashlib
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    request,
    send_from_directory,
    make_response,
    render_template,
    session,
    url_for,
)
from urllib.parse import urljoin, urlparse
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64decode
from box import Box
from .login_form import LoginForm
from .profile_form import ProfileForm
from functools import wraps
db = None

################################
# Set up app
APP_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(APP_PATH, "templates/"),
    static_folder=os.path.join(APP_PATH, "static/"),
)
# You can also load app configuration from a Python file – this could
# be a convenient way of loading secret tokens and other configuration data
# that shouldn't be pushed to Git.
#    app.config.from_pyfile(os.path.join(APP_PATH, 'secrets'))

# The secret key enables storing encrypted session data in a cookie (TODO: make a secure random key for this! and don't store it in Git!)
app.config["SECRET_KEY"] = "mY s3kritz"
app.config["TEMPLATES_AUTO_RELOAD"] = True
#app.config["GITLAB_BASE_URL"] = 'https://git.app.uib.no/'
#app.config["GITLAB_CLIENT_ID"] = ''
#app.config["GITLAB_CLIENT_SECRET"] = ''
# Pick appropriate values for these
#app.config['SESSION_COOKIE_NAME'] = 
#app.config['SESSION_COOKIE_SAMESITE'] = 
#app.config['SESSION_COOKIE_SECURE'] = 

# Add a login manager to the app
import flask_login
from flask_login import current_user, login_required, login_user

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

################################

def debug(*args, **kwargs):
    if request and '_user_id' in session:
        print(f"[user={session.get('_user_id')}]  ", end='', file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)

def prefers_json():
    return request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json'

################################
# Class to store user info
# UserMixin provides us with an `id` field and the necessary methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`).
# Box makes it behave like a dict, but also allows accessing data with `user.key`.
class User(flask_login.UserMixin, Box):
    def __init__(self, user_data):
        super().__init__(user_data)

    def save(self):
        """Save this user object to the database"""
        info = json.dumps(
            {k: self[k] for k in self if k not in ["username", "hash", "salt", "id"]}
        )

        if "id" in self:
            sql_execute(
                "UPDATE users SET username=?, hash=?, salt=?, info=? WHERE id=?",
                (self.username, self.hash, self.salt, info, self.id) # Safe from SQL injections
            )
        else:
            sql_execute(
                "INSERT INTO users (username, hash, salt, info) VALUES (?, ?, ?, ?)",
                (self.username, self.hash, self.salt, info) # Safe from SQL injections
            ) 
            self.id = db.last_insert_rowid()

    def add_token(self, name=""):
        """Add a new access token for a user"""
        token = secrets.token_urlsafe(32)
        sql_execute(
            "INSERT INTO tokens (user_id, token, name) VALUES (?, ?, ?)",
            (self.id, token, name) # Safe from SQL injections
        )

    def delete_token(self, token):
        """Delete an access token"""
        sql_execute(
            "DELETE FROM tokens WHERE user_id = ? AND token = ?",
            (self.id, token) # Safe from SQL injections
        )

    def get_tokens(self):
        """Retrieve all access tokens belonging to a user"""
        return sql_execute(
            "SELECT token, name FROM tokens WHERE user_id = ?",
            (self.id) # Safe from SQL injections
        ).fetchall()

    @staticmethod
    def get_token_user(token):
        """Retrieve the user who owns a particular access token"""
        user_id = sql_execute(
            "SELECT user_id FROM tokens WHERE token = ?", 
            (token,) # Safe from SQL injections
        ).get
        if user_id != None:
            return User.get_user(user_id)

    @staticmethod
    def get_user(userid):
        if type(userid) == int or userid.isnumeric():
            sql = "SELECT id, username, hash, salt, info FROM users WHERE id = ?"
            arg = (userid,) # Safe from SQL injections
        else:
            sql = "SELECT id, username, hash, salt, info FROM users WHERE username = ?"
            arg = (userid,) # Safe from SQL injections
        row = sql_execute(sql, arg).fetchone()
        if row:
            user = User(json.loads(row[4]))
            user.update({"id": row[0], "username": row[1], "hash": row[2], "salt": row[3]}) # Removed update password row2
            return user


# This method is called whenever the login manager needs to get
# the User object for a given user id – for example, when it finds
# the id of a logged in user in the session data (session['_user_id'])
@login_manager.user_loader
def user_loader(user_id):
    return User.get_user(user_id)


# This method is called to get a User object based on a request,
# for example, if using an api key or authentication token rather
# than getting the user name the standard way (from the session cookie)
@login_manager.request_loader
def request_loader(request):
    # Even though this HTTP header is primarily used for *authentication*
    # rather than *authorization*, it's still called "Authorization".
    auth = request.headers.get("Authorization")

    # If there is not Authorization header, do nothing, and the login
    # manager will deal with it (i.e., by redirecting to a login page)
    if not auth:
        return

    (auth_scheme, auth_params) = auth.split(maxsplit=1)
    auth_scheme = auth_scheme.casefold()
    if auth_scheme == "basic":  # Basic auth has username:password in base64
        # TODO: it's probably a bad idea to implement Basic authentication anyway
        (uname, passwd) = (
            b64decode(auth_params.encode(errors="ignore"))
            .decode(errors="ignore")
            .split(":", maxsplit=1)
        )
        debug(f"Basic auth: {uname}:{passwd}")
        u = User.get_user(uname)
        passwdHashed = hashPassword(passwd, u.salt)
        if u and u.hash == passwdHashed:
            return u
    elif auth_scheme == "bearer":  # Bearer auth contains an access token;
        # an 'access token' is a unique string that both identifies
        # and authenticates a user, so no username is provided (unless
        # you encode it in the token – see JWT (JSON Web Token), which
        # encodes credentials and (possibly) authorization info)
        debug(f"Bearer auth: {auth_params}")
        # TODO
    # For other authentication schemes, see
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

    # If we failed to find a valid Authorized header or valid credentials, fail
    # with "401 Unauthorized" and a list of valid authentication schemes
    # (The presence of the Authorized header probably means we're talking to
    # a program and not a user in a browser, so we should send a proper
    # error message rather than redirect to the login page.)
    # (If an authenticated user doesn't have authorization to view a page,
    # Flask will send a "403 Forbidden" response, so think of
    # "Unauthorized" as "Unauthenticated" and "Forbidden" as "Unauthorized")
    abort(
        HTTPStatus.UNAUTHORIZED,
        www_authenticate=WWWAuthenticate("Basic realm=headbook, Bearer"),
    )

################################
# ROUTES – these get called to handle requests
#
#    Before we get this far, Flask has set up a session store with a session cookie, and Flask-Login
#    has dealt with authentication stuff (for routes marked `@login_required`)
#
#    Request data is available as global context variables:
#      * request – current request object
#      * session – current session (stores arbitrary session data in a dict-like object)
#      * g – can store whatever data you like while processing the current request
#      * current_user – a User object with the currently logged in user (if any)

@app.get("/")
@app.get("/index.html")
@login_required
def index_html():
    """Render the home page"""

    return render_template("home.html")



@app.get("/<filename>.<ext>")  # by default, path parameters (filename, ext) match any string not including a '/'
@login_required # Prevents users that are not logged in to access source files (security fix)
#@require_admin_access
def serve_static(filename, ext):
    """Serve files from the static/ subdirectory"""

    # browsers can be really picky about file types, so it's important 
    # to set this correctly, particularly for JS and CSS
    file_types = {
        "js": "application/javascript",
        "ico": "image/vnd.microsoft.icon",
        "png": "image/png",
        "html": "text/html",
        "css": "text/css",
    }

    if ext in file_types:
        return send_from_directory(
            app.static_folder, f"{filename}.{ext}", mimetype=file_types[ext]
        )
        #return redirect('/')
    else:
        abort(404)


@app.route("/login/", methods=["GET", "POST"])
def login():
    """Render (GET) or process (POST) login form"""

    debug('/login/ – session:', session, request.host_url)
    form = LoginForm()

    if not form.next.data:
        form.next.data = flask.request.args.get("next") # set 'next' field from URL parameters

    if form.is_submitted():
        debug(
            f'Received form:\n    {form.data}\n{"INVALID" if not form.validate() else "valid"} {form.errors}'
        )
        if form.validate():
            username = form.username.data
            password = form.password.data
            user = user_loader(username)

            calculatedHash = hashPassword(password, user.salt)
            if user.hash == calculatedHash:
                # automatically sets logged in session cookie
                login_user(user)

                flask.flash(f"User {user.username} Logged in successfully.")

                return safe_redirect_next()

    return render_template("login.html", form=form)

@app.get('/logout/')
def logout_gitlab():
    print('logout', session, session.get('access_token'))
    flask_login.logout_user()
    return redirect('/')

@app.route("/profile/", methods=["GET", "POST", "PUT"])
@login_required
def my_profile():
    """Display or edit user's profile info"""
    debug("/profile/ – current user:", current_user, request.host_url)

    form = ProfileForm()
    if form.is_submitted():
        debug(
            f'Received form:\n    {form.data}\n    {f"INVALID: {form.errors}" if not form.validate() else "ok"}'
        )
        if form.validate():
            if form.password.data: # change password if user set it
                current_user.salt = hashlib.sha256(os.urandom(16)).digest()
                current_user.hash = hashPassword(form.password.data, current_user.salt)
                
            if form.birthdate.data: # change birthday if set
                current_user.birthdate = form.birthdate.data.isoformat()
            # TODO: do we need additional validation for these?
            current_user.color = form.color.data
            current_user.picture_url = form.picture_url.data
            current_user.about = form.about.data
            current_user.save()
        else:
            pass  # The profile.html template will display any errors in form.errors
    else: # fill in the form with the user's info
        form.username.data = current_user.username
        form.password.data = ""
        form.password_again.data = ""
        # only set this if we have a valid date
        form.birthdate.data = current_user.get("birthdate") and date.fromisoformat(
            current_user.get("birthdate")
        )
        form.color.data = current_user.get("color", "")
        form.picture_url.data = current_user.get("picture_url", "")
        form.about.data = current_user.get("about", "")

    return render_template("profile.html", form=form, user=current_user)


@app.get("/users/")
@login_required
def get_users():
    rows = sql_execute("SELECT id, username FROM users;").fetchall()

    result = []
    for row in rows:
        user = User({"id": row[0], "username": row[1]})
        result.append(user)

    if prefers_json():
        return jsonify(result)
    else:
        return render_template("users.html", users=result)

def access_control(current_user, target_user):
    if (current_user.id == target_user.id):
        return True
    else:
        return False

@app.get("/users/<userid>")
@login_required
def get_user(userid):
    if userid == 'me':
        u = current_user
    elif (userid == current_user.id):
        u = User.get_user(userid)
    else:
        u = User.get_user(userid)

    if u:
        del u["hash"] # hide hash
        del u["salt"] #hide salt

        can_access = access_control(current_user, u)

        if can_access:
            if prefers_json():
                return jsonify(u)
            else:
                return render_template("users.html", users=[u])
        else:
            if prefers_json():
                return jsonify({"username": u.username})
            else:
                return render_template("users.html", users=[{"username": u.username}])
    else:
        abort(404)




@app.before_request
def before_request():
    # can be used to allow particular inline scripts with Content-Security-Policy
    g.csp_nonce = secrets.token_urlsafe(32)

# Can be used to set HTTP headers on the responses
@app.after_request
def after_request(response):
    # Content security policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self';" # Set default source for content like scripts
        f"script-src 'self' 'nonce-{g.csp_nonce}';" # Specifies valid sources for scripts
        "img-src 'self' https://git.app.uib.no/uploads/-/system/user/avatar/788/avatar.png;" " " # Specify valid sources for loading images
        "style-src 'self' 'unsafe-hashes' 'sha256-rwjCqLpub2wsnYFBRebsVvC2PLXgjWUbLWZLPHwcOUI=' 'sha256-yBddcDTnDhyH5px4uw3w4NH3K5FXc+ju2ULWjBYi16w=' 'sha256-NHlAhxnE0VhNcpmi3Ez8Q6jbTjUJLvbLaD/bX4mqqRM=' 'sha256-3J17DDRTCF5QGTGcrhgesfip4NmdFIUM0Lv0lnJV+BY=' 'sha256-/tcM+omKvf/6yAp3ohf46tSx4vQZHC6AL81z9FFxOSs=' 'sha256-MwcSxQa4PkeqGLo063IT+QMAw2qfpEwCg0NMFKdnQZU=' 'sha256-5qKNKRlCeAGixar7r7BiNcLTr/q8a9uXAQKpgKRiWRg=' 'sha256-7GIUSLZLILLPuWL1Wvn5n8B3KfoYy+xp5PPC5zdRY7E=';"
        "font-src 'self' https://fonts.gstatic.com/ https://fonts.googleapis.com/;"
        "font-src 'self' https://fonts.gstatic.com/ https://fonts.googleapis.com/;" # Specifies valid sources for fonts
        "object-src 'none';" # Specifies valid sources for embedded objects.
        "frame-ancestors 'none';" # Specifies which ancestors may embed in the page in a frame
        "form-action 'self';" # Specifies valid sources for form submissions
    )
    response.headers["X-Frame-Options"] = "SAMEORIGIN" # Prevents the page from being embedded in frames
    response.headers["X-Content-Type-Options"] = "nosniff" # Advises browser to not interpret files as a different MIME typenthan what is specified by the serveer
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains" # Enforce HTTPS for the duration set
    return response


def get_safe_redirect_url():
    # see discussion at 
    # https://stackoverflow.com/questions/60532973/how-do-i-get-a-is-safe-url-function-to-use-with-flask-and-how-does-it-work/61446498#61446498
    next = request.values.get('next')
    if next:
        url = urlparse(next)
        if not url.scheme and not url.netloc: # ignore if absolute url
            return url.path   # use only the path
    return None

def safe_redirect_next():
    next = get_safe_redirect_url()
    return redirect(next or '/')

# Safe redirect
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get('next'), request.args.get('next'):
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    target = request.form['next'] if request.form and 'next' in request.form else request.args.get('next')
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)




# For full RFC2324 compatibilty

@app.get("/coffee/")
def nocoffee():
    abort(418)


@app.route("/coffee/", methods=["POST", "PUT"])
def gotcoffee():
    return "Thanks!"


################################
# For database access

def get_cursor():
    if "cursor" not in g:
        g.cursor = db.cursor()

    return g.cursor


@app.teardown_appcontext
def teardown_db(exception):
    cursor = g.pop("cursor", None)

    if cursor is not None:
        cursor.close()


def sql_execute(stmt, *args, **kwargs):
    debug(stmt, args or "", kwargs or "")
    return get_cursor().execute(stmt, *args, **kwargs)


def sql_init():
    global db
    db = apsw.Connection("./users.db")
    if db.pragma("user_version") == 0:
        sql_execute(
            """CREATE TABLE IF NOT EXISTS users (
            id integer PRIMARY KEY, 
            username TEXT NOT NULL UNIQUE,
            hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            info JSON NOT NULL);"""
        ) # Added hash and salt to database and removed password, we now store hash and salt which is safer than stroing the password in the database
        sql_execute(
            """CREATE TABLE IF NOT EXISTS tokens (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            name TEXT
            );"""
        )
        sql_execute(
            """CREATE TABLE IF NOT EXISTS buddies (
            user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (user1_id, user2_id)
            );"""
        )
        aliceSalt = hashlib.sha256(os.urandom(16)).digest()
        aliceHash = hashPassword("password123", aliceSalt)
        alice = User(
            {
                "username": "alice",
                "hash": aliceHash,
                "salt": aliceSalt,
                "color": "green",
                "picture_url": "https://git.app.uib.no/uploads/-/system/user/avatar/788/avatar.png",
            }
        )
        alice.save()
        alice.add_token("example")
        bobSalt = hashlib.sha256(os.urandom(16)).digest()
        bobHash = hashPassword("bananas", bobSalt)
        bob = User({"username": "bob", "hash": bobHash, "salt": bobSalt, "color": "red"})
        bob.save()
        bob.add_token("test")
        sql_execute(
            "INSERT INTO buddies (user1_id, user2_id) VALUES (?, ?), (?, ?)",
            (alice.id, bob.id, bob.id, alice.id)
        )
        sql_execute("PRAGMA user_version = 1;")

# Function to hash the password
def hashPassword(password, salt):
    encodePass = password.encode("utf-8")
    return hashlib.scrypt(encodePass, salt=salt, n=2**14, r=8, p=1, dklen=64)


with app.app_context():
    sql_init()


