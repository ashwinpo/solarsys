"""SolarSys UI views."""
from flask import Flask, render_template, url_for, request, session, redirect, flash, g, abort
from flask_cors import CORS
import json
import requests
import os
import sqlite3
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = "ultivillage"
CORS(app)

DATABASE= os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
    'sql', 'planets.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        print(DATABASE)
        db = g._database = sqlite3.connect('sql/planets.db')
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/', methods=['GET'])
def show_index():
    """Display / route."""
    if 'username' not in session:
        return redirect(url_for('login'))
    context = {}
    return render_template("index.html", **context, iframe= "opening_frame")


@app.route('/sys', methods=['GET'])
def show_sys():
    """Display /sys route."""
    if 'username' not in session:
        return redirect(url_for('login'))

    context = {}
    return render_template("index.html", **context, iframe="sys_frame")

@app.route('/collider', methods=['GET'])
def show_collider():
    """Display /collider route."""
    if 'username' not in session:
        return redirect(url_for('login'))

    context = {}
    return render_template("index.html", **context, iframe="collider_frame")

######## iframes #############

@app.route('/opening_frame', methods=['GET'])
def show_opening_frame():
    """Display / route."""

    context = {}
    return render_template("opening.html", **context)

@app.route('/sys_frame', methods=['GET'])
def show_sys_frame():
    """Display / route."""

    context = {}
    return render_template("sys.html", **context)

@app.route('/collider_frame', methods=['GET'])
def show_collider_frame():
    """Display / route."""

    context = {}
    return render_template("collider.html", **context)


############ Login #############

# @app.before_request
# def before_request():
#     if 'username' in session:
#         user = [x for x in users if x.id == session['username']][0]
#         g.user = user

# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if 'username' in session:
            session.pop('username')
        username = request.form['username']
        password = request.form['psw']


        if user and user.password == password:
            session['username'] = user.id
            #flash('You were successfully logged in')
            return redirect(url_for('show_index'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        if 'username' in session:
            session.pop('username')
        username = request.form['username']
        password = request.form['psw']

        user_exist = get_db().cursor().execute('''
        SELECT EXISTS(
        SELECT *
        FROM users U
        WHERE U.username = ?
        ) AS user_exist
        ''', (username,)).fetchall()
        print(user_exist)
        if user_exist[0][0]:
            return abort(409)

        if not password:
            return abort(400)

        print("here")
        # Password shit
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])

        id = uuid.uuid4().hex
        get_db().cursor().execute('''
        INSERT INTO users
        VALUES (?,?,?)
        ''', (username,id,
              password_db_string))
        # -------------------------------------#
        session['username'] = username
        return redirect("/")

    context = {}
    return render_template('signup.html', **context)
