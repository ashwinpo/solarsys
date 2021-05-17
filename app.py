"""SolarSys UI views."""
from flask import Flask, render_template, url_for, request, session, redirect, flash, g, abort, jsonify
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
    return render_template("index.html", **context, iframe= "opening_frame", log = "Log Out")


@app.route('/sys', methods=['GET'])
def show_sys():
    """Display /sys route."""
    if 'username' not in session:
        return redirect(url_for('login'))

    context = {}
    return render_template("index.html", **context, iframe="sys_frame", log = "Log Out")

@app.route('/collider', methods=['GET'])
def show_collider():
    """Display /collider route."""
    if 'username' not in session:
        return redirect(url_for('login'))

    context = {}
    return render_template("index.html", **context, iframe="collider_frame", log = "Log Out")

######## iframes #############

@app.route('/opening_frame', methods=['GET'])
def show_opening_frame():
    """Display opening frame."""
    if 'username' not in session:
        return redirect(url_for('login'))

    sql = ''' SELECT json FROM planets
            Where username= ? '''
    content = get_db().cursor().execute(sql, (session['username'],)).fetchone()
    if content:
        session["content"] = content[0]
        return redirect('sys_frame')
    context = {}
    return render_template("opening.html", **context)

@app.route('/save', methods=['POST'])
def save():
    """Display sys frame."""
    if 'username' not in session:
        return redirect(url_for('login'))

    content = request.json
    sql = ''' INSERT OR REPLACE INTO planets(username, json)
          VALUES(?,?) '''
    get_db().cursor().execute(sql,(session['username'], json.dumps(content)))
    get_db().commit()
    session["content"] = json.dumps(content)
    context = {}
    return render_template("sys.html", **context)

@app.route('/sys_frame', methods=['GET'])
def show_sys_frame():
    """Display sys frame."""
    if 'username' not in session:
        return redirect(url_for('login'))
    if 'content' not in session:
        sql = ''' SELECT json FROM planets
                Where username= ? '''
        content = get_db().cursor().execute(sql, (session['username'],)).fetchone()

        if not content:
            return redirect('opening_frame')
        else:
            session["content"] = content[0]
    data = json.loads(session["content"])
    with open('static/data.txt', 'w') as outfile:
        json.dump(data, outfile)
    context = {}
    return render_template("sys.html", **context)

@app.route('/get_config', methods=['GET'])
def get_config():
    """Display sys frame."""
    if 'username' not in session:
        return redirect(url_for('login'))
    if 'content' not in session:
        sql = ''' SELECT json FROM planets
                Where username= ? '''
        content = get_db().cursor().execute(sql, (session['username'],)).fetchone()

        if not content:
            return redirect('opening_frame')
        else:
            session["content"] = content[0]
    resp = jsonify(json.loads(session["content"]))
    context = {}
    return resp

@app.route('/collider_frame', methods=['GET'])
def show_collider_frame():
    """Display collider frame."""
    if 'username' not in session:
        return redirect(url_for('login'))
    if 'content' not in session:
        sql = ''' SELECT json FROM planets
                Where username= ? '''
        content = get_db().cursor().execute(sql, (session['username'],)).fetchone()

        if not content:
            return redirect('opening_frame')
        else:
            session["content"] = content[0]

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
    if 'username' in session:
        session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['psw']

        algorithm = 'sha512'
        hash_obj = hashlib.new(algorithm)
        user_exist = get_db().cursor().execute('''
        SELECT EXISTS(
        SELECT *
        FROM users U
        WHERE U.username = ?
        ) AS user_exist
        ''', (username,)).fetchall()
        if user_exist[0][0] == 0:
            return render_template('login.html', error="Invalid credentials. Please try again.")

        db_password = ""
        post = get_db().cursor().execute('''
        SELECT U.password
        FROM users U
        WHERE U.username = ?
        ''', (username,)).fetchone()

        db_password = post[0]
        salt = db_password[7:db_password.find("$", 8)]
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_in = "$".join([algorithm, salt, password_hash])

        if password_in != db_password:
            return render_template('login.html', error="Invalid credentials. Please try again.")

        session['username'] = username
        return redirect('/')

    return render_template('login.html')

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
        if user_exist[0][0]:
            return render_template('signup.html', error="Username is taken.")


        if not password:
            return render_template('signup.html', error="Please enter a password.")

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
        get_db().commit()
        # -------------------------------------#
        session['username'] = username
        return redirect("/")

    context = {}
    return render_template('signup.html', **context)

@app.route('/logout')
def logout():
    """Account logout"""
    session.clear()
    return redirect("/login")
