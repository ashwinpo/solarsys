from flask import Flask, redirect, url_for, request, jsonify, Response, g, session, abort
from flask_cors import CORS
import json
import sqlite3
import uuid
import shutil
import hashlib

app = Flask(__name__)
CORS(app)

DATABASE = "planets.db"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()



@app.route('/api',methods = ['POST', 'GET'])
@app.route('/',methods = ['POST', 'GET'])
def new_config():
    if request.method == 'POST':
        content = request.json
        username = content["username"]
        del content["username"]
        # sql = ''' SELECT ID FROM planets '''
        # users = get_db().cursor().execute(sql).fetchall()
        # users = [user[0] for user in users]
        # if user in users:
        #     return jsonify({'No': 'Overwrite'})
        sql = ''' INSERT OR REPLACE INTO planets(ID, json)
              VALUES(?,?) '''
        get_db().cursor().execute(sql,(username, json.dumps(content)))
        get_db().commit()
        # with open('data.txt', 'w') as outfile:
        #   json.dump(content, outfile)
        response = jsonify({'Mission': 'Accomplished'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response #Response(status=201, mimetype='application/json')


@app.route('/sketch',methods = ['POST'])
def get_config():
    if request.method == 'POST':
        content = request.json
        username = content["username"]
        sql = ''' SELECT json FROM planets
                Where ID= ? '''
        content = get_db().cursor().execute(sql, (username,)).fetchone()
        response = jsonify(json.loads(content[0]))
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

@app.route('/login',methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        return ""


@app.route('/signup', methods = ['POST'])
def signup():
    if request.method == 'POST':

        user_exist = get_db().cursor().execute('''
        SELECT EXISTS(
        SELECT *
        FROM users U
        WHERE U.username = ?
        ) AS user_exist
        ''', (request.form['username'],)).fetchall()
        if user_exist[0]['user_exist']:
            return flask.abort(409)

        if not flask.request.form['password']:
            return flask.abort(400)

        hash_filename_basename = ""
        if flask.request.files["file"].filename != '':
            # Save POST request's file object to a temp file
            dummy, temp_filename = tempfile.mkstemp()
            file = flask.request.files["file"]
            file.save(temp_filename)

            # Compute filename
            hash_txt = sha256sum(temp_filename)
            dummy, suffix = os.path.splitext(file.filename)
            hash_filename_basename = hash_txt + suffix
            hash_filename = os.path.join(insta485.app.config["UPLOAD_FOLDER"],
                                         hash_filename_basename)

            # Move temp file to permanent location
            shutil.move(temp_filename, hash_filename)
            insta485.app.logger.debug("Saved %s", hash_filename_basename)

        # Password shit
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + flask.request.form['password']
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])
        # ---- Send all this shit to db plz ----#
        # fullname = flask.request.form['fullname']
        # username = flask.request.form['username']
        # email = flask.request.form['email']
        # passw = password_db_string
        # filename = hash_filename_basename
        get_db().cursor().execute('''
        INSERT INTO users
        VALUES (?,?,?,?,?, CURRENT_TIMESTAMP)
        ''', (flask.request.form['username'], flask.request.form['fullname'],
              flask.request.form['email'], hash_filename_basename,
              password_db_string))
        # -------------------------------------#
        flask.session['username'] = flask.request.form['username']
        return flask.redirect("/")




if __name__ == '__main__':
    app.run(debug = True, port=8001)
