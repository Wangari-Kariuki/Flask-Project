import functools #provides highr order functions that act on or return other functions
import sqlite3
from flask import (
    Blueprint, flash,g, redirect, render_template,request, session, url_for
)
from werkzeug.security import check_password_hash,generate_password_hash
 #provides request and response objects abstracting raw web server gate interface environment 
 # making it easier t ineractieith https headers 

from flaskr.db import get_db
bp = Blueprint('auth', __name__, url_prefix='/auth') #we create a blueprint called auth, defined in name 

@bp.route('/register', methods= ('GET', 'POST')) #associates the url /register with the register function
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form ['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username required!'
        elif not password:
            error = 'Password is required'
        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?,?)",
                     (username, generate_password_hash(password))
                )
                db.commit() #saves changes made to the database
            except sqlite3.IntegrityError:
                error = f"User{username} is already registered. "
            else:
                return redirect(url_for("auth.login")) #after storing th use they are redirected to the login page
            
        flash(error) #shows if the user validation fails
    return render_template('auth/register.html')

#LOGIN VIEW
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        users = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone() #returns one row from the query. if the query return no results it returns None

        if users is None:
            error = 'Incorrect username.'
        elif not check_password_hash(users['password'], password):
            error = 'Incorrect password'
        
        if error is None:
            session.clear() #session is a dict tha stores data across requests, when the validation sa
            #succeeds the user's id is stored in a new session
            session['user_id'] = users['id']
            return redirect(url_for('base'))
        
        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request #registers a function tht runs before the view function, no matter what URL is requested
def load_logged_in_users(): #checks if user idis stored in the session and gets that the user;s data frm the database is storing it on g.users which lasts for the lenghts of the request
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()

#LOGOUT VIEW
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index')) #in this view we remove the user id from the session

#the decorator wraps the original view function it's applied to and makes a new function
#that checks if the user is loaded and redirects to the login page otherwise
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view