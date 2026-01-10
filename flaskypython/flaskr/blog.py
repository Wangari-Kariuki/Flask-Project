from flask import Flask
from flask import (
    Blueprint, flash,g, redirect, render_template,request, session, url_for
)
from flaskr.auth import login_required
from flaskr.db import get_db

bp = Blueprint('blog', __name__)
@bp.route('/blog', methods=('GET', 'POST'))
def blog():
