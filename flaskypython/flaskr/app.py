import os
from flask import Flask, render_template

#definign the app factory
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True, template_folder = 'templates', static_folder='static') #here we created the flask instance
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'APP.sqlite')
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    #ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    #initializing the database
    from . import db
    db.init_app(app)

    #importing and registering the auth blueprint
    from . import auth
    app.register_blueprint(auth.bp)

    from . import blog
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')

    @app.route('/app/')
    def base():
        return render_template('base.html')
    return app

