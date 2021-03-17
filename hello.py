from flask import Flask, render_template,request, flash, session , redirect , url_for
from datetime import datetime
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,IntegerField,TextAreaField,BooleanField,PasswordField
from wtforms.validators import DataRequired,Email,InputRequired,Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
basedir=os.path.abspath(os.path.dirname(__file__))
app=Flask(__name__)

app.config['SECRET_KEY'] = 'Thisisasecret!'
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///' + os.path.join(basedir,'data1.sqlite')
db= SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# class SignupForm(FlaskForm):
#     email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
#     username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
#     password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

# class LoginForm(FlaskForm):
#     username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
#     password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
#     remember = BooleanField('remember me')

@app.route('/')
@login_required
def index():
    posts = Blog.query.order_by(Blog.date_posted.desc()).all()
    return render_template('index1.html',posts=posts,name=current_user.username)

@app.route('/about')
@login_required
def about():
    return render_template('about1.html',name=current_user.username)

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method=='POST':
        name=request.form['sname']
        eml=request.form['smail']
        passwrd=request.form['spw']
        hashed_password = generate_password_hash(passwrd, method='sha256')
        new_user = User(username=name, email=eml, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
    return render_template('signup.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        umail=request.form['lmail']
        lpass=request.form['lpw']
        user = User.query.filter_by(email=umail).first()
        if user:
            if check_password_hash(user.password, lpass):
                login_user(user)
                return redirect(url_for('index'))

        return '<h1>Invalid username({}) or password({})</h1>'.format(umail,lpass)
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html')

@app.route('/post/<int:post_id>')
def post(post_id):
    post = Blog.query.filter_by(id=post_id).one()
    return render_template('post1.html',post=post,name=current_user.username)

@app.route('/contact')
@login_required
def contact():
    return render_template('contact1.html',name=current_user.username)

@app.route('/add')
@login_required
def add():
    return render_template('add1.html',name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/addblog', methods=['POST'])
def addblog():
    title = request.form['title']
    subtitle = request.form['subtitle']
    author = request.form['author']
    content = request.form['content']

    post = Blog(title=title, subtitle=subtitle, author=author, content=content, date_posted=datetime.now())

    db.session.add(post)
    db.session.commit()

    return redirect(url_for('index'))

