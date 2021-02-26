from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or os.getenv("SQLITE")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

# DATABASE MODELS
class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(50), unique=True, nullable=False)
  password = db.Column(db.String(60), nullable=False)
  movie_list = db.relationship('MovieList', backref='creator', lazy=True)

class MovieList(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  movie1 = db.Column(db.String(100))
  movie2 = db.Column(db.String(100))
  movie3 = db.Column(db.String(100))
  movie4 = db.Column(db.String(100))
  movie5 = db.Column(db.String(100))
  movie6 = db.Column(db.String(100))
  movie7 = db.Column(db.String(100))
  movie8 = db.Column(db.String(100))
  movie9 = db.Column(db.String(100))
  movie10 = db.Column(db.String(100))
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# db.create_all()


# FORMS
class RegistrationForm(FlaskForm):
  name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  submit = SubmitField('Create Account')
  def validate_name(self, name):
    user = User.query.filter_by(name=name.data).first()
    if user:
      raise ValidationError('That name is taken. Please enter a different one.')

class LoginForm(FlaskForm):
  name = StringField('Name', validators=[DataRequired()])
  password = PasswordField('Password', validators=[DataRequired()])
  submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
  name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
  submit = SubmitField('Update Account Name')
  def validate_name(self, name):
    if name.data != current_user.name:
      user = User.query.filter_by(name=name.data).first()
      if user:
        raise ValidationError('That name is taken. Please enter a different one.')

class MovieListForm(FlaskForm):
  movie1 = StringField('1')
  movie2 = StringField('2')
  movie3 = StringField('3')
  movie4 = StringField('4')
  movie5 = StringField('5')
  movie6 = StringField('6')
  movie7 = StringField('7')
  movie8 = StringField('8')
  movie9 = StringField('9')
  movie10 = StringField('10')
  submit = SubmitField('Submit')


# ROUTES
@app.route('/')
def index():
  allMovieLists = MovieList.query.all()
  return render_template('index.html', allMovieLists=allMovieLists)

@app.route('/register', methods=['GET', 'POST'])
def register():
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  form = RegistrationForm()
  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    user = User(name=form.name.data, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    flash('Your account has been created!', 'success')
    return redirect(url_for('add'))
  return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
  if current_user.is_authenticated:
    return redirect(url_for('add'))
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(name=form.name.data).first()
    if user and bcrypt.check_password_hash(user.password, form.password.data):
      login_user(user)
      return redirect(url_for('add'))
    else:
      flash('Login unsuccessful. Please check your name and password.', 'danger')
  return render_template('login.html', form=form)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
  form = UpdateAccountForm()
  if form.validate_on_submit():
    current_user.name = form.name.data
    db.session.commit()
    flash('Your account name has been updated.', 'success')
    return redirect(url_for('account'))
  elif request.method == 'GET':
    form.name.data = current_user.name
  return render_template('account.html', form=form)

@app.route('/logout')
def logout():
  logout_user()
  return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
  if len(current_user.movie_list) == 1:
    thisMovieList = MovieList.query.filter_by(creator=current_user).first()
    return render_template('edit.html', movieList=thisMovieList)
  else:
    form = MovieListForm()
    if form.validate_on_submit():
      movieList = MovieList(movie1=form.movie1.data, movie2=form.movie2.data, movie3=form.movie3.data, movie4=form.movie4.data, movie5=form.movie5.data, movie6=form.movie6.data, movie7=form.movie7.data, movie8=form.movie8.data, movie9=form.movie9.data, movie10=form.movie10.data, creator=current_user)
      db.session.add(movieList)
      db.session.commit()
      flash('Your movie list has been created and added to the overall listing below!', 'success')
      return redirect(url_for('index'))
    return render_template('add.html', form=form, title='Add')

@app.route('/edit/<int:id>')
def edit(id):
  movieList = MovieList.query.get_or_404(id)
  return render_template('edit.html', movieList=movieList)

@app.route('/edit/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update(id):
  movieList = MovieList.query.get_or_404(id)
  if movieList.creator != current_user:
    abort(403)
  form = MovieListForm()
  if form.validate_on_submit():
    movieList.movie1 = form.movie1.data
    movieList.movie2 = form.movie2.data
    movieList.movie3 = form.movie3.data
    movieList.movie4 = form.movie4.data
    movieList.movie5 = form.movie5.data
    movieList.movie6 = form.movie6.data
    movieList.movie7 = form.movie7.data
    movieList.movie8 = form.movie8.data
    movieList.movie9 = form.movie9.data
    movieList.movie10 = form.movie10.data
    db.session.commit()
    flash('Your movie list has been updated.', 'success')
    return redirect(url_for('index'))
  elif request.method == 'GET':
    form.movie1.data = movieList.movie1
    form.movie2.data = movieList.movie2
    form.movie3.data = movieList.movie3
    form.movie4.data = movieList.movie4
    form.movie5.data = movieList.movie5
    form.movie6.data = movieList.movie6
    form.movie7.data = movieList.movie7
    form.movie8.data = movieList.movie8
    form.movie9.data = movieList.movie9
    form.movie10.data = movieList.movie10
  return render_template('add.html', form=form, title='Update')

@app.route('/edit/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
  movieList = MovieList.query.get_or_404(id)
  if movieList.creator != current_user:
    abort(403)
  db.session.delete(movieList)
  db.session.commit()
  flash('This movie list has been deleted.', 'success')
  return redirect(url_for('index'))


# FLASK_APP=app.py FLASK_ENV=development flask run