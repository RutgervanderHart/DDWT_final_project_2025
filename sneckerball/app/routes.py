from app import app, db
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
import sqlalchemy as sa
from urllib.parse import urlsplit
from datetime import datetime, timezone
from app.forms import LoginForm, RegistrationForm, EditProfileForm, ReviewForm, AddSnackbarForm
from app.models import User, Review, Snackbar

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    snackbars = db.session.scalars(sa.select(Snackbar)).all()
    return render_template('index.html', title='Home', snackbars=snackbars)

@app.route('/snackbar/<snackbar_name>', )
def snackbar(snackbar_name):
    current_snackbar = db.first_or_404(
        sa.select(Snackbar).where(Snackbar.name == snackbar_name)
        )
    reviews = db.session.scalars(
        sa.select(Review).where(Review.subject == current_snackbar)
    ).all()
    return render_template('snackbar.html', snackbar=current_snackbar,reviews=reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/user/<username>')
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    reviews = db.session.scalars(
        sa.select(Review).where(Review.author == user)
    ).all()
    snackbars = db.session.scalars(
        sa.select(Snackbar).where(Snackbar.owner == user)
        ).all()
    return render_template('user.html', user=user, reviews=reviews,snackbars=snackbars)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('user', username=current_user.username))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@app.route('/add_snackbar', methods=['GET', 'POST'])
@login_required
def add_snackbar():
    form = AddSnackbarForm()
    if form.validate_on_submit():
        snackbar = Snackbar(name=form.name.data, about=form.about.data,owner= current_user )
        db.session.add(snackbar)
        db.session.commit()
        flash('Congratulations, you succesfully added a snackbar!')
        return redirect(url_for('index'))
    return render_template('add_snackbar.html', title='Add Snackbar', form=form)

@app.route('/write_review/<snackbar_name>', methods=['GET', 'POST'])
@login_required
def write_review(snackbar_name):
    form = ReviewForm()
    current_snackbar = db.first_or_404(
        sa.select(Snackbar).where(Snackbar.name == snackbar_name)
        )
    if form.validate_on_submit():
        review = Review(body=form.review.data, author=current_user, subject=current_snackbar)
        db.session.add(review)
        db.session.commit()
        flash('Your review is now live!')
        return redirect(url_for('snackbar', snackbar_name=snackbar_name))
    reviews = db.session.scalars(current_user.written_reviews()).all()
    return render_template('write_review.html', title='Write Review',form=form, reviews=reviews)