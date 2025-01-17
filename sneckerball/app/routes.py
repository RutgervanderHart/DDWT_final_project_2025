from app import app, db
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
import sqlalchemy as sa
from urllib.parse import urlsplit
from datetime import datetime, timezone
from app.forms import LoginForm, RegistrationForm, EditProfileForm,EditSnackbarForm, ReviewForm, AddSnackbarForm, ReportForm
from app.models import User, Review, Snackbar, Report

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    snackbars = db.session.scalars(sa.select(Snackbar).where(Snackbar.is_deleted == False)).all()
    return render_template('index.html', title='Home', snackbars=snackbars)

@app.route('/snackbar/<snackbar_name>', )
def snackbar(snackbar_name):
    current_snackbar = db.first_or_404(
        sa.select(Snackbar).where(Snackbar.name == snackbar_name, Snackbar.is_deleted == False)
        )
    reviews = db.session.scalars(
        sa.select(Review).where(Review.subject == current_snackbar, Review.is_deleted == False)
    ).all()
    return render_template('snackbar.html', snackbar=current_snackbar,reviews=reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data, User.is_deleted == False))
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
    user = db.first_or_404(sa.select(User).where(User.username == username, User.is_deleted == False))
    reviews = db.session.scalars(
        sa.select(Review).where(Review.author == user, Review.is_deleted == False)
    ).all()
    snackbars = db.session.scalars(
        sa.select(Snackbar).where(Snackbar.owner == user, Snackbar.is_deleted == False)
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

@app.route('/edit_snackbar/<snackbar_name>', methods=['GET', 'POST'])
@login_required
def edit_snackbar(snackbar_name):
    current_snackbar = db.first_or_404(
        sa.select(Snackbar).where(Snackbar.name == snackbar_name, Snackbar.is_deleted == False)
        )
    form = EditSnackbarForm(current_snackbar.name)
    if form.validate_on_submit():
        current_snackbar.name = form.name.data
        current_snackbar.about = form.about.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('snackbar', snackbar_name=current_snackbar.name))
    elif request.method == 'GET':
        form.name.data = current_snackbar.name
        form.about.data = current_snackbar.about
    return render_template('edit_snackbar.html', title='Edit Snackbar',
                           form=form)

@app.route('/edit_review/<review>', methods=['GET', 'POST'])
@login_required
def edit_review(review):
    current_review = db.first_or_404(
        sa.select(Review).where(Review.id == review, Review.is_deleted == False)
        )
    form = ReviewForm()
    if form.validate_on_submit():
        current_review.body = form.body.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('snackbar', snackbar_name=current_review.subject.name))
    elif request.method == 'GET':
        form.body.data = current_review.body
    return render_template('edit_review.html', title='Edit Review',
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
        sa.select(Snackbar).where(Snackbar.name == snackbar_name, Snackbar.is_deleted == False)
        )
    if form.validate_on_submit():
        review = Review(body=form.body.data, author=current_user, subject=current_snackbar)
        db.session.add(review)
        db.session.commit()
        flash('Your review is now live!')
        return redirect(url_for('snackbar', snackbar_name=snackbar_name))
    reviews = db.session.scalars(current_user.written_reviews().where(Review.is_deleted == False)).all()
    return render_template('write_review.html', title='Write Review',form=form, reviews=reviews, snackbar=current_snackbar)

@app.route('/admin/reports')
@login_required
def admin_reports():
    # Check if current_user is admin
    if not current_user.is_admin:
        flash("You are not authorized to access this page.")
        return redirect(url_for('index'))

    # Get all reports and filter by status
    all_reports = db.session.scalars(sa.select(Report)).all()

    grouped_reports = {
        'open_user_reports': [],
        'open_snackbar_reports': [],
        'resolved_reports': [],
        'rejected_reports': []
    }

    for report in all_reports:
        if report.status == 'open':
            if report.reported_user:
                grouped_reports['open_user_reports'].append(report)
            elif report.reported_snackbar:
                grouped_reports['open_snackbar_reports'].append(report)
        elif report.status == 'resolved':
            grouped_reports['resolved_reports'].append(report)
        elif report.status == 'rejected':
            grouped_reports['rejected_reports'].append(report)

    return render_template('admin_reports.html', grouped_reports=grouped_reports)

@app.route('/file_report/<target_type>/<target_identifier>', methods=['GET', 'POST'])
@login_required
def file_report(target_type, target_identifier):
    form = ReportForm(target_type)
    reported_user = None
    reported_snackbar = None

    if target_type == 'user':
        reported_user = db.first_or_404(
            sa.select(User).where(User.username == target_identifier)
        )
    elif target_type == 'snackbar':
        reported_snackbar = db.first_or_404(
            sa.select(Snackbar).where(Snackbar.name == target_identifier)
        )
    else:
        flash("Invalid report type.")
        return redirect(url_for('index'))

    if form.validate_on_submit():
        #  Check for existing report from the same reporter on the same target
        existing_report = None
        if reported_user:
            existing_report = db.session.scalar(sa.select(Report).where(
                Report.reporter_id == current_user.id,
                Report.reported_user_id == reported_user.id
            ))
        else:
            existing_report = db.session.scalar(sa.select(Report).where(
                Report.reporter_id == current_user.id,
                Report.reported_snackbar_id == reported_snackbar.id
            ))

        if existing_report:
            # If a duplicate is found, show a message and redirect
            flash("You have already reported this user/snackbar.")
            if reported_user:
                return redirect(url_for('user', username=reported_user.username))
            else:
                return redirect(url_for('snackbar', snackbar_name=reported_snackbar.name))

        # Otherwise, create a new Report
        new_report = Report(
            reporter=current_user,
            reported_user=reported_user,
            reported_snackbar=reported_snackbar,
            reason=form.reason.data,
            details=form.details.data
        )
        db.session.add(new_report)
        db.session.commit()

        flash("Your report has been submitted.")
        if reported_user:
            return redirect(url_for('user', username=reported_user.username))
        else:
            return redirect(url_for('snackbar', snackbar_name=reported_snackbar.name))

    # For the template to show the "name" at top
    reported_name = reported_user.username if reported_user else reported_snackbar.name
    # let the template know if it's user or snackbar for reason-choices usage
    return render_template(
        'file_report.html',
        form=form,
        target_type=target_type,
        reported_name=reported_name
    )


@app.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@login_required
def resolve_report(report_id):
    if not current_user.is_admin:
        flash("You are not authorized to access this page.")
        return redirect(url_for('index'))

    report = db.first_or_404(sa.select(Report).where(Report.id == report_id))
    report.status = 'resolved'
    db.session.commit()
    flash("Report has been marked as resolved.")
    return redirect(url_for('admin_reports'))


@app.route('/admin/report/<int:report_id>/reject', methods=['POST'])
@login_required
def reject_report(report_id):
    if not current_user.is_admin:
        flash("You are not authorized to access this page.")
        return redirect(url_for('index'))

    report = db.first_or_404(sa.select(Report).where(Report.id == report_id))
    report.status = 'rejected'
    db.session.commit()
    flash("Report has been rejected.")
    return redirect(url_for('admin_reports'))


@app.route('/admin/report/<int:report_id>/delete_user', methods=['POST'])
@login_required
def delete_user_by_report(report_id):
    if not current_user.is_admin:
        flash("You are not authorized to access this page.")
        return redirect(url_for('index'))

    report = db.first_or_404(sa.select(Report).where(Report.id == report_id))
    if report.reported_user:
        report.reported_user.soft_delete()
        report.status = 'resolved'
        db.session.commit()
        flash("User (and associated snackbars & reviews) have been soft-deleted.")
    else:
        flash("No reported user found in this report.")
    return redirect(url_for('admin_reports'))


@app.route('/admin/report/<int:report_id>/delete_snackbar', methods=['POST'])
@login_required
def delete_snackbar_by_report(report_id):
    if not current_user.is_admin:
        flash("You are not authorized to access this page.")
        return redirect(url_for('index'))

    report = db.first_or_404(sa.select(Report).where(Report.id == report_id))
    if report.reported_snackbar:
        report.reported_snackbar.soft_delete()
        report.status = 'resolved'
        db.session.commit()
        flash("Snackbar (and associated reviews) have been soft-deleted.")
    else:
        flash("No reported snackbar found in this report.")
    return redirect(url_for('admin_reports'))
