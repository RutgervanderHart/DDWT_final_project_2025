from typing import Optional
from datetime import datetime, timezone
from hashlib import md5
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db, login

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True,
                                                unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True,
                                             unique=True)
    about_me: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    last_seen: so.Mapped[Optional[datetime]] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc))
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    is_admin: so.Mapped[bool] = so.mapped_column(sa.Boolean, server_default=sa.sql.expression.literal(False), nullable=False)
    reviews: so.WriteOnlyMapped['Review'] = so.relationship(
        back_populates='author')
    snackbars: so.WriteOnlyMapped['Snackbar'] = so.relationship(
        back_populates='owner')
    is_deleted: so.Mapped[bool] = so.mapped_column(
        sa.Boolean,
        server_default=sa.sql.expression.literal(False),
        nullable=False
    )
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'
    
    def written_reviews(self):
        Author = so.aliased(User)
        return (
            sa.select(Review)
            .join(Review.author.of_type(Author))
            .where(Author.id == self.id)
            .order_by(Review.timestamp.desc())
        )

    def soft_delete(self):
        """
        Soft-delete the user and all dependent snackbars and reviews.
        """
        self.is_deleted = True

        # Query the user's snackbars and soft-delete them
        snackbars = db.session.scalars(
            sa.select(Snackbar).where(Snackbar.owner == self)
        ).all()
        for sb in snackbars:
            sb.soft_delete()

        # Query the user's reviews and soft-delete them
        reviews = db.session.scalars(
            sa.select(Review).where(Review.author == self)
        ).all()
        for review in reviews:
            review.is_deleted = True

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Snackbar(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.String(64), index=True,
                                                unique=True)
    about: so.Mapped[str] = so.mapped_column(sa.String(140))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id),
                                               index=True)
    owner: so.Mapped[User] = so.relationship(back_populates='snackbars')
    reviews: so.WriteOnlyMapped['Review'] = so.relationship(
        back_populates='subject')
    is_deleted: so.Mapped[bool] = so.mapped_column(
        sa.Boolean,
        server_default=sa.sql.expression.literal(False),
        nullable=False
    )

    def soft_delete(self):
        """
        Soft-delete the snackbar and all dependent reviews.
        """
        self.is_deleted = True

        # Query the snackbar's reviews and soft-delete them
        reviews = db.session.scalars(
            sa.select(Review).where(Review.subject == self)
        ).all()
        for review in reviews:
            review.is_deleted = True

    def __repr__(self):
        return '<Post {}>'.format(self.body)

class Review(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.String(140))
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id),
                                               index=True)
    author: so.Mapped[User] = so.relationship(back_populates='reviews')
    snackbar_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(Snackbar.id),
                                                   index=True)
    subject: so.Mapped[Snackbar] = so.relationship(back_populates='reviews')
    is_deleted: so.Mapped[bool] = so.mapped_column(
        sa.Boolean,
        server_default=sa.sql.expression.literal(False),
        nullable=False
    )

    def soft_delete(self):
        """
        Soft-delete this review only.
        """
        self.is_deleted = True

    def __repr__(self):
        return '<Post {}>'.format(self.body)

class Report(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)

    # Who filed the report
    reporter_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('user.id'))
    reporter: so.Mapped['User'] = so.relationship('User',
                                                  foreign_keys=[reporter_id])

    # Who is being reported (if the target is a user)
    reported_user_id: so.Mapped[int] = so.mapped_column(
        sa.ForeignKey('user.id'), nullable=True
    )
    reported_user: so.Mapped['User'] = so.relationship(
        'User', foreign_keys=[reported_user_id]
    )

    # Which snackbar is being reported (if the target is a snackbar)
    reported_snackbar_id: so.Mapped[int] = so.mapped_column(
        sa.ForeignKey('snackbar.id'), nullable=True
    )
    reported_snackbar: so.Mapped['Snackbar'] = so.relationship('Snackbar')

    # Reason and optional details
    reason: so.Mapped[str] = so.mapped_column(sa.String(140))
    details: so.Mapped[str] = so.mapped_column(sa.Text, nullable=True)

    # Timestamp
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc))

    # Status to decide render location in admin panel
    status: so.Mapped[str] = so.mapped_column(
        sa.String(20),
        nullable=False,
        server_default="open"
    )

    def __repr__(self):
        return f"<Report id={self.id}, reason={self.reason}>"

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))