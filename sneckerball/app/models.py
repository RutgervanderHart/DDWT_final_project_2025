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
    reviews: so.WriteOnlyMapped['Review'] = so.relationship(
        back_populates='author')
    snackbars: so.WriteOnlyMapped['Snackbar'] = so.relationship(
        back_populates='owner')
    
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

    def __repr__(self):
        return '<Post {}>'.format(self.body)

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))