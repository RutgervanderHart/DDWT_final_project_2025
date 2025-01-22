from typing import Optional
from datetime import datetime, timezone, timedelta
from hashlib import md5
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db, login
import secrets

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
    is_genieter = db.Column(db.Boolean, default=True)  # True = Snackbar-genieter, False = Snackbar-houder


    #  Fields for token-based authentication
    token: so.Mapped[Optional[str]] = so.mapped_column(sa.String(32), index=True, unique=True)
    token_expiration: so.Mapped[Optional[datetime]]
    
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

    # to_dict / from_dict for JSON serialization & deserialization
    def to_dict(self, include_email=False):
        """
        Convert User object into a Python dict suitable for JSON.
        :param include_email: Only set True if the user is retrieving
                              their own profile information.
        :return: dict with user fields, suitable for JSON responses.
        """
        data = {
            'id': self.id,
            'username': self.username,
            'about_me': self.about_me,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'avatar_url': self.avatar(128),
            'is_deleted': self.is_deleted
            # Might add more fields later like count of review or something.
        }
        if include_email:
            data['email'] = self.email
        return data

    def from_dict(self, data, new_user=False):
        """
        Update User object from a Python dict (typically from JSON).
        :param data: dict containing user fields
        :param new_user: If True, we expect a password for creation
        """
        for field in ['username', 'email', 'about_me']:
            if field in data:
                setattr(self, field, data[field])
        if 'role' in data:
            self.is_genieter = (data['role'].lower() == 'genieter')
        # If creating a brand-new user (POST /api/users), set password
        if new_user and 'password' in data:
            self.set_password(data['password'])


    # Token Authentication Helpers
    def get_token(self, expires_in=3600):
        """
        Generate (or reuse) a token for the user, valid for expires_in seconds.
        If an existing token has more than 60s to live, re-use that one.
        """
        now = datetime.now(timezone.utc)
        if self.token and self.token_expiration and self.token_expiration > now + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_hex(16)  # 32-char hex string
        self.token_expiration = now + timedelta(seconds=expires_in)
        db.session.add(self)
        db.session.commit()
        return self.token

    def revoke_token(self):
        """Immediately invalidates the user token."""
        self.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    @staticmethod
    def check_token(token):
        """
        Check whether a token is valid and has not expired.
        :param token: The token string sent by the client.
        :return: User object if valid; None if invalid or expired.
        """
        if not token:
            return None
        user = db.session.scalar(sa.select(User).where(User.token == token))
        if user is None or user.token_expiration.replace(
                tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return None
        return user

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

    # to_dict / from_dict
    def to_dict(self):
        """
        Convert Snackbar object into dict for JSON serialization.
        """
        data = {
            'id': self.id,
            'name': self.name,
            'about': self.about,
            'owner_id': self.user_id,
            'is_deleted': self.is_deleted
        }
        return data

    def from_dict(self, data):
        """
        Update Snackbar object from a dict. For partial updates, only
        fields found in data will be updated.
        """
        for field in ['name', 'about']:
            if field in data:
                setattr(self, field, data[field])


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

    # to_dict / from_dict
    def to_dict(self):
        """
        Convert Review into dict for JSON.
        """
        data = {
            'id': self.id,
            'body': self.body,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'author_id': self.user_id,
            'snackbar_id': self.snackbar_id,
            'is_deleted': self.is_deleted
        }
        return data

    def from_dict(self, data):
        """
        Update Review fields from dict.
        """
        for field in ['body']:
            if field in data:
                setattr(self, field, data[field])

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