from flask import Flask, render_template, flash, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask import session, abort
from flask_login import (
    UserMixin,
    LoginManager,
    login_required,
    login_user,
    logout_user,
    current_user,
)
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, Regexp
from flask_session import Session
from flask_session_captcha import FlaskSessionCaptcha
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import uuid
import os
import string
import secrets
import glob
from PIL import Image, ImageDraw, ImageFont
import random
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from flask import send_from_directory
import re

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(basedir, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "database.db")
app.config["SECRET_KEY"] = os.urandom(32)

app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)
app.config["SESSION_COOKIE_SECURE"] = True     
app.config["SESSION_COOKIE_HTTPONLY"] = True   
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  
app.config["CAPTCHA_ENABLE"] = True
app.config["CAPTCHA_LENGTH"] = 5
app.config["CAPTCHA_WIDTH"] = 200
app.config["CAPTCHA_HEIGHT"] = 70

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "dlugimail123@gmail.com"
app.config["MAIL_PASSWORD"] = "egwd xjsi idlk txkx"
app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]



Session(app)
captcha = FlaskSessionCaptcha(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

POST_RATE_LIMIT_MINUTES = 5

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    creation_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    email_verified = db.Column(db.Boolean, default=False)
    activation_token = db.Column(db.String(64), unique=True, nullable=False)
    token_expiration_time = db.Column(db.DateTime, nullable=False)
    role = db.Column(db.Integer, nullable=False, default=1)

    is_active = db.Column(db.Boolean, default=False)
    last_post_created_at = db.Column(db.DateTime, nullable=True)
    registration_ip = db.Column(db.String(45), nullable=False)

    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    current_session_id = db.Column(db.String(128), nullable=True)
    reset_token = db.Column(db.String(64), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

def can_delete_post(post: Post) -> bool:
    if not current_user.is_authenticated:
        return False
    if current_user.role >= 2:  
        return True
    return post.author_id == current_user.id

def can_delete_comment(comment: Comment) -> bool:
    if not current_user.is_authenticated:
        return False
    if current_user.role >= 2:  # admin
        return True
    return comment.author_id == current_user.id

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


SAFE_TITLE_REGEX = r'^[A-Za-z0-9 _-]{1,24}$'
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(24), nullable=False)
    image_filename = db.Column(db.String(255), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = db.relationship("User", backref="posts")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    comments = db.relationship(
        "Comment",
        backref="post",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    ratings = db.relationship(
        "Rating",
        backref="post",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    post_id = db.Column(
    db.Integer,
    db.ForeignKey("post.id", ondelete="CASCADE"),
    nullable=False
    )

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    author = db.relationship("User")
    created_at = db.Column(db.DateTime, default=datetime.now())

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    value = db.Column(db.Integer, nullable=False)  # 1–5

    post_id = db.Column(
    db.Integer,
    db.ForeignKey("post.id", ondelete="CASCADE"),
    nullable=False
    )

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = db.relationship("User")

    __table_args__ = (
        db.UniqueConstraint("post_id", "user_id", name="one_rating_per_user"),
    )

def get_average_rating(post: Post):
    if not post.ratings:
        return None
    return round(sum(r.value for r in post.ratings) / len(post.ratings), 2)

class RegisterForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(min=4, max=16),
            Regexp(r'^[A-Za-z0-9]+$', message="Username may contain only letters and numbers.")
        ],
        render_kw={"placeholder": "Username"}
    )

    email = StringField(
        validators=[InputRequired(), Email()],
        render_kw={"placeholder": "Email"}
    )

    password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=14, max=32),
            Regexp(r'^[A-Za-z0-9!@#$%^&*()_+=\-]+$', message="Password contains invalid characters.")
        ],
        render_kw={"placeholder": "Password"}
    )

    confirm_password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=14, max=32),
            Regexp(r'^[A-Za-z0-9!@#$%^&*()_+=\-]+$', message="Password contains invalid characters.")
        ],
        render_kw={"placeholder": "Confirm Password"}
    )

    captcha = StringField(
        validators=[InputRequired()],
        render_kw={"placeholder": "Captcha"}
    )

    submit = SubmitField("Register", render_kw={"class": "default-button"})


class LoginForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(min=4, max=16),
            Regexp(r'^[A-Za-z0-9]+$', message="Username may contain only letters and numbers.")
        ],
        render_kw={"placeholder": "Username"}
    )

    password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=14, max=32),
            Regexp(r'^[A-Za-z0-9!@#$%^&*()_+=\-]+$', message="Password contains invalid characters.")
        ],
        render_kw={"placeholder": "Password"}
    )
    captcha = StringField(
    validators=[InputRequired()],
    render_kw={"placeholder": "Captcha"}
    )
    submit = SubmitField("Login", render_kw={"class": "default-button"})


class ResetRequestForm(FlaskForm):
    email = StringField(
        validators=[InputRequired(), Email()],
        render_kw={"placeholder": "Email"}
    )
    submit = SubmitField("Send reset password", render_kw={"class": "default-button"})


class ChangePasswordForm(FlaskForm):
    password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=14, max=32),
            Regexp(r'^[A-Za-z0-9!@#$%^&*()_+=\-]+$', message="Password contains invalid characters.")
        ],
        render_kw={"placeholder": "New Password"}
    )

    confirm_password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=14, max=32),
            Regexp(r'^[A-Za-z0-9!@#$%^&*()_+=\-]+$', message="Password contains invalid characters.")
        ],
        render_kw={"placeholder": "Confirm New Password"}
    )

    submit = SubmitField("Change password", render_kw={"class": "default-button"})

@app.before_request
def global_security_middleware():

    session.permanent = True

    if not current_user.is_authenticated:
        return

    if session.get("session_id") != current_user.current_session_id:
        flash("Your session expired.", "error")
        print(f"sessions values aren't the same - user logged in from another device")
        logout_user()
        return redirect(url_for("login"))

    allowed_webpages = {"change_password", "logout", "login", "second_factor"}
    if current_user.must_change_password:
        if request.endpoint not in allowed_webpages:
            return redirect(url_for("change_password"))

    session.modified = True


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
    )

    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"

    return response


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegisterForm()

    if form.validate_on_submit():

        if not captcha.validate():
            flash("Wrong captcha!", "error")
            return render_template("register.html", form=form)

        if form.password.data != form.confirm_password.data:
            flash("Passwords do not match.", "error")
            return render_template("register.html", form=form)

        user_ip = request.remote_addr or "0.0.0.0"
        token = uuid.uuid4().hex
        expiration = datetime.now() + timedelta(hours=24)

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            registration_ip=user_ip,
            activation_token=token,
            token_expiration_time=expiration
        )
        new_user.set_password(form.password.data)

        try:
            db.session.add(new_user)
            db.session.commit()

        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "error")
            return render_template("register.html", form=form)

        activation_link = url_for("activate_account", token=token, _external=True)

        try:
            msg = Message(
                subject="Activate your account",
                recipients=[form.email.data],
                html=f"""
                    <h2>Activate Your Account</h2>
                    <p>Hi {form.username.data},</p>
                    <p>Click the link below to activate your account:</p>
                    <p><a href="{activation_link}">{activation_link}</a></p>
                    <p>This link is valid for 24 hours.</p>
                """
            )
            mail.send(msg)
            flash("Account created! Check your email for activation link.", "success")

        except Exception as e:
            flash(f"Account created, but email could not be sent: {e}", "error")

        return render_template("register.html", form=RegisterForm(), account_created=True)

    return render_template("register.html", form=form)

def generate_2fa_pin():
    return f"{random.randint(0, 999999):06d}"  

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.must_change_password:
            return redirect(url_for("change_password"))
        return redirect(url_for("home"))

    form = LoginForm()

    if form.validate_on_submit():
        if not captcha.validate():
            flash("Wrong captcha!", "error")
            return render_template("login.html", form=form)
        user = User.query.filter_by(
            username=form.username.data,
            is_active=True
        ).first()

        if user is None or not user.check_password(form.password.data):
            flash("Invalid credentials or account is inactive.", "error")
            return render_template("login.html", form=form)

        session.pop("session_id", None)

        pin = generate_2fa_pin()
        session["2fa_user_id"] = user.id
        session["2fa_pin"] = pin
        session["2fa_expiration"] = (datetime.now() + timedelta(minutes=3)).isoformat()

        try:
            msg = Message(
                subject="Your 2FA Code",
                recipients=[user.email],
                html=f"""
                    <h3>Your login PIN:</h3>
                    <p style='font-size:22px;'><b>{pin}</b></p>
                    <p>This PIN is valid for 3 minutes.</p>
                """
            )
            mail.send(msg)
        except Exception as e:
            flash(f"Failed to send 2FA code: {e}", "error")
            return render_template("login.html", form=form)

        return redirect(url_for("second_factor"))


    return render_template("login.html", form=form)

@app.route("/2fa", methods=["GET", "POST"])
def second_factor():
    if "2fa_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user_input = request.form.get("pin")
        saved_pin = session.get("2fa_pin")
        exp = session.get("2fa_expiration")

        if saved_pin and exp and datetime.now() > datetime.fromisoformat(exp):
            flash("2FA PIN expired. Log in again.", "error")
            session.pop("2fa_user_id", None)
            session.pop("2fa_pin", None)
            session.pop("2fa_expiration", None)
            return redirect(url_for("login"))

        if user_input != saved_pin:
            flash("Invalid PIN.", "error")
            return render_template("2fa.html")

        user = db.session.get(User, session["2fa_user_id"])

        login_user(user)
        new_session = uuid.uuid4().hex
        session["session_id"] = new_session
        user.current_session_id = new_session
        db.session.commit()

        session.pop("2fa_user_id", None)
        session.pop("2fa_pin", None)
        session.pop("2fa_expiration", None)

        if user.must_change_password:
            return redirect(url_for("change_password"))

        return redirect(url_for("home"))

    return render_template("2fa.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if not can_delete_post(post):
        abort(403)

    image_path = os.path.join(app.config["UPLOAD_FOLDER"], post.image_filename)
    if os.path.exists(image_path):
        os.remove(image_path)

    db.session.delete(post)
    db.session.commit()

    flash("Post deleted.", "success")
    return redirect(url_for("home"))


@app.route("/post/<int:post_id>/rate", methods=["POST"])
@login_required
def rate_post(post_id):
    if current_user.role < 1: #user is a guest
        abort(403)

    post = Post.query.get_or_404(post_id)

    try:
        value = int(request.form.get("rating"))
    except (TypeError, ValueError):
        abort(400)

    if value < 1 or value > 5: #manual rating manipulation
        abort(400)

    rating = Rating.query.filter_by(
        post_id=post.id,
        user_id=current_user.id
    ).first()

    if rating:
        rating.value = value
    else:
        rating = Rating(
            value=value,
            post_id=post.id,
            user_id=current_user.id
        )
        db.session.add(rating)

    db.session.commit()
    return redirect(url_for("view_post", post_id=post.id))


def add_watermark(image_path, text="APPSEC"):
    from PIL import Image, ImageDraw, ImageFont

    with Image.open(image_path).convert("RGBA") as base:
        width, height = base.size

        watermark = Image.new("RGBA", base.size)
        draw = ImageDraw.Draw(watermark)

        font_size = max(20, width // 15)

        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except IOError:
            font = ImageFont.load_default()

        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        x = width - text_width - 10
        y = height - text_height - 10

        draw.text(
            (x, y),
            text,
            font=font,
            fill=(255, 255, 255, 80)  
        )

        combined = Image.alpha_composite(base, watermark)
        combined.convert("RGB").save(image_path)


@app.route("/activate/<token>")
def activate_account(token):
    user = User.query.filter_by(activation_token=token).first()

    if not user:
        return "Invalid activation token."

    if user.token_expiration_time < datetime.now():
        return "Activation token expired."

    user.email_verified = True
    user.is_active = True
    db.session.commit()

    return "Account activated! You may now log in."

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = ResetRequestForm()

    if form.validate_on_submit():

        user = User.query.filter_by(email=form.email.data).first()
        flash("If the email exists in the database, a reset link has been sent.", "info")

        if not user:
            return redirect(url_for("login"))

        token = uuid.uuid4().hex
        user.reset_token = token
        user.reset_token_expiration = datetime.now() + timedelta(minutes=30)
        db.session.commit()
        reset_link = url_for("reset_password_token", token=token, _external=True)
        msg = Message(
            subject="Password Reset Link",
            recipients=[user.email],
            html=f"""
                <h3>Password Reset Request</h3>
                <p>Click the link below to continue password reset:</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
                <p>This link will expire in 30 minutes.</p>
            """
        )
        mail.send(msg)

        return redirect(url_for("login"))

    return render_template("forgot_password.html", form=form)




@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def view_post(post_id):
    post = Post.query.get_or_404(post_id)

    if request.method == "POST":
        if not current_user.is_authenticated or current_user.role < 1: #user is a guest
            abort(403)

        content = request.form.get("content", "").strip()
        if not content:
            flash("Empty comment", "error")
            return redirect(url_for("view_post", post_id=post.id))

        comment = Comment(
            content=content,
            post_id=post.id,
            author_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()

        return redirect(url_for("view_post", post_id=post.id))

    avg_rating = get_average_rating(post)
    return render_template("post.html", post=post, avg_rating=avg_rating)




@app.route("/reset/<token>")
def reset_password_token(token):

    user = User.query.filter(
        User.reset_token == token,
        User.reset_token_expiration > datetime.now()
    ).first()

    if not user:
        return "Invalid or expired reset token."

    temporary_password = uuid.uuid4().hex[:16]

    user.set_password(temporary_password)
    user.must_change_password = True
    user.reset_token = None
    user.reset_token_expiration = None

    db.session.commit()

    msg = Message(
        subject="Your Temporary Password",
        recipients=[user.email],
        html=f"""
            <h3>Your temporary password:</h3>
            <p><b>{temporary_password}</b></p>
            <p>Use it to log in. You will be required to change your password immediately.</p>
        """
    )
    mail.send(msg)

    return "A temporary password has been sent to your email. You may now log in."


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if not current_user.must_change_password:
        return redirect(url_for("home"))

    if form.validate_on_submit():

        if form.password.data != form.confirm_password.data:
            flash("Passwords do not match.", "error")
            return render_template("change_password.html", form=form)

        if current_user.check_password(form.password.data):
            flash("New password must be different from your current password.", "error")
            return render_template("change_password.html", form=form)

        current_user.set_password(form.password.data)
        current_user.must_change_password = False
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for("home"))

    return render_template("change_password.html", form=form)

@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if not can_delete_comment(comment):
        abort(403)

    post_id = comment.post_id

    db.session.delete(comment)
    db.session.commit()

    flash("Comment deleted.", "success")
    return redirect(url_for("view_post", post_id=post_id))

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role < 2:
        abort(403)

    users = User.query.order_by(User.id).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_user(user_id):
    if current_user.role < 2:
        abort(403)

    user = User.query.get_or_404(user_id)

    if user.role == 3:
        abort(403)  

    if user.id == current_user.id:
        abort(400)

    user.is_active = not user.is_active
    db.session.commit()

    return redirect(url_for("admin_users"))

@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@login_required
def change_role(user_id):
    if current_user.role < 2:
        abort(403)

    user = User.query.get_or_404(user_id)

    if user.role == 3:
        abort(403)

    if current_user.id == user.id:
        abort(403)

    user.role = 2 if user.role == 1 else 1
    db.session.commit()

    flash("User role updated.", "success")
    return redirect(url_for("admin_users"))




@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if not current_user.is_authenticated or current_user.role < 1: #user is a guest 
            abort(403)

        if current_user.role < 2:  #if not an admin
            if current_user.last_post_created_at:
                delta = datetime.now() - current_user.last_post_created_at
                if delta < timedelta(minutes=POST_RATE_LIMIT_MINUTES):
                    remaining = POST_RATE_LIMIT_MINUTES * 60 - int(delta.total_seconds())
                    flash(
                        f"You can upload next image in {remaining} seconds.",
                        "error"
                    )
                    return redirect(url_for("home"))

        
        title = request.form.get("title", "").strip()
        if not re.match(SAFE_TITLE_REGEX, title):
            flash("Invalid title.", "error")
            return redirect(url_for("home"))

        file = request.files.get("image")
        if not file or not allowed_file(file.filename):
            flash("Invalid file.", "error")
            return redirect(url_for("home"))

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        ext = file.filename.rsplit(".", 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        file.save(path)
        add_watermark(
                path,
                text="Epic forum watermark"
        )
        post = Post(
            title=title,
            image_filename=filename,
            author_id=current_user.id
        )

        db.session.add(post)

        if current_user.role < 2:
            current_user.last_post_created_at = datetime.now()

        db.session.commit()

        flash("Post uploaded successfully.", "success")
        return redirect(url_for("home"))

    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("home.html", posts=posts)

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()

    if not q:
        return redirect(url_for("home"))

    posts = Post.query.filter(Post.title.ilike(f"%{q}%")).all()
    return render_template("search.html", posts=posts, query=q)

def generate_secure_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    files = glob.glob('flask_session/*')
    for f in files:
        os.remove(f)

    with app.app_context():
        db.create_all()

        superadmin = User.query.filter_by(role=3).first()

        if not superadmin:
            email = input("Enter email for superadmin: ").strip()

            while not email or "@" not in email:
                email = input("Invalid email. Enter valid email: ").strip()

            password = generate_secure_password(16)

            superadmin = User(
                username="admin",
                email=email,
                role=3,  # SUPERADMIN
                is_active=True,
                email_verified=True,
                registration_ip="127.0.0.1",
                activation_token=uuid.uuid4().hex,
                token_expiration_time=datetime.now()
            )
            superadmin.set_password(password)

            db.session.add(superadmin)
            db.session.commit()

            print("\nsuperadmin created")
            print(f"Username: admin")
            print(f"Email: {email}")
            print(f"Password: {password}")

        else:
            superadmin.role = 3
            superadmin.is_active = True
            db.session.commit()

    app.run(
        debug=False,
        host="127.1.0.0",
        port=5000,
        ssl_context="adhoc"
    )

