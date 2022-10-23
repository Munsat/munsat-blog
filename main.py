import os

from flask import Flask, render_template, redirect, url_for, flash, request, abort
import smtplib
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ["SECRET_KEY"]
ckeditor = CKEditor(app)
Bootstrap(app)

# My EMAIL
MY_EMAIL = os.environ["my_email"]
MY_PASS = os.environ["my_pass"]

# INITIALISE GRAVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

Base = declarative_base()


# CONFIGURE TABLES
class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)

    posts = relationship('BlogPost', back_populates='blog_author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)

    author_id = Column(Integer, ForeignKey('users.id'))
    blog_author = relationship('User', back_populates='posts')

    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)

    comments = relationship('Comment', back_populates='parent_blog')


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)

    author_id = Column(Integer, ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')

    blog_id = Column(Integer, ForeignKey('blog_posts.id'))
    parent_blog = relationship('BlogPost', back_populates='comments')

    comment = Column(Text, nullable=False)


# Create all the tables in the database
db.create_all()


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return function(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# Register new users into the User database
@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():

        if User.query.filter_by(email=register_form.email.data).first() is None:
            hashed_password = generate_password_hash(password=request.form.get('password'),
                                                     method='pbkdf2:sha256',
                                                     salt_length=8)
            add_user = User(email=register_form.email.data,
                            password=hashed_password,
                            name=register_form.name.data)
            db.session.add(add_user)
            db.session.commit()
            # This line will authenticate the user with Flask-Login
            login_user(user=add_user)
            return redirect(url_for('get_all_posts'))

        flash(message="You've already signed up with that email. Try logging in!", category="error")
        return redirect(url_for('login'))
    return render_template("register.html", form=register_form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash('The email does not exist. Please try again.', 'error')
            return redirect(url_for('login'))
        elif check_password_hash(pwhash=user.password, password=login_form.password.data) is False:
            flash('Invalid password provided. Please try again.', 'error')
            return redirect(url_for('login'))
        else:
            login_user(user=user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:index>", methods=['GET', 'POST'])
def show_post(index):
    requested_post = BlogPost.query.get(index)
    all_comments = requested_post.comments
    comment_box = CommentForm()
    if comment_box.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(author_id=current_user.id,
                                  blog_id=index,
                                  comment=comment_box.comment.data)
            db.session.add(new_comment)
            db.session.commit()
            flash(message='Your comment has been submitted!', category='text-success')
            return redirect(url_for('show_post', index=index))
        else:
            flash('You need to login or register to comment.', 'error')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, current_user=current_user,
                           form=comment_box, all_comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        data = request.form
        name = data['name']
        email = data['email']
        phone = data['phone']
        message = data['message']
        send_email(name, email, phone, message)
        flash(message='Successfully sent your email!', category='text-success')
        return redirect(url_for('contact'))
    return render_template("contact.html", current_user=current_user)


def send_email(name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=MY_EMAIL, password=MY_PASS)
        connection.sendmail(from_addr=email, to_addrs=MY_EMAIL, msg=f"Subject:Blog Enquiry\n\nName: {name}\n"
                                                                    f"Email: {email}\nPhone: {phone}\nMessage: {message}")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_post():
    create_post_form = CreatePostForm()
    if create_post_form.validate_on_submit():
        data = request.form
        current_date = datetime.today()
        new_post = BlogPost(title=data.get('title'),
                            subtitle=data.get('subtitle'),
                            author_id=current_user.id,
                            img_url=data.get('img_url'),
                            body=data.get('body'),
                            date=f"{current_date.strftime('%B %d, %Y')}",
                            )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form=create_post_form, current_user=current_user)


@app.route("/edit-post/<post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    create_post_form = CreatePostForm(title=post.title,
                                      subtitle=post.subtitle,
                                      author_id=current_user.id,
                                      img_url=post.img_url,
                                      body=post.body)
    if create_post_form.validate_on_submit():
        data = request.form
        post.title = data.get('title')
        post.subtitle = data.get('subtitle')
        post.author = data.get('author')
        post.img_url = data.get('img_url')
        post.body = data.get('body')
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form=create_post_form, is_edit=True, current_user=current_user)


@app.route('/delete-post/<post_id>')
@admin_only
def delete_post(post_id):
    post = BlogPost.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
