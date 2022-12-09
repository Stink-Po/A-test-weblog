from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, ConfirmForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import random
import smtplib
from functools import wraps

email = "fresh.pourya@gmail.com"
email_pw = "yqnnkzqqvyjnwude"
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
app.app_context().push()
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )
gravatar.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    confirmed = db.Column(db.Boolean, nullable=False)
    confirm_cod = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

    def __repr__(self):
        return f"<User {self.name}>"


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user.name != "admin":
            return abort(403)
        return f(*args, **kwargs)

    return decorator_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    # only admin can create and delete posts
    if current_user.is_authenticated:
        print(current_user.confirmed)
        print(current_user.id)
        if current_user.name == "admin" and current_user.id == 1:
            admin = True
        else:
            admin = False
    else:
        admin = False

    return render_template("index.html", all_posts=posts, is_log_in=current_user.is_authenticated, admin=admin)


@app.route('/register', methods=["POST", "GET"])
def register():
    all_users = User.query.all()
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        for user in all_users:
            if form.user_email.data == user.email:
                flash("You already ُSinged Up With This Email login Please")
                return redirect(url_for("register"))

        hash_password = generate_password_hash(password=form.user_password.data,
                                               method='pbkdf2:sha256',
                                               salt_length=8)

        confirm_number = ""
        for n in range(10):
            num = str(random.randint(0, 9))
            confirm_number += num
        print(confirm_number)
        new_user = User(
            email=form.user_email.data,
            password=hash_password,
            name=form.username.data,
            confirmed=False,
            confirm_cod=confirm_number,
        )
        db.session.add(new_user)
        db.session.commit()

        message = f"Subject:Please Confirm Your Address\n\n Hello Dear {form.username.data}\n" \
                  f"Thank You for creating account on my website\n" \
                  f"please confirm your email address by Entering the code blow in the website\n" \
                  f"Confirmation Code :  {confirm_number}"

        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(email, email_pw)
            connection.sendmail(from_addr=email,
                                to_addrs=form.user_email.data,
                                msg=message)
        login_user(new_user)
        flash("Thank you for Register Please Confirm your Email address")
        return redirect(url_for("confirm_email"))

    return render_template("register.html", form=form)


@app.route("/confirm", methods=["POST", "GET"])
def confirm_email():
    form = ConfirmForm()
    if form.scape.data:
        return redirect(url_for("get_all_posts"))
    if form.validate_on_submit():
        if current_user.confirm_cod == form.code.data:
            current_user.confirmed = True
            db.session.commit()
            flash('Thank you for Confirming Your Email')
            return redirect(url_for("get_all_posts"))
        else:
            flash("The Code is not Correct !  please try again")
            return redirect(url_for("confirm_email"))
    return render_template("confirm.html", form=form, is_log_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user_email = request.form.get("email")
            user_password = request.form.get("password")
            actual_user = User.query.filter_by(email=user_email).first()
            if actual_user:
                if check_password_hash(actual_user.password, user_password):
                    login_user(actual_user, remember=True)
                    return redirect(url_for("get_all_posts"))
                else:
                    flash("invalid Password")
            else:
                flash("check your entry email")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("We will Miss You comeback Soon !")
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            if current_user.confirmed:
                new_comment = Comment(text=comment_form.comment_text.data,
                                      comment_author=current_user,
                                      parent_post=requested_post
                                      )
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You Need To Login or register to comment")
            return redirect(url_for("login"))
    return render_template("post.html",
                           post=requested_post,
                           is_log_in=current_user.is_authenticated,
                           form=comment_form
                           )


@app.route("/about")
def about():
    return render_template("about.html", is_log_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", is_log_in=current_user.is_authenticated)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_log_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    if current_user.is_authenticated:
        if current_user.name == "admin":
            admin = True
        else:
            admin = False
    else:
        admin = False
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_log_in=current_user.is_authenticated, admin=admin)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
