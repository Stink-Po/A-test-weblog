from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, EqualTo, Length
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    user_email = StringField("Email", validators=[DataRequired()])
    username = StringField("Name", validators=[DataRequired()])
    user_password = PasswordField("password",
                                  [Length(min=8),
                                   DataRequired(),
                                   EqualTo("confirm_password",
                                           message="passwords must mach")])
    confirm_password = PasswordField("Repeat Password")
    submit = SubmitField("Create Account")


class ConfirmForm(FlaskForm):
    code = StringField("Enter Your Code", validators=[DataRequired()])
    submit = SubmitField("Submit")
    scape = SubmitField("Skip")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit")
