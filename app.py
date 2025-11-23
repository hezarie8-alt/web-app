import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_, and_, case
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development')

database_url = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    major = db.Column(db.String(100))
    grade = db.Column(db.String(50))
    password_hash = db.Column(db.String(128), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class RegistrationForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100)])
    major = StringField('رشته تحصیلی')
    grade = StringField('مقطع تحصیلی')
    password = PasswordField('رمز عبور', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('ثبت‌نام')

    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('این نام کاربری قبلاً استفاده شده است.')

class LoginForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('رمز عبور', validators=[DataRequired()])
    submit = SubmitField('ورود')

class UpdateProfileForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100)])
    major = StringField('رشته تحصیلی')
    grade = StringField('مقطع تحصیلی')
    submit = SubmitField('بروزرسانی پروفایل')

    def __init__(self, original_username, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_name(self, field):
        if field.data != self.original_username:
            if User.query.filter_by(name=field.data).first():
                raise ValidationError('نام کاربری جدید توسط شخص دیگری استفاده شده است.')

class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('تکرار رمز عبور جدید', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('تغییر رمز عبور')

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('حذف حساب کاربری')

class SendMessageForm(FlaskForm):
    content = TextAreaField('پیام', validators=[DataRequired()])
    submit = SubmitField('ارسال')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            name=form.name.data,
            major=form.major.data,
            grade=form.grade.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('حساب کاربری شما با موفقیت ایجاد شد. لطفاً وارد شوید.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['current_user_id'] = user.id
            return redirect(url_for('match'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('current_user_id', None)
    return redirect(url_for('login'))

@app.route('/match')
@login_required
def match():
    current_user_id = session.get('current_user_id')
    q = request.args.get('q')
    query = User.query.filter(User.id != current_user_id)
    if q:
        users = query.filter(
            (User.major.contains(q)) | (User.name.contains(q))
        ).all()
    else:
        users = query.all()
    return render_template('match.html', users=users, current_user_id=current_user_id)

@app.route('/profile')
@login_required
def profile():
    current_user_id = session.get('current_user_id')
    user = User.query.get_or_404(current_user_id)
    update_profile_form = UpdateProfileForm(obj=user, original_username=user.name)
    update_password_form = UpdatePasswordForm()
    delete_account_form = DeleteAccountForm()
    return render_template('profile.html', user=user, update_profile_form=update_profile_form, update_password_form=update_password_form, delete_account_form=delete_account_form)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user_id = session.get('current_user_id')
    user = User.query.get_or_404(current_user_id)
    form = UpdateProfileForm(obj=user, original_username=user.name)
    if form.validate_on_submit():
        user.name = form.name.data
        user.major = form.major.data
        user.grade = form.grade.data
        db.session.commit()
        flash('پروفایل شما با موفقیت بروزرسانی شد.', 'success')
    return redirect(url_for('profile'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_user_id = session.get('current_user_id')
    user = User.query.get_or_404(current_user_id)
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(user.password_hash, form.current_password.data):
            user.password_hash = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('رمز عبور شما با موفقیت تغییر کرد.', 'success')
        else:
            flash('رمز عبور فعلی اشتباه است.', 'error')
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    current_user_id = session.get('current_user_id')
    user_to_delete = User.query.get_or_404(current_user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    session.pop('current_user_id', None)
    flash('حساب کاربری شما حذف شد.', 'info')
    return redirect(url_for('register'))

@app.route('/chat/<int:other_user_id>')
@login_required
def chat(other_user_id):
    current_user_id = session.get('current_user_id')
    other_user = User.query.get_or_404(other_user_id)
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
            and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.timestamp.asc()).all()
    form = SendMessageForm()
    return render_template('chat.html', other_user=other_user, messages=messages, form=form)

@app.route('/send_chat_message/<int:other_user_id>', methods=['POST'])
@login_required
def send_chat_message(other_user_id):
    form = SendMessageForm()
    if form.validate_on_submit():
        current_user_id = session.get('current_user_id')
        msg = Message(sender_id=current_user_id, receiver_id=other_user_id, content=form.content.data)
        db.session.add(msg)
        db.session.commit()
    return redirect(url_for('chat', other_user_id=other_user_id))

@app.route('/inbox/<int:user_id>')
@login_required
def inbox(user_id):
    current_user_id = session.get('current_user_id')
    if current_user_id != user_id:
        abort(403)
        
    user1 = case((Message.receiver_id < Message.sender_id, Message.receiver_id), else_=Message.sender_id)
    user2 = case((Message.receiver_id > Message.sender_id, Message.receiver_id), else_=Message.sender_id)
    subquery = db.session.query(user1.label('user1_id'), user2.label('user2_id'), db.func.max(Message.timestamp).label('max_timestamp')).filter(or_(Message.receiver_id == current_user_id, Message.sender_id == current_user_id)).group_by(user1, user2).subquery()
    conversations = db.session.query(Message.content, Message.timestamp, user1.label('user1_id'), user2.label('user2_id')).join(subquery, and_(Message.timestamp == subquery.c.max_timestamp, user1 == subquery.c.user1_id, user2 == subquery.c.user2_id)).all()

    formatted_conversations = []
    for conv in conversations:
        other_user_id = conv.user1_id if conv.user1_id != current_user_id else conv.user2_id
        other_user = User.query.get(other_user_id)
        formatted_conversations.append({'other_user_id': other_user.id, 'other_user_name': other_user.name, 'last_message_content': conv.content, 'last_message_timestamp': conv.timestamp})
    formatted_conversations.sort(key=lambda x: x['last_message_timestamp'], reverse=True)
    return render_template('inbox.html', conversations=formatted_conversations)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)