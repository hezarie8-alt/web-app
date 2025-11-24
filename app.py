import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, text
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError

# --- تنظیمات اولیه اپلیکیشن ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development')

database_url = os.getenv("DATABASE_URL")
if not database_url:
    basedir = os.path.abspath(os.path.dirname(__file__))
    database_url = 'sqlite:///' + os.path.join(basedir, 'app.db')
    print(f"WARNING: DATABASE_URL not set. Using local SQLite database: {database_url}")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- مقداردهی اولیه به افزونه‌ها ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*")

online_users = {}

# --- توابع کمکی و دکوراتورها ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            flash('برای دسترسی به این صفحه باید وارد شوید.', 'info')
            return redirect(url_for('show_auth_page'))
        return f(*args, **kwargs)
    return decorated_function

def is_user_online(user_id):
    return user_id in online_users

@app.context_processor
def inject_user():
    """این تابع متغیر 'current_user' را در تمام قالب‌های جینجا در دسترس قرار می‌دهد."""
    if 'current_user_id' in session and session['current_user_id']:
        current_user = User.query.get(session['current_user_id'])
        return dict(current_user=current_user)
    return dict(current_user=None)

# --- توابع به‌روزرسانی ساختار دیتابیس ---
def ensure_columns():
    """ستون‌های مورد نیاز را به جداول اضافه می‌کند. این تابع ایمن است و در صورت وجود ستون خطایی ایجاد نمی‌کند."""
    try:
        # اضافه کردن ستون created_at به جدول user
        user_table_sql = text("""
            ALTER TABLE IF EXISTS "user"
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now();
        """)
        
        # اضافه کردن ستون read_at به جدول message
        message_table_sql = text("""
            ALTER TABLE IF EXISTS "message"
            ADD COLUMN IF NOT EXISTS read_at TIMESTAMP WITH TIME ZONE;
        """)
        
        with db.engine.connect() as conn:
            conn.execute(user_table_sql)
            conn.execute(message_table_sql)
        db.session.commit()
        print("Database columns verified/added successfully")
    except SQLAlchemyError as e:
        print("ensure_columns: failed:", str(e))
        try:
            db.session.rollback()
        except:
            pass

# --- مدل‌های دیتابیس ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    major = db.Column(db.String(100))
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    read_at = db.Column(db.DateTime, nullable=True)

# --- فرم‌های WTForms ---
MAJOR_CHOICES = [('', '     رشته خود را انتخاب کنید'), ('     مهندسی کامپیوتر', '     مهندسی کامپیوتر'), ('     علوم کامپیوتر', '     علوم کامپیوتر')]

class RegistrationForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100)])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES, validators=[DataRequired()])
    password = PasswordField('رمز عبور', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('ثبت‌نام')
    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('این نام کاربری قبلاً استفاده شده است.')

class LoginForm(FlaskForm):
    username = StringField('نام کاربری', validators=[DataRequired()])
    password = PasswordField('رمز عبور', validators=[DataRequired()])
    remember_me = BooleanField('مرا به خاطر بسپار')
    submit = SubmitField('ورود')

class MessageForm(FlaskForm):
    content = TextAreaField('متن پیام', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField('ارسال پیام')

class UpdateProfileForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100)])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES)
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

# --- مسیرهای اصلی (Routes) ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/auth')
def show_auth_page():
    if session.get('current_user_id'):
        return redirect(url_for('match'))
    form = RegistrationForm()
    login_form = LoginForm()
    return render_template('register.html', form=form, login_form=login_form)

@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm()
    login_form = LoginForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            name=form.name.data,
            major=form.major.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        # اصلاح: استفاده از current_user_id برای یکپارچگی
        session['current_user_id'] = new_user.id

        flash('ثبت‌نام موفقیت‌آمیز بود. وارد شدید!', 'success')
        return redirect(url_for('match'))

    return render_template('register.html', form=form, login_form=login_form)

@app.route('/login', methods=['POST'])
def login():
    login_form = LoginForm()
    form = RegistrationForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(name=login_form.username.data).first()
        if user and check_password_hash(user.password_hash, login_form.password.data):
            session['current_user_id'] = user.id
            return redirect(url_for('match'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است.', 'error')
    return render_template('register.html', form=form, login_form=login_form)

@app.route('/logout')
@login_required # اصلاح: اضافه شدن دکوراتور برای امنیت
def logout():
    session.pop('current_user_id', None)
    flash('شما با موفقیت از حساب کاربری خود خارج شدید.', 'info')
    return redirect(url_for('show_auth_page'))

@app.route('/match')
@login_required
def match():
    # اصلاح: استفاده از current_user_id
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect('/auth')
    current_user = User.query.get(current_user_id)
    query = User.query.filter(User.id != current_user_id)
    q = request.args.get('q', '')
    if q:
        users = query.filter((User.major.contains(q)) | (User.name.contains(q))).all()
    else:
        users = query.all()
    return render_template(
    'match.html',
    users=users,
    current_user_id=current_user_id,
    current_user=current_user
)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect('/auth')
    
    user = User.query.get_or_404(user_id)
    
    # اصلاح: تعیین اینکه آیا کاربر می‌تواند پروفایل را ویرایش کند یا خیر
    can_edit = (current_user_id == user_id)
    
    update_profile_form = UpdateProfileForm(obj=user, original_username=user.name) if can_edit else None
    update_password_form = UpdatePasswordForm() if can_edit else None
    delete_account_form = DeleteAccountForm() if can_edit else None
    
    return render_template('profile.html', 
    user=user,
    user_id=user.id,
    can_edit=can_edit,
    update_profile_form=update_profile_form,
    update_password_form=update_password_form,
    delete_account_form=delete_account_form
)

@app.route('/update_profile/<int:user_id>', methods=['POST'])
@login_required
def update_profile(user_id):
    current_user_id = session.get('current_user_id')
    if current_user_id != user_id:
        abort(403)

    user = User.query.get_or_404(user_id)
    form = UpdateProfileForm(obj=user, original_username=user.name)
    if form.validate_on_submit():
        user.name = form.name.data
        user.major = form.major.data
        db.session.commit()
        flash('پروفایل شما با موفقیت بروزرسانی شد.', 'success')
    return redirect(url_for('profile', user_id=user_id))

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
    return redirect(url_for('profile', user_id=current_user_id))

@app.route('/delete_account/<int:user_id>', methods=['POST'])
@login_required
def delete_account(user_id):
    current_user_id = session.get('current_user_id')
    if current_user_id != user_id:
        abort(403)
        
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    session.pop('current_user_id', None)
    flash('حساب کاربری شما حذف شد.', 'info')
    return redirect(url_for('show_auth_page'))

@app.route('/chat/<int:other_user_id>')
@login_required
def chat(other_user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect('/auth')
    
    if current_user_id == other_user_id:
        return redirect(url_for('inbox', user_id=current_user_id))

    other_user = User.query.get_or_404(other_user_id)

    # بهینه‌سازی: فقط پیام‌های خوانده نشده را به عنوان خوانده شده علامت‌گذاری کن
    unread_messages = Message.query.filter(
        and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id, Message.read_at.is_(None))
    ).all()
    for msg in unread_messages:
        msg.read_at = db.func.now()
    db.session.commit()

    # بهینه‌سازی: فقط ۵۰ پیام آخر را بارگذاری کن تا صفحه سریع باز شود
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
            and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.timestamp.desc()).limit(50).all()
    
    # چون پیام‌ها را به ترتیب نزولی گرفتیم، باید ترتیب را برای نمایش صحیح برگردانیم
    messages.reverse()
    
    message_form = MessageForm()
    
    return render_template('chat.html', other_user=other_user, messages=messages, message_form=message_form)

# این مسیر دیگر نیازی نیست چون ارسال کاملاً از طریق Socket.IO انجام می‌شود
# @app.route('/send_message/<int:other_user_id>', methods=['POST'])
# ...

@app.route('/inbox/<int:user_id>')
@login_required
def inbox(user_id):
    current_user_id = session.get('current_user_id')
    if current_user_id != user_id:
        abort(403)

    sent_to_users = db.session.query(Message.receiver_id).filter(Message.sender_id == current_user_id).distinct()
    received_from_users = db.session.query(Message.sender_id).filter(Message.receiver_id == current_user_id).distinct()
    other_users_ids = sent_to_users.union(received_from_users).all()
    other_users_ids = [id for (id,) in other_users_ids]

    conversations = []
    for other_user_id in other_users_ids:
        last_message = Message.query.filter(or_(and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id), and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id))).order_by(Message.timestamp.desc()).first()
        if last_message:
            other_user = User.query.get(other_user_id)
            unread_count = Message.query.filter(and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id, Message.read_at.is_(None))).count()
            conversations.append({
                'other_user_id': other_user.id,
                'other_user_name': other_user.name,
                'last_message_content': last_message.content,
                'last_message_timestamp': last_message.timestamp,
                'has_unread': unread_count > 0
            })
    
    conversations.sort(key=lambda x: x['last_message_timestamp'], reverse=True)
    return render_template('inbox.html', conversations=conversations, user_id=user_id)

@app.route('/is_user_online/<int:user_id>')
def check_user_online(user_id):
    return jsonify({'online': is_user_online(user_id)})

# --- رویدادهای Socket.IO ---
@socketio.on('connect')
def handle_connect():
    current_user_id = session.get('current_user_id')
    if current_user_id:
        online_users[current_user_id] = True
        print(f'Client {current_user_id} connected')

@socketio.on('disconnect')
def handle_disconnect():
    current_user_id = session.get('current_user_id')
    if current_user_id and current_user_id in online_users:
        del online_users[current_user_id]
        print(f'Client {current_user_id} disconnected')

@socketio.on('join_chat')
def handle_join_chat(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return
    other_user_id = data['other_user_id']
    room_id = f"chat-{min(current_user_id, other_user_id)}-{max(current_user_id, other_user_id)}"
    join_room(room_id)
    user = User.query.get(current_user_id)
    emit('status_message', {'msg': f"{user.name} به گفتگو پیوست.", 'type': 'join'}, room=room_id, include_self=False)

@socketio.on('send_message')
def handle_send_message(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return

    other_user_id = data.get('other_user_id')
    content = data.get('content')
    if not other_user_id or not content: return

    room_id = f"chat-{min(current_user_id, other_user_id)}-{max(current_user_id, other_user_id)}"
    msg = Message(sender_id=current_user_id, receiver_id=other_user_id, content=content)
    db.session.add(msg)
    db.session.commit()
    
    user = User.query.get(current_user_id)
    # بهینه‌سازی: پیام را برای خود ارسال‌کننده ارسال نکن تا از تکرار جلوگیری شود
    emit('new_message', {
        'sender_name': user.name,
        'content': content,
        'timestamp': msg.timestamp.strftime('%H:%M'),
        'sender_id': current_user_id,
        'message_id': msg.id
    }, room=room_id, include_self=False)

@socketio.on('typing')
def handle_typing(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return
    
    room = data.get('room')
    if room:
        emit('typing', {'user_id': current_user_id}, room=room, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return
    
    room = data.get('room')
    if room:
        emit('stop_typing', {'user_id': current_user_id}, room=room, include_self=False)

# --- اجرای اپلیکیشن ---
if __name__ == '__main__':
    with app.app_context():
        # اطمینان از وجود ستون‌های مورد نیاز در دیتابیس
        ensure_columns()
        # ایجاد جداول در صورت عدم وجود
        db.create_all()

    port = int(os.environ.get('PORT', 5000))
    # استفاده از socketio.run برای پشتیبانی از WebSocket
    socketio.run(app, host='0.0.0.0', port=port)