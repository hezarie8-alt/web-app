from flask import Flask, render_template, request, redirect, url_for, session, abort, flash 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_, and_

# 🔧 تنظیمات اولیه اپلیکیشن
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_and_long_random_string_that_is_hard_to_guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 🧑‍🎓 مدل کاربر
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    major = db.Column(db.String(100))
    grade = db.Column(db.String(50))
    password_hash = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Removed unique=True

# 💬 مدل پیام
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# 🧱 ساخت دیتابیس در صورت عدم وجود
with app.app_context():
    db.create_all()  # فقط جدول‌هایی که وجود ندارند ساخته می‌شوند

# --- مسیرهای اصلی (Public) ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

# --- مسیرهای احراز هویت ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_ip = request.remote_addr
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(
            name=request.form['name'],
            major=request.form['major'],
            grade=request.form['grade'],
            password_hash=hashed_password,
            ip_address=user_ip
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(name=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['current_user_id'] = user.id
            return redirect(url_for('match'))
        else:
            return render_template('login.html', error="نام کاربری یا رمز عبور اشتباه است.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('current_user_id', None)
    return redirect(url_for('login'))

# --- مسیرهای محافظت شده ---
@app.route('/match')
def match():
    q = request.args.get('q')
    if q:
        users = User.query.filter(
            (User.major.contains(q)) | (User.name.contains(q))
        ).all()
    else:
        users = User.query.all()
    return render_template('match.html', users=users)

@app.route('/profile')
def profile():
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    user = User.query.get(current_user_id)
    if not user:
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    user = User.query.get(current_user_id)
    if user:
        user.name = request.form['name']
        user.major = request.form['major']
        user.grade = request.form['grade']
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/update_password', methods=['POST'])
def update_password():
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    user = User.query.get(current_user_id)
    if user:
        if check_password_hash(user.password_hash, request.form['current_password']):
            new_hashed_password = generate_password_hash(request.form['new_password'], method='pbkdf2:sha256')
            user.password_hash = new_hashed_password
            db.session.commit()
        else:
            flash("رمز فعلی اشتباه است.", "error")
            return redirect(url_for('profile'))
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    user_to_delete = User.query.get(current_user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        session.pop('current_user_id', None)
    return redirect(url_for('register'))

# --- Chat ---
@app.route('/chat/<int:other_user_id>')
def chat(other_user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    other_user = User.query.get_or_404(other_user_id)
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
            and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', other_user=other_user, messages=messages)

@app.route('/send_chat_message/<int:other_user_id>', methods=['POST'])
def send_chat_message(other_user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))
    content = request.form['content']
    if content.strip():
        msg = Message(sender_id=current_user_id, receiver_id=other_user_id, content=content)
        db.session.add(msg)
        db.session.commit()
    return redirect(url_for('chat', other_user_id=other_user_id))

# --- Inbox simplified for SQLite ---
@app.route('/inbox/<int:user_id>')
def inbox(user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id or current_user_id != user_id:
        abort(403)
    messages = Message.query.filter(
        or_(Message.sender_id == current_user_id, Message.receiver_id == current_user_id)
    ).order_by(Message.timestamp.desc()).all()
    conversations = {}
    for msg in messages:
        other_id = msg.receiver_id if msg.sender_id == current_user_id else msg.sender_id
        if other_id not in conversations:
            conversations[other_id] = msg
    formatted_conversations = []
    for other_id, msg in conversations.items():
        other_user = User.query.get(other_id)
        formatted_conversations.append({
            'other_user_id': other_user.id,
            'other_user_name': other_user.name,
            'last_message_content': msg.content,
            'last_message_timestamp': msg.timestamp
        })
    formatted_conversations.sort(key=lambda x: x['last_message_timestamp'], reverse=True)
    return render_template('inbox.html', conversations=formatted_conversations)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
