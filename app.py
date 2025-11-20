from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_, and_, case

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
    # ✨ MODIFIED: Name must now be unique
    name = db.Column(db.String(100), nullable=False, unique=True)
    major = db.Column(db.String(100))
    grade = db.Column(db.String(50))
    password_hash = db.Column(db.String(128), nullable=False)
    # ✨ REMOVED: ip_address field is no longer needed for this logic
    # ip_address = db.Column(db.String(45), nullable=False, unique=True)

# 💬 مدل پیام
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# --- مسیرهای اصلی (Public) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

# --- مسیرهای احراز هویت (Authentication) ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # ✨ MODIFIED: Check if a user with this NAME already exists
        existing_user = User.query.filter_by(name=request.form['name']).first()
        
        if existing_user:
            # If user exists, show an error message and redirect to register page
            flash('این نام کاربری قبلاً استفاده شده است. لطفاً نام دیگری انتخاب کنید.', 'error')
            return redirect(url_for('register'))
        
        # If user doesn't exist, proceed with registration
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(
            name=request.form['name'],
            major=request.form['major'],
            grade=request.form['grade'],
            password_hash=hashed_password
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

# --- مسیرهای محافظت شده (Protected) ---

@app.route('/match')
def match():
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))

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
        # ✨ MODIFIED: Check if the new name is taken by another user
        new_name = request.form['name']
        if new_name != user.name:
            existing_user = User.query.filter_by(name=new_name).first()
            if existing_user:
                flash('نام کاربری جدید توسط شخص دیگری استفاده شده است.', 'error')
                return redirect(url_for('profile'))

        user.name = new_name
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
    if user and check_password_hash(user.password_hash, request.form['current_password']):
        new_hashed_password = generate_password_hash(request.form['new_password'], method='pbkdf2:sha256')
        user.password_hash = new_hashed_password
        db.session.commit()
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

# ✨ NEW: Chat page to view conversation with a specific user
@app.route('/chat/<int:other_user_id>')
def chat(other_user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))

    other_user = User.query.get_or_404(other_user_id)
    
    # Fetch all messages between two users
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
            and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', other_user=other_user, messages=messages)

# ✨ NEW: Route to send a message from the chat page
@app.route('/send_chat_message/<int:other_user_id>', methods=['POST'])
def send_chat_message(other_user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id:
        return redirect(url_for('login'))

    content = request.form['content']
    if content:
        msg = Message(sender_id=current_user_id, receiver_id=other_user_id, content=content)
        db.session.add(msg)
        db.session.commit()
    
    # Redirect back to the chat page
    return redirect(url_for('chat', other_user_id=other_user_id))

# ✨ MODIFIED: Inbox now shows a list of conversations
@app.route('/inbox/<int:user_id>')
def inbox(user_id):
    current_user_id = session.get('current_user_id')
    if not current_user_id or current_user_id != user_id:
        abort(403) # Forbidden

    # Create SQLite-safe least/greatest expressions
    user1 = case(
        (Message.receiver_id < Message.sender_id, Message.receiver_id),
        else_=Message.sender_id
    )
    user2 = case(
        (Message.receiver_id > Message.sender_id, Message.receiver_id),
        else_=Message.sender_id
    )

    # Subquery to find latest message per conversation
    subquery = db.session.query(
        user1.label('user1_id'),
        user2.label('user2_id'),
        db.func.max(Message.timestamp).label('max_timestamp')
    ).filter(
        or_(Message.receiver_id == current_user_id, Message.sender_id == current_user_id)
    ).group_by(
        user1, user2
    ).subquery()

    conversations = db.session.query(
        Message.content,
        Message.timestamp,
        user1.label('user1_id'),
        user2.label('user2_id')
    ).join(
        subquery,
        and_(
            Message.timestamp == subquery.c.max_timestamp,
            user1 == subquery.c.user1_id,
            user2 == subquery.c.user2_id
        )
    ).all()
    
    # Format data for the template
    formatted_conversations = []
    for conv in conversations:
        other_user_id = conv.user1_id if conv.user1_id != current_user_id else conv.user2_id
        other_user = User.query.get(other_user_id)
        formatted_conversations.append({
            'other_user_id': other_user.id,
            'other_user_name': other_user.name,
            'last_message_content': conv.content,
            'last_message_timestamp': conv.timestamp
        })

    # Sort conversations by the latest message time
    formatted_conversations.sort(key=lambda x: x['last_message_timestamp'], reverse=True)

    return render_template('inbox.html', conversations=formatted_conversations)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)