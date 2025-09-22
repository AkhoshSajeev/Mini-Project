from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from werkzeug.utils import secure_filename
from flask import request
import os

app = Flask(__name__)
app.secret_key = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hub.db'
db = SQLAlchemy(app)

ROLE_CREATOR = 'creator'
ROLE_COMPANY = 'company'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    bio = db.Column(db.Text, default='')
    profile_pic = db.Column(db.String(200), default='')

    ideas = db.relationship('Idea', backref='creator', lazy=True)


class Idea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class CollaborationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'))
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    accepted = db.Column(db.Boolean, default=False)
    idea = db.relationship('Idea', backref='collab_requests')
    company = db.relationship('User', foreign_keys=[company_id])


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')



@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    other_user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        msg = request.form['message']
        if msg.strip():
            new_msg = ChatMessage(sender_id=current_user_id, receiver_id=other_user.id, message=msg)
            db.session.add(new_msg)
            db.session.commit()
        return redirect(url_for('chat', user_id=user_id))

    # Get all messages between current user & other user
    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user_id) & (ChatMessage.receiver_id == other_user.id)) |
        ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == current_user_id))
    ).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('chat.html', messages=messages, other_user=other_user)



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        

        user = User.query.filter_by(username=username, role=role).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for(f"{role}_dashboard"))
        flash('Invalid credentials.')
    return render_template('login.html')


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'admin':
            session['user_id'] = 'admin'
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid admin credentials.')  # Show flash message

    # ✅ This line ensures there is always a return
    return render_template('admin_login.html')

@app.route('/admin/delete_creator/<int:id>', methods=['POST'])
def delete_creator(id):
    user = User.query.get_or_404(id)
    if user.role == 'creator':
        db.session.delete(user)
        db.session.commit()
        flash('Creator deleted successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_company/<int:id>', methods=['POST'])
def delete_company(id):
    user = User.query.get_or_404(id)
    if user.role == 'company':
        db.session.delete(user)
        db.session.commit()
        flash('Company deleted successfully.')
    return redirect(url_for('admin_dashboard'))



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/creator/dashboard', methods=['GET', 'POST'])
def creator_dashboard():
    if session.get('role') != ROLE_CREATOR:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        idea = Idea(title=title, description=description, creator_id=session['user_id'])
        db.session.add(idea)
        db.session.commit()
    ideas = Idea.query.filter_by(creator_id=session['user_id']).all()
    requests = CollaborationRequest.query.all()
    return render_template('creator_dashboard.html', ideas=ideas, requests=requests)


@app.route('/creator/accept/<int:req_id>')
def accept_request(req_id):
    if session.get('role') != ROLE_CREATOR:
        return redirect(url_for('login'))
    collab = CollaborationRequest.query.get(req_id)
    if collab:
        collab.accepted = True
        db.session.commit()
    return redirect(url_for('creator_dashboard'))






@app.route('/company/dashboard')
def company_dashboard():
    if session.get('role') != 'company':
        return redirect('/login')

    ideas = Idea.query.all()
    requests = CollaborationRequest.query.filter_by(company_id=session['user_id']).all()

    return render_template('company_dashboard.html', ideas=ideas, requests=requests)




@app.route('/company/request/<int:idea_id>')
def send_request(idea_id):
    if session.get('role') != ROLE_COMPANY:
        return redirect(url_for('login'))
    exists = CollaborationRequest.query.filter_by(idea_id=idea_id, company_id=session['user_id']).first()
    if not exists:
        req = CollaborationRequest(idea_id=idea_id, company_id=session['user_id'])
        db.session.add(req)
        db.session.commit()
    return redirect(url_for('company_dashboard'))


@app.route('/admin')
def admin_dashboard():
    if session.get('user_id') != 'admin':
        return redirect(url_for('admin_login'))
    users = User.query.all()
    ideas = Idea.query.all()
    requests = CollaborationRequest.query.all()
    return render_template('admin_dashboard.html', users=users, ideas=ideas, requests=requests)

@app.route('/creator/profile/<int:creator_id>')
def creator_profile(creator_id):
    profile = User.query.filter_by(id=creator_id, role='creator').first()
    if profile:
        return render_template('creator_profile.html', profile=profile)
    else:
        return "Creator not found", 404


@app.route('/creator/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    creator_id = session.get('creator_id')
    if not creator_id:
        return redirect(url_for('creator_login'))

    if request.method == 'POST':
        bio = request.form['bio']
        profile_pic = request.files['profile_pic']
        pic_filename = None

        if profile_pic and profile_pic.filename != '':
            pic_filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join('static/uploads', pic_filename))

        conn = sqlite3.connect('your_db.db')
        cursor = conn.cursor()
        if pic_filename:
            cursor.execute("UPDATE creators SET bio = ?, profile_pic = ? WHERE id = ?", (bio, pic_filename, creator_id))
        else:
            cursor.execute("UPDATE creators SET bio = ? WHERE id = ?", (bio, creator_id))
        conn.commit()
        conn.close()

        return redirect(url_for('creator_profile', creator_id=creator_id))

    conn = sqlite3.connect('your_db.db')
    cursor = conn.cursor()
    cursor.execute("SELECT bio FROM creators WHERE id = ?", (creator_id,))
    result = cursor.fetchone()
    conn.close()

    current_bio = result[0] if result else ''

    return render_template('edit_creator_profile.html', current_bio=current_bio)


@app.route('/creator/post', methods=['GET', 'POST'])
def post_idea():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        creator_id = session['user_id']  # Important

        idea = Idea(title=title, description=description, creator_id=creator_id)
        db.session.add(idea)
        db.session.commit()
        return redirect('/creator/dashboard')

    return render_template('post_idea.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
