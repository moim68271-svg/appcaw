# caw_app.py - تطبيق CAW سطح المكتب (نسخة كاملة)

import os
import json
import secrets
import time
import threading
import sys
import webbrowser
from datetime import datetime
from functools import wraps
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import customtkinter as ctk

# إعدادات المظهر
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# استيراد Flask
from flask import Flask, request, session, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageTk
import requests
import threading
import queue

# ===================================================================
# خادم Flask (يعمل في خلفية التطبيق)
# ===================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MINI_PIC_FOLDER'] = 'static/mini_pics'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('static/mini_pics', exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ===================================================================
# ملفات البيانات
# ===================================================================

FILES = {
    'users': 'data/users.json',
    'posts': 'data/posts.json',
    'reels': 'data/reels.json',
    'likes': 'data/likes.json',
    'comments': 'data/comments.json',
    'friends': 'data/friends.json',
    'messages': 'data/messages.json',
    'group_chats': 'data/group_chats.json',
    'notifications': 'data/notifications.json'
}

for file_path in FILES.values():
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)

def read_json(name):
    with open(FILES[name], 'r', encoding='utf-8') as f:
        return json.load(f)

def write_json(name, data):
    with open(FILES[name], 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_next_id(name):
    data = read_json(name)
    return max([d['id'] for d in data]) + 1 if data else 1

def get_user(user_id):
    users = read_json('users')
    for u in users:
        if u['id'] == user_id:
            return u
    return None

def get_user_by_username(username):
    users = read_json('users')
    for u in users:
        if u['username'] == username:
            return u
    return None

def get_profile_pic(user):
    if user and user.get('profile_pic') and user['profile_pic'] not in ['default.jpg', 'default_profile.jpg']:
        return user['profile_pic']
    return 'default_profile.jpg'

def get_display_name(user):
    if not user:
        return ''
    return user.get('display_name', user.get('username', ''))

def safe_text(text):
    if not text:
        return ''
    return str(text).replace('\n', '<br>')

# ===================================================================
# نظام الحماية
# ===================================================================

class InvisibleProtection:
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked_ips = set()
        self.whitelist = set()
        self.lock = threading.Lock()
        self.is_under_attack = False
    
    def check_request(self, ip):
        return True  # مبسط للتطبيق المحلي
    
    def get_stats(self):
        return {'blocked_ips': 0, 'suspicious_ips': 0, 'whitelisted_ips': 1, 'is_under_attack': False}

protection = InvisibleProtection()

# ===================================================================
# نظام الحظر
# ===================================================================

class BlockSystem:
    def __init__(self):
        self.blocks_file = 'data/blocks.json'
        if not os.path.exists(self.blocks_file):
            with open(self.blocks_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
    
    def get_blocks(self):
        with open(self.blocks_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def save_blocks(self, blocks):
        with open(self.blocks_file, 'w', encoding='utf-8') as f:
            json.dump(blocks, f, ensure_ascii=False, indent=2)
    
    def is_blocked(self, user_id, target_id):
        if user_id == target_id:
            return False
        blocks = self.get_blocks()
        for b in blocks:
            if (b['blocker_id'] == user_id and b['blocked_id'] == target_id) or \
               (b['blocker_id'] == target_id and b['blocked_id'] == user_id):
                return True
        return False
    
    def get_blocked_users(self, user_id):
        blocks = self.get_blocks()
        blocked = []
        for b in blocks:
            if b['blocker_id'] == user_id:
                blocked.append(b['blocked_id'])
            if b['blocked_id'] == user_id:
                blocked.append(b['blocker_id'])
        return list(set(blocked))
    
    def block_user(self, blocker_id, blocked_id):
        if blocker_id == blocked_id:
            return False
        blocks = self.get_blocks()
        for b in blocks:
            if b['blocker_id'] == blocker_id and b['blocked_id'] == blocked_id:
                return False
        friends = read_json('friends')
        friends = [f for f in friends if not (
            (f['from_user_id'] == blocker_id and f['to_user_id'] == blocked_id) or
            (f['from_user_id'] == blocked_id and f['to_user_id'] == blocker_id)
        )]
        write_json('friends', friends)
        blocks.append({
            'id': len(blocks) + 1,
            'blocker_id': blocker_id,
            'blocked_id': blocked_id,
            'created_at': datetime.utcnow().isoformat()
        })
        self.save_blocks(blocks)
        return True
    
    def unblock_user(self, blocker_id, blocked_id):
        blocks = self.get_blocks()
        blocks = [b for b in blocks if not (
            b['blocker_id'] == blocker_id and b['blocked_id'] == blocked_id
        )]
        self.save_blocks(blocks)
        return True

block_system = BlockSystem()

def get_blocked_user_ids(user_id):
    return block_system.get_blocked_users(user_id)

def is_user_blocked(user_id, target_id):
    return block_system.is_blocked(user_id, target_id)

# ===================================================================
# نظام الإبلاغ
# ===================================================================

class ReportSystem:
    REPORT_REASONS = [
        'حساب وهمي أو منتحل شخصية',
        'تحرش أو مضايقة',
        'خطاب كراهية',
        'عنف أو محتوى صادم',
        'استغلال أو تعريض قاصر للخطر',
        'ترويج لمواد أو أنشطة غير قانونية',
        'رسائل مزعجة أو سبام',
        'انتهاك حقوق الملكية',
        'معلومات مضللة',
        'سبب آخر'
    ]
    
    def __init__(self):
        self.reports_file = 'data/reports.json'
        if not os.path.exists(self.reports_file):
            with open(self.reports_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
    
    def get_reports(self):
        with open(self.reports_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def save_reports(self, reports):
        with open(self.reports_file, 'w', encoding='utf-8') as f:
            json.dump(reports, f, ensure_ascii=False, indent=2)
    
    def add_report(self, reporter_id, target_id, target_type, reason, content_id=None):
        reports = self.get_reports()
        for r in reports:
            if r['reporter_id'] == reporter_id and r['target_id'] == target_id and \
               r['target_type'] == target_type and r.get('content_id') == content_id:
                return False
        reports.append({
            'id': len(reports) + 1,
            'reporter_id': reporter_id,
            'target_id': target_id,
            'target_type': target_type,
            'content_id': content_id,
            'reason': reason,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        })
        self.save_reports(reports)
        return True

report_system = ReportSystem()

# ===================================================================
# دوال مساعدة Flask
# ===================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'غير مسجل دخول'}), 401
        return f(*args, **kwargs)
    return decorated

def developer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'غير مسجل دخول'}), 401
        user = get_user(session['user_id'])
        if not user or not user.get('is_developer', False):
            return jsonify({'error': 'غير مصرح'}), 403
        return f(*args, **kwargs)
    return decorated

def save_image(file, prefix):
    if file and file.filename:
        filename = secure_filename(prefix + '_' + str(int(datetime.utcnow().timestamp())) + '.jpg')
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

def save_video(file):
    if file and file.filename:
        filename = secure_filename('reel_' + str(int(datetime.utcnow().timestamp())) + '.mp4')
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

def save_mini_pic(file, user_id):
    if file and file.filename:
        filename = secure_filename(f'mini_{user_id}_{int(datetime.utcnow().timestamp())}.jpg')
        file.save(os.path.join(app.config['MINI_PIC_FOLDER'], filename))
        return filename
    return None

def add_notification(user_id, message, link=None, type='info'):
    notifications = read_json('notifications')
    notifications.append({
        'id': get_next_id('notifications'),
        'user_id': user_id,
        'message': message,
        'link': link,
        'type': type,
        'is_read': False,
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('notifications', notifications)

def get_unread_notifications_count(user_id):
    notifications = read_json('notifications')
    return len([n for n in notifications if n['user_id'] == user_id and not n.get('is_read', False)])

def get_user_notifications(user_id):
    notifications = read_json('notifications')
    user_notifications = [n for n in notifications if n['user_id'] == user_id]
    user_notifications.sort(key=lambda x: x['created_at'], reverse=True)
    return user_notifications

def mark_notifications_read(user_id):
    notifications = read_json('notifications')
    for n in notifications:
        if n['user_id'] == user_id:
            n['is_read'] = True
    write_json('notifications', notifications)

def render_user_display(user, size='normal'):
    if not user:
        return ''
    display_name = get_display_name(user)
    verified = '✓' if user.get('is_verified', False) else ''
    dev = '👑' if user.get('is_developer', False) else ''
    return f'{display_name} {verified} {dev}'

# ===================================================================
# مسارات Flask API
# ===================================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').upper()
    password = data.get('password', '')
    
    if username == 'MBL' and password == 'MBL':
        user = get_user_by_username('MBL')
        if not user:
            users = read_json('users')
            new_id = get_next_id('users')
            user = {
                'id': new_id,
                'username': 'MBL',
                'password': generate_password_hash('MBL'),
                'display_name': 'المطور الرئيسي',
                'is_verified': True,
                'is_developer': True,
                'mini_pic_enabled': True,
                'mini_pic': None,
                'bio': 'المطور الرئيسي',
                'profile_pic': 'default_profile.jpg',
                'created_at': datetime.utcnow().isoformat()
            }
            users.append(user)
            write_json('users', users)
        session['user_id'] = user['id']
        return jsonify({'success': True, 'user': user})
    
    if username == 'MBLL' and password == 'MBMB':
        user = get_user_by_username('MBLL')
        if not user:
            users = read_json('users')
            new_id = get_next_id('users')
            user = {
                'id': new_id,
                'username': 'MBLL',
                'password': generate_password_hash('MBMB'),
                'display_name': 'المطور الثاني',
                'is_verified': True,
                'is_developer': True,
                'mini_pic_enabled': True,
                'mini_pic': None,
                'bio': 'المطور الثاني',
                'profile_pic': 'default_profile.jpg',
                'created_at': datetime.utcnow().isoformat()
            }
            users.append(user)
            write_json('users', users)
        session['user_id'] = user['id']
        return jsonify({'success': True, 'user': user})
    
    user = get_user_by_username(username)
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        return jsonify({'success': True, 'user': user})
    
    return jsonify({'success': False, 'error': 'اسم المستخدم أو كلمة السر غير صحيحة'})

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').upper()
    password = data.get('password', '')
    display_name = data.get('display_name', '').strip()
    bio = data.get('bio', '')
    
    if not username.isalnum():
        return jsonify({'success': False, 'error': 'اسم المستخدم يجب أن يحتوي على أحرف وأرقام فقط'})
    
    if username in ['MBL', 'MBLL']:
        return jsonify({'success': False, 'error': 'هذا الاسم محجوز'})
    
    if get_user_by_username(username):
        return jsonify({'success': False, 'error': 'اسم المستخدم موجود'})
    
    if not display_name:
        display_name = username
    
    users = read_json('users')
    new_id = get_next_id('users')
    user = {
        'id': new_id,
        'username': username,
        'password': generate_password_hash(password),
        'display_name': display_name,
        'is_verified': False,
        'is_developer': False,
        'mini_pic_enabled': False,
        'mini_pic': None,
        'bio': bio,
        'profile_pic': 'default_profile.jpg',
        'created_at': datetime.utcnow().isoformat()
    }
    users.append(user)
    write_json('users', users)
    return jsonify({'success': True, 'user': user})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>')
def api_get_user(user_id):
    user = get_user(user_id)
    if not user:
        return jsonify({'error': 'مستخدم غير موجود'}), 404
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'display_name': get_display_name(user),
        'bio': user.get('bio', ''),
        'profile_pic': get_profile_pic(user),
        'is_verified': user.get('is_verified', False),
        'is_developer': user.get('is_developer', False),
        'mini_pic': user.get('mini_pic') if user.get('mini_pic_enabled', False) else None
    })

@app.route('/api/posts')
@login_required
def api_get_posts():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    posts = read_json('posts')
    posts = [p for p in posts if p['user_id'] not in blocked_ids]
    posts.reverse()
    
    result = []
    for p in posts:
        author = get_user(p['user_id'])
        if author:
            likes = read_json('likes')
            likes_count = len([l for l in likes if l.get('post_id') == p['id']])
            user_liked = any(l.get('user_id') == session['user_id'] and l.get('post_id') == p['id'] for l in likes)
            
            comments = [c for c in read_json('comments') if c.get('post_id') == p['id'] and c['user_id'] not in blocked_ids]
            
            result.append({
                'id': p['id'],
                'content': p['content'],
                'image': p.get('image'),
                'user_id': p['user_id'],
                'username': author['username'],
                'display_name': get_display_name(author),
                'profile_pic': get_profile_pic(author),
                'is_verified': author.get('is_verified', False),
                'is_developer': author.get('is_developer', False),
                'likes': likes_count,
                'user_liked': user_liked,
                'comments_count': len(comments),
                'comments': [{
                    'user_id': c['user_id'],
                    'username': get_user(c['user_id'])['username'] if get_user(c['user_id']) else '',
                    'display_name': get_display_name(get_user(c['user_id'])) if get_user(c['user_id']) else '',
                    'content': c['content'],
                    'image': c.get('image'),
                    'created_at': c['created_at'][:19]
                } for c in comments[-3:]],
                'created_at': p['created_at'][:19]
            })
    return jsonify(result)

@app.route('/api/create_post', methods=['POST'])
@login_required
def api_create_post():
    content = request.form.get('content', '')
    image = None
    if 'image' in request.files and request.files['image'].filename:
        image = save_image(request.files['image'], 'post')
    
    posts = read_json('posts')
    posts.append({
        'id': get_next_id('posts'),
        'content': content,
        'image': image,
        'user_id': session['user_id'],
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('posts', posts)
    return jsonify({'success': True})

@app.route('/api/delete_post/<int:post_id>', methods=['POST'])
@login_required
def api_delete_post(post_id):
    posts = read_json('posts')
    post_to_delete = None
    for p in posts:
        if p['id'] == post_id:
            post_to_delete = p
            break
    
    if not post_to_delete:
        return jsonify({'success': False, 'error': 'غير موجود'})
    
    if post_to_delete['user_id'] != session['user_id']:
        user = get_user(session['user_id'])
        if not user.get('is_developer', False):
            return jsonify({'success': False, 'error': 'غير مصرح'})
    
    posts = [p for p in posts if p['id'] != post_id]
    write_json('posts', posts)
    
    likes = read_json('likes')
    likes = [l for l in likes if l.get('post_id') != post_id]
    write_json('likes', likes)
    
    comments = read_json('comments')
    comments = [c for c in comments if c.get('post_id') != post_id]
    write_json('comments', comments)
    
    return jsonify({'success': True})

@app.route('/api/like_post/<int:post_id>', methods=['POST'])
@login_required
def api_like_post(post_id):
    likes = read_json('likes')
    existing = None
    for l in likes:
        if l.get('user_id') == session['user_id'] and l.get('post_id') == post_id:
            existing = l
            break
    
    if existing:
        likes.remove(existing)
        liked = False
    else:
        likes.append({'id': get_next_id('likes'), 'user_id': session['user_id'], 'post_id': post_id})
        liked = True
    write_json('likes', likes)
    likes_count = len([l for l in likes if l.get('post_id') == post_id])
    return jsonify({'liked': liked, 'likes': likes_count})

@app.route('/api/add_comment', methods=['POST'])
@login_required
def api_add_comment():
    content = request.form.get('content', '')
    post_id = request.form.get('post_id')
    image = None
    
    if 'image' in request.files and request.files['image'].filename:
        image = save_image(request.files['image'], 'comment')
    
    if not content and not image:
        return jsonify({'success': False, 'error': 'التعليق فارغ'})
    
    comments = read_json('comments')
    comments.append({
        'id': get_next_id('comments'),
        'content': content,
        'user_id': session['user_id'],
        'post_id': int(post_id),
        'image': image,
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('comments', comments)
    return jsonify({'success': True})

@app.route('/api/friends')
@login_required
def api_get_friends():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    all_friends = read_json('friends')
    accepted = []
    pending = []
    
    for f in all_friends:
        if f['to_user_id'] == session['user_id'] and f['status'] == 'pending':
            if f['from_user_id'] not in blocked_ids:
                pending.append(get_user(f['from_user_id']))
        elif f['from_user_id'] == session['user_id'] and f['status'] == 'accepted':
            if f['to_user_id'] not in blocked_ids:
                accepted.append(get_user(f['to_user_id']))
        elif f['to_user_id'] == session['user_id'] and f['status'] == 'accepted':
            if f['from_user_id'] not in blocked_ids:
                accepted.append(get_user(f['from_user_id']))
    
    return jsonify({
        'accepted': [{'id': u['id'], 'display_name': get_display_name(u), 'username': u['username'], 'profile_pic': get_profile_pic(u)} for u in accepted if u],
        'pending': [{'id': u['id'], 'display_name': get_display_name(u), 'username': u['username'], 'profile_pic': get_profile_pic(u)} for u in pending if u]
    })

@app.route('/api/send_friend_request/<int:user_id>', methods=['POST'])
@login_required
def api_send_friend_request(user_id):
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'لا يمكن اضافة نفسك'})
    if is_user_blocked(session['user_id'], user_id):
        return jsonify({'success': False, 'error': 'لا يمكن إرسال طلب'})
    
    friends = read_json('friends')
    existing = any((f['from_user_id'] == session['user_id'] and f['to_user_id'] == user_id) or 
                   (f['from_user_id'] == user_id and f['to_user_id'] == session['user_id']) for f in friends)
    
    if not existing:
        friends.append({
            'id': get_next_id('friends'),
            'from_user_id': session['user_id'],
            'to_user_id': user_id,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('friends', friends)
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'طلب موجود'})

@app.route('/api/accept_friend/<int:user_id>', methods=['POST'])
@login_required
def api_accept_friend(user_id):
    if is_user_blocked(session['user_id'], user_id):
        return jsonify({'success': False, 'error': 'لا يمكن قبول الطلب'})
    
    friends = read_json('friends')
    for f in friends:
        if f['from_user_id'] == user_id and f['to_user_id'] == session['user_id'] and f['status'] == 'pending':
            f['status'] = 'accepted'
            write_json('friends', friends)
            return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'لا يوجد طلب'})

@app.route('/api/block_user/<int:user_id>', methods=['POST'])
@login_required
def api_block_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'لا يمكن حظر نفسك'})
    success = block_system.block_user(session['user_id'], user_id)
    return jsonify({'success': success})

@app.route('/api/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def api_unblock_user(user_id):
    success = block_system.unblock_user(session['user_id'], user_id)
    return jsonify({'success': success})

@app.route('/api/search_users/<query>')
@login_required
def api_search_users(query):
    blocked_ids = get_blocked_user_ids(session['user_id'])
    users = read_json('users')
    friends = read_json('friends')
    
    friends_ids = []
    for f in friends:
        if f['from_user_id'] == session['user_id'] and f['status'] == 'accepted':
            friends_ids.append(f['to_user_id'])
        elif f['to_user_id'] == session['user_id'] and f['status'] == 'accepted':
            friends_ids.append(f['from_user_id'])
    
    results = []
    for u in users:
        if u['id'] == session['user_id']:
            continue
        if u['id'] in blocked_ids:
            continue
        if query.upper() in u['username']:
            results.append({
                'id': u['id'],
                'username': u['username'],
                'display_name': get_display_name(u),
                'profile_pic': get_profile_pic(u),
                'is_friend': u['id'] in friends_ids
            })
    return jsonify(results)

@app.route('/api/messages/<int:user_id>')
@login_required
def api_get_messages(user_id):
    all_messages = read_json('messages')
    chat_messages = []
    for msg in all_messages:
        if (msg['sender_id'] == session['user_id'] and msg['receiver_id'] == user_id) or \
           (msg['sender_id'] == user_id and msg['receiver_id'] == session['user_id']):
            chat_messages.append(msg)
            if msg['receiver_id'] == session['user_id'] and not msg['is_read']:
                msg['is_read'] = True
    write_json('messages', all_messages)
    chat_messages.sort(key=lambda x: x['created_at'])
    
    result = []
    for msg in chat_messages:
        sender = get_user(msg['sender_id'])
        result.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_name': get_display_name(sender) if sender else '',
            'content': msg['content'],
            'image': msg.get('image'),
            'is_sent': msg['sender_id'] == session['user_id'],
            'created_at': msg['created_at'][:19]
        })
    return jsonify(result)

@app.route('/api/send_message', methods=['POST'])
@login_required
def api_send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content', '')
    image = None
    
    if 'image' in request.files and request.files['image'].filename:
        image = save_image(request.files['image'], 'chat')
    
    if not content and not image:
        return jsonify({'success': False, 'error': 'الرسالة فارغة'})
    
    messages = read_json('messages')
    messages.append({
        'id': get_next_id('messages'),
        'sender_id': session['user_id'],
        'receiver_id': int(receiver_id),
        'content': content,
        'image': image,
        'is_read': False,
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('messages', messages)
    return jsonify({'success': True})

@app.route('/api/group_chats')
@login_required
def api_get_group_chats():
    all_chats = read_json('group_chats')
    my_chats = [c for c in all_chats if session['user_id'] in c.get('members', [])]
    return jsonify(my_chats)

@app.route('/api/create_group_chat', methods=['POST'])
@login_required
def api_create_group_chat():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'أدخل اسم الدردشة'})
    
    chats = read_json('group_chats')
    new_id = get_next_id('group_chats')
    chats.append({
        'id': new_id,
        'name': name,
        'description': data.get('description', ''),
        'created_by': session['user_id'],
        'members': [session['user_id']],
        'messages': [],
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('group_chats', chats)
    return jsonify({'success': True, 'id': new_id})

@app.route('/api/group_chat/<int:chat_id>')
@login_required
def api_get_group_chat(chat_id):
    chats = read_json('group_chats')
    chat = None
    for c in chats:
        if c['id'] == chat_id:
            chat = c
            break
    
    if not chat:
        return jsonify({'error': 'غير موجود'}), 404
    if session['user_id'] not in chat.get('members', []):
        return jsonify({'error': 'غير مصرح'}), 403
    
    return jsonify(chat)

@app.route('/api/send_group_message', methods=['POST'])
@login_required
def api_send_group_message():
    chat_id = request.form.get('chat_id')
    content = request.form.get('content', '')
    image = None
    
    if 'image' in request.files and request.files['image'].filename:
        image = save_image(request.files['image'], 'groupchat')
    
    if not content and not image:
        return jsonify({'success': False, 'error': 'الرسالة فارغة'})
    
    chats = read_json('group_chats')
    chat = None
    for c in chats:
        if c['id'] == int(chat_id):
            chat = c
            break
    
    if not chat:
        return jsonify({'success': False, 'error': 'الدردشة غير موجودة'})
    if session['user_id'] not in chat.get('members', []):
        return jsonify({'success': False, 'error': 'غير مصرح'})
    
    user = get_user(session['user_id'])
    chat['messages'].append({
        'id': len(chat['messages']) + 1,
        'sender_id': session['user_id'],
        'sender_name': get_display_name(user),
        'content': content,
        'image': image,
        'created_at': datetime.utcnow().isoformat()
    })
    write_json('group_chats', chats)
    return jsonify({'success': True})

@app.route('/api/add_member_to_group/<int:chat_id>', methods=['POST'])
@login_required
def api_add_member_to_group(chat_id):
    data = request.get_json()
    username = data.get('username', '').upper()
    
    chats = read_json('group_chats')
    chat = None
    for c in chats:
        if c['id'] == chat_id:
            chat = c
            break
    
    if not chat:
        return jsonify({'success': False, 'error': 'الدردشة غير موجودة'})
    
    user = get_user_by_username(username)
    if not user:
        return jsonify({'success': False, 'error': 'المستخدم غير موجود'})
    
    if user['id'] in chat.get('members', []):
        return jsonify({'success': False, 'error': 'المستخدم موجود بالفعل'})
    
    chat['members'].append(user['id'])
    write_json('group_chats', chats)
    return jsonify({'success': True})

@app.route('/api/notifications')
@login_required
def api_get_notifications():
    notifications = get_user_notifications(session['user_id'])
    mark_notifications_read(session['user_id'])
    return jsonify(notifications)

@app.route('/api/current_user')
def api_current_user():
    if 'user_id' in session:
        user = get_user(session['user_id'])
        if user:
            return jsonify({
                'id': user['id'],
                'username': user['username'],
                'display_name': get_display_name(user),
                'profile_pic': get_profile_pic(user),
                'is_developer': user.get('is_developer', False),
                'is_verified': user.get('is_verified', False)
            })
    return jsonify({'error': 'غير مسجل'}), 401

# ===================================================================
# خادم Flask في خلفية التطبيق
# ===================================================================

def run_flask():
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)

# ===================================================================
# واجهة التطبيق - customtkinter
# ===================================================================

class CAWApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # إعدادات النافذة
        self.title("CAW - تطبيق الدردشة")
        self.geometry("900x650")
        self.minsize(800, 600)
        
        # متغيرات الحالة
        self.current_user = None
        self.current_view = "home"
        self.current_chat_user = None
        self.current_group_chat = None
        
        # بدء خادم Flask في خلفية منفصلة
        self.flask_thread = threading.Thread(target=run_flask, daemon=True)
        self.flask_thread.start()
        
        # انتظار بدء الخادم
        time.sleep(1)
        
        # إنشاء الواجهة
        self.setup_ui()
        
        # التحقق من حالة تسجيل الدخول
        self.check_login_status()
    
    def setup_ui(self):
        """إنشاء واجهة التطبيق"""
        # الإطار الرئيسي
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # إنشاء الشاشات
        self.create_login_screen()
        self.create_register_screen()
        self.create_main_screen()
        
        # إظهار شاشة تسجيل الدخول افتراضياً
        self.show_screen("login")
    
    def create_login_screen(self):
        """شاشة تسجيل الدخول"""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        
        # العنوان
        title = ctk.CTkLabel(self.login_frame, text="CAW", font=("Arial", 40, "bold"), text_color="#1877f2")
        title.pack(pady=20)
        
        subtitle = ctk.CTkLabel(self.login_frame, text="Chat & Wellness", font=("Arial", 14))
        subtitle.pack(pady=(0, 20))
        
        # حقول الإدخال
        self.login_username = ctk.CTkEntry(self.login_frame, placeholder_text="اسم المستخدم", width=280, height=40)
        self.login_username.pack(pady=5)
        
        self.login_password = ctk.CTkEntry(self.login_frame, placeholder_text="كلمة السر", width=280, height=40, show="*")
        self.login_password.pack(pady=5)
        
        # زر تسجيل الدخول
        login_btn = ctk.CTkButton(self.login_frame, text="تسجيل الدخول", width=280, height=40, 
                                  command=self.do_login, fg_color="#1877f2")
        login_btn.pack(pady=10)
        
        # رابط التسجيل
        register_link = ctk.CTkButton(self.login_frame, text="انشاء حساب جديد", width=280, height=30,
                                      command=lambda: self.show_screen("register"), fg_color="transparent", 
                                      text_color="#1877f2", hover_color="#e8f0fe")
        register_link.pack(pady=5)
        
        # معلومات المطورين
        info = ctk.CTkLabel(self.login_frame, text="👑 MBL / MBL  |  MBLL / MBMB", font=("Arial", 11), text_color="#65676b")
        info.pack(pady=10)
    
    def create_register_screen(self):
        """شاشة التسجيل"""
        self.register_frame = ctk.CTkFrame(self.main_frame)
        
        # العنوان
        title = ctk.CTkLabel(self.register_frame, text="انشاء حساب جديد", font=("Arial", 24, "bold"))
        title.pack(pady=15)
        
        # حقول الإدخال
        self.register_username = ctk.CTkEntry(self.register_frame, placeholder_text="اسم المستخدم", width=280, height=40)
        self.register_username.pack(pady=5)
        
        self.register_display_name = ctk.CTkEntry(self.register_frame, placeholder_text="الاسم الظاهر (اختياري)", width=280, height=40)
        self.register_display_name.pack(pady=5)
        
        self.register_password = ctk.CTkEntry(self.register_frame, placeholder_text="كلمة السر", width=280, height=40, show="*")
        self.register_password.pack(pady=5)
        
        self.register_bio = ctk.CTkEntry(self.register_frame, placeholder_text="السيرة الذاتية (اختياري)", width=280, height=40)
        self.register_bio.pack(pady=5)
        
        # زر التسجيل
        register_btn = ctk.CTkButton(self.register_frame, text="تسجيل", width=280, height=40,
                                     command=self.do_register, fg_color="#45bd62")
        register_btn.pack(pady=10)
        
        # رابط تسجيل الدخول
        login_link = ctk.CTkButton(self.register_frame, text="لديك حساب؟ سجل دخول", width=280, height=30,
                                   command=lambda: self.show_screen("login"), fg_color="transparent",
                                   text_color="#1877f2", hover_color="#e8f0fe")
        login_link.pack(pady=5)
    
    def create_main_screen(self):
        """الشاشة الرئيسية بعد تسجيل الدخول"""
        self.main_screen = ctk.CTkFrame(self.main_frame)
        
        # تقسيم إلى شريط جانبي ومحتوى
        self.main_container = ctk.CTkFrame(self.main_screen)
        self.main_container.pack(fill="both", expand=True)
        
        # الشريط الجانبي (يمين)
        self.sidebar = ctk.CTkFrame(self.main_container, width=200, corner_radius=10)
        self.sidebar.pack(side="right", fill="y", padx=(0, 5))
        self.sidebar.pack_propagate(False)
        
        # صورة المستخدم
        self.user_pic_label = ctk.CTkLabel(self.sidebar, text="👤", font=("Arial", 40))
        self.user_pic_label.pack(pady=10)
        
        self.user_name_label = ctk.CTkLabel(self.sidebar, text="", font=("Arial", 16, "bold"))
        self.user_name_label.pack(pady=2)
        
        self.user_username_label = ctk.CTkLabel(self.sidebar, text="", font=("Arial", 12), text_color="#65676b")
        self.user_username_label.pack(pady=2)
        
        # فاصل
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#e4e6eb").pack(fill="x", pady=10)
        
        # أزرار التنقل
        nav_buttons = [
            ("🏠 الرئيسية", "home"),
            ("🎬 الريلزات", "reels"),
            ("👥 الأصدقاء", "friends"),
            ("💬 الرسائل", "messages"),
            ("👥 مجموعات", "groups"),
            ("🔔 الإشعارات", "notifications"),
            ("👤 ملفي", "profile")
        ]
        
        self.nav_buttons = {}
        for text, view in nav_buttons:
            btn = ctk.CTkButton(self.sidebar, text=text, width=180, height=35,
                               command=lambda v=view: self.navigate_to(v),
                               fg_color="transparent", text_color="#1a1a1e",
                               hover_color="#e8f0fe", anchor="w")
            btn.pack(pady=2, padx=5)
            self.nav_buttons[view] = btn
        
        # فاصل
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#e4e6eb").pack(fill="x", pady=10)
        
        # أزرار المطور
        if self.current_user and self.current_user.get('is_developer', False):
            dev_btn = ctk.CTkButton(self.sidebar, text="🛠 لوحة المطور", width=180, height=35,
                                   command=self.open_developer_panel,
                                   fg_color="#ffd700", text_color="#000", hover_color="#e6c200")
            dev_btn.pack(pady=2, padx=5)
        
        # زر الخروج
        logout_btn = ctk.CTkButton(self.sidebar, text="🚪 خروج", width=180, height=35,
                                   command=self.do_logout, fg_color="#e74c3c", hover_color="#c0392b")
        logout_btn.pack(pady=10, padx=5)
        
        # منطقة المحتوى
        self.content_area = ctk.CTkFrame(self.main_container)
        self.content_area.pack(side="left", fill="both", expand=True, padx=(5, 0))
        
        # عنوان الصفحة
        self.page_title = ctk.CTkLabel(self.content_area, text="الرئيسية", font=("Arial", 20, "bold"))
        self.page_title.pack(pady=10)
        
        # حاوية المحتوى القابلة للتبديل
        self.content_container = ctk.CTkFrame(self.content_area)
        self.content_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # إنشاء شاشات المحتوى
        self.create_home_view()
        self.create_reels_view()
        self.create_friends_view()
        self.create_messages_view()
        self.create_groups_view()
        self.create_notifications_view()
        self.create_profile_view()
        self.create_chat_view()
        self.create_group_chat_view()
        self.create_developer_view()
        self.create_create_post_view()
        
        # إظهار الرئيسية
        self.show_content("home")
    
    def create_home_view(self):
        """شاشة الرئيسية"""
        self.home_frame = ctk.CTkScrollableFrame(self.content_container)
        
        # زر إنشاء منشور
        create_btn = ctk.CTkButton(self.home_frame, text="✏️ إنشاء منشور", 
                                   command=lambda: self.show_content("create_post"),
                                   fg_color="#1877f2", height=40)
        create_btn.pack(fill="x", pady=5, padx=10)
        
        # حاوية المنشورات
        self.posts_container = ctk.CTkFrame(self.home_frame)
        self.posts_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_reels_view(self):
        """شاشة الريلزات"""
        self.reels_frame = ctk.CTkScrollableFrame(self.content_container)
        self.reels_container = ctk.CTkFrame(self.reels_frame)
        self.reels_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_friends_view(self):
        """شاشة الأصدقاء"""
        self.friends_frame = ctk.CTkScrollableFrame(self.content_container)
        self.friends_container = ctk.CTkFrame(self.friends_frame)
        self.friends_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_messages_view(self):
        """شاشة الرسائل"""
        self.messages_frame = ctk.CTkScrollableFrame(self.content_container)
        self.messages_container = ctk.CTkFrame(self.messages_frame)
        self.messages_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_groups_view(self):
        """شاشة المجموعات"""
        self.groups_frame = ctk.CTkScrollableFrame(self.content_container)
        self.groups_container = ctk.CTkFrame(self.groups_frame)
        self.groups_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_notifications_view(self):
        """شاشة الإشعارات"""
        self.notifications_frame = ctk.CTkScrollableFrame(self.content_container)
        self.notifications_container = ctk.CTkFrame(self.notifications_frame)
        self.notifications_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_profile_view(self):
        """شاشة الملف الشخصي"""
        self.profile_frame = ctk.CTkScrollableFrame(self.content_container)
        self.profile_container = ctk.CTkFrame(self.profile_frame)
        self.profile_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_chat_view(self):
        """شاشة الدردشة الخاصة"""
        self.chat_frame = ctk.CTkFrame(self.content_container)
        self.chat_container = ctk.CTkFrame(self.chat_frame)
        self.chat_container.pack(fill="both", expand=True, pady=5, padx=10)
        
        # منطقة الرسائل
        self.chat_messages = ctk.CTkTextbox(self.chat_container, height=400, font=("Arial", 13))
        self.chat_messages.pack(fill="both", expand=True, pady=5)
        self.chat_messages.configure(state="disabled")
        
        # منطقة الإدخال
        input_frame = ctk.CTkFrame(self.chat_container)
        input_frame.pack(fill="x", pady=5)
        
        self.chat_input = ctk.CTkEntry(input_frame, placeholder_text="اكتب رسالتك...", height=40)
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        send_btn = ctk.CTkButton(input_frame, text="📤", width=40, height=40,
                                command=self.send_chat_message, fg_color="#1877f2")
        send_btn.pack(side="right")
    
    def create_group_chat_view(self):
        """شاشة الدردشة الجماعية"""
        self.group_chat_frame = ctk.CTkFrame(self.content_container)
        self.group_chat_container = ctk.CTkFrame(self.group_chat_frame)
        self.group_chat_container.pack(fill="both", expand=True, pady=5, padx=10)
        
        # منطقة الرسائل
        self.group_chat_messages = ctk.CTkTextbox(self.group_chat_container, height=400, font=("Arial", 13))
        self.group_chat_messages.pack(fill="both", expand=True, pady=5)
        self.group_chat_messages.configure(state="disabled")
        
        # منطقة الإدخال
        input_frame = ctk.CTkFrame(self.group_chat_container)
        input_frame.pack(fill="x", pady=5)
        
        self.group_chat_input = ctk.CTkEntry(input_frame, placeholder_text="اكتب رسالتك للجميع...", height=40)
        self.group_chat_input.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        send_btn = ctk.CTkButton(input_frame, text="📤", width=40, height=40,
                                command=self.send_group_chat_message, fg_color="#1877f2")
        send_btn.pack(side="right")
    
    def create_developer_view(self):
        """شاشة لوحة المطور"""
        self.developer_frame = ctk.CTkScrollableFrame(self.content_container)
        self.developer_container = ctk.CTkFrame(self.developer_frame)
        self.developer_container.pack(fill="both", expand=True, pady=5, padx=10)
    
    def create_create_post_view(self):
        """شاشة إنشاء منشور"""
        self.create_post_frame = ctk.CTkFrame(self.content_container)
        
        title = ctk.CTkLabel(self.create_post_frame, text="✏️ إنشاء منشور", font=("Arial", 18, "bold"))
        title.pack(pady=10)
        
        self.post_content = ctk.CTkTextbox(self.create_post_frame, height=150, font=("Arial", 14))
        self.post_content.pack(fill="x", padx=20, pady=10)
        
        post_btn = ctk.CTkButton(self.create_post_frame, text="نشر", command=self.create_post,
                                fg_color="#1877f2", height=40)
        post_btn.pack(pady=10)
        
        back_btn = ctk.CTkButton(self.create_post_frame, text="🔙 رجوع", command=lambda: self.show_content("home"),
                                fg_color="transparent", text_color="#65676b")
        back_btn.pack(pady=5)
    
    # ===================================================================
    # دوال التحكم
    # ===================================================================
    
    def show_screen(self, screen):
        """إظهار شاشة معينة"""
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.main_screen.pack_forget()
        
        if screen == "login":
            self.login_frame.pack(fill="both", expand=True)
        elif screen == "register":
            self.register_frame.pack(fill="both", expand=True)
        elif screen == "main":
            self.main_screen.pack(fill="both", expand=True)
            self.load_home()
    
    def show_content(self, view, **kwargs):
        """إظهار محتوى معين في المنطقة الرئيسية"""
        # إخفاء كل المحتويات
        for frame in [self.home_frame, self.reels_frame, self.friends_frame, 
                      self.messages_frame, self.groups_frame, self.notifications_frame,
                      self.profile_frame, self.chat_frame, self.group_chat_frame,
                      self.developer_frame, self.create_post_frame]:
            frame.pack_forget()
        
        # تحديث عنوان الصفحة
        titles = {
            "home": "🏠 الرئيسية",
            "reels": "🎬 الريلزات",
            "friends": "👥 الأصدقاء",
            "messages": "💬 الرسائل",
            "groups": "👥 المجموعات",
            "notifications": "🔔 الإشعارات",
            "profile": "👤 ملفي",
            "chat": "💬 الدردشة",
            "group_chat": "👥 دردشة جماعية",
            "developer": "🛠 لوحة المطور",
            "create_post": "✏️ إنشاء منشور"
        }
        self.page_title.configure(text=titles.get(view, view))
        
        # إظهار المحتوى المطلوب
        if view == "home":
            self.home_frame.pack(fill="both", expand=True)
            self.load_home()
        elif view == "reels":
            self.reels_frame.pack(fill="both", expand=True)
            self.load_reels()
        elif view == "friends":
            self.friends_frame.pack(fill="both", expand=True)
            self.load_friends()
        elif view == "messages":
            self.messages_frame.pack(fill="both", expand=True)
            self.load_messages()
        elif view == "groups":
            self.groups_frame.pack(fill="both", expand=True)
            self.load_groups()
        elif view == "notifications":
            self.notifications_frame.pack(fill="both", expand=True)
            self.load_notifications()
        elif view == "profile":
            self.profile_frame.pack(fill="both", expand=True)
            self.load_profile()
        elif view == "chat":
            self.chat_frame.pack(fill="both", expand=True)
            if kwargs.get('user_id'):
                self.current_chat_user = kwargs['user_id']
                self.load_chat()
        elif view == "group_chat":
            self.group_chat_frame.pack(fill="both", expand=True)
            if kwargs.get('chat_id'):
                self.current_group_chat = kwargs['chat_id']
                self.load_group_chat()
        elif view == "developer":
            self.developer_frame.pack(fill="both", expand=True)
            self.load_developer_panel()
        elif view == "create_post":
            self.create_post_frame.pack(fill="both", expand=True)
        
        self.current_view = view
    
    def navigate_to(self, view):
        """التنقل إلى صفحة"""
        self.show_content(view)
    
    def check_login_status(self):
        """التحقق من حالة تسجيل الدخول"""
        try:
            response = requests.get('http://127.0.0.1:5000/api/current_user')
            if response.status_code == 200:
                data = response.json()
                if 'id' in data:
                    self.current_user = data
                    self.show_screen("main")
                    return
        except:
            pass
        self.show_screen("login")
    
    def do_login(self):
        """تسجيل الدخول"""
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("خطأ", "الرجاء ملء جميع الحقول")
            return
        
        try:
            response = requests.post('http://127.0.0.1:5000/api/login', 
                                    json={'username': username, 'password': password})
            data = response.json()
            
            if data.get('success'):
                self.current_user = data['user']
                self.show_screen("main")
                self.login_username.delete(0, 'end')
                self.login_password.delete(0, 'end')
            else:
                messagebox.showerror("خطأ", data.get('error', 'فشل تسجيل الدخول'))
        except Exception as e:
            messagebox.showerror("خطأ", f"تعذر الاتصال بالخادم: {str(e)}")
    
    def do_register(self):
        """تسجيل مستخدم جديد"""
        username = self.register_username.get()
        password = self.register_password.get()
        display_name = self.register_display_name.get()
        bio = self.register_bio.get()
        
        if not username or not password:
            messagebox.showerror("خطأ", "الرجاء ملء الحقول المطلوبة")
            return
        
        try:
            response = requests.post('http://127.0.0.1:5000/api/register',
                                    json={
                                        'username': username,
                                        'password': password,
                                        'display_name': display_name,
                                        'bio': bio
                                    })
            data = response.json()
            
            if data.get('success'):
                messagebox.showinfo("نجاح", "تم التسجيل بنجاح! يمكنك تسجيل الدخول الآن")
                self.show_screen("login")
                self.register_username.delete(0, 'end')
                self.register_password.delete(0, 'end')
                self.register_display_name.delete(0, 'end')
                self.register_bio.delete(0, 'end')
            else:
                messagebox.showerror("خطأ", data.get('error', 'فشل التسجيل'))
        except Exception as e:
            messagebox.showerror("خطأ", f"تعذر الاتصال بالخادم: {str(e)}")
    
    def do_logout(self):
        """تسجيل الخروج"""
        if messagebox.askyesno("تأكيد", "هل تريد تسجيل الخروج؟"):
            try:
                requests.post('http://127.0.0.1:5000/api/logout')
            except:
                pass
            self.current_user = None
            self.show_screen("login")
    
    # ===================================================================
    # تحميل المحتوى
    # ===================================================================
    
    def load_home(self):
        """تحميل المنشورات في الصفحة الرئيسية"""
        # تنظيف الحاوية
        for widget in self.posts_container.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get('http://127.0.0.1:5000/api/posts', 
                                   cookies={'session': ''})
            if response.status_code == 200:
                posts = response.json()
                
                if not posts:
                    label = ctk.CTkLabel(self.posts_container, text="لا توجد منشورات بعد",
                                        font=("Arial", 14), text_color="#65676b")
                    label.pack(pady=20)
                    return
                
                for post in posts:
                    self.create_post_widget(post)
            else:
                label = ctk.CTkLabel(self.posts_container, text="حدث خطأ في تحميل المنشورات",
                                    font=("Arial", 14), text_color="#e74c3c")
                label.pack(pady=20)
        except Exception as e:
            label = ctk.CTkLabel(self.posts_container, text=f"خطأ في الاتصال: {str(e)}",
                                font=("Arial", 12), text_color="#e74c3c")
            label.pack(pady=20)
    
    def create_post_widget(self, post):
        """إنشاء عنصر منشور"""
        frame = ctk.CTkFrame(self.posts_container, corner_radius=10)
        frame.pack(fill="x", pady=5, padx=5)
        
        # رأس المنشور
        header = ctk.CTkFrame(frame)
        header.pack(fill="x", pady=5, padx=10)
        
        # صورة المستخدم
        user_pic = post.get('profile_pic', 'default_profile.jpg')
        pic_label = ctk.CTkLabel(header, text="👤", font=("Arial", 20))
        pic_label.pack(side="left", padx=5)
        
        # اسم المستخدم
        name = post.get('display_name', post.get('username', ''))
        name_label = ctk.CTkLabel(header, text=name, font=("Arial", 14, "bold"))
        name_label.pack(side="left")
        
        # علامة التوثيق
        if post.get('is_verified'):
            verify = ctk.CTkLabel(header, text="✓", text_color="#1877f2", font=("Arial", 12, "bold"))
            verify.pack(side="left", padx=2)
        
        # الوقت
        time_label = ctk.CTkLabel(header, text=post.get('created_at', ''), font=("Arial", 10), text_color="#65676b")
        time_label.pack(side="right")
        
        # المحتوى
        content_label = ctk.CTkLabel(frame, text=post.get('content', ''), font=("Arial", 13), wraplength=400, justify="right")
        content_label.pack(pady=5, padx=10)
        
        # صورة المنشور
        if post.get('image'):
            img_label = ctk.CTkLabel(frame, text="🖼️ [صورة]", font=("Arial", 12))
            img_label.pack(pady=5)
        
        # أزرار التفاعل
        actions = ctk.CTkFrame(frame)
        actions.pack(fill="x", pady=5, padx=10)
        
        # زر الإعجاب
        like_text = f"❤️ {post.get('likes', 0)}"
        if post.get('user_liked'):
            like_btn = ctk.CTkButton(actions, text=like_text, width=60, height=30,
                                     fg_color="#1877f2", command=lambda p=post: self.like_post(p))
        else:
            like_btn = ctk.CTkButton(actions, text=like_text, width=60, height=30,
                                     fg_color="transparent", text_color="#65676b",
                                     command=lambda p=post: self.like_post(p))
        like_btn.pack(side="left", padx=2)
        
        # زر التعليق
        comment_btn = ctk.CTkButton(actions, text=f"💬 {post.get('comments_count', 0)}", width=60, height=30,
                                   fg_color="transparent", text_color="#65676b",
                                   command=lambda p=post: self.show_comments(p))
        comment_btn.pack(side="left", padx=2)
        
        # عرض التعليقات
        if post.get('comments'):
            comments_frame = ctk.CTkFrame(frame)
            comments_frame.pack(fill="x", pady=5, padx=10)
            
            for comment in post['comments']:
                c_text = f"{comment.get('display_name', '')}: {comment.get('content', '')}"
                c_label = ctk.CTkLabel(comments_frame, text=c_text, font=("Arial", 11), wraplength=350, justify="right")
                c_label.pack(anchor="w", pady=1)
    
    def like_post(self, post):
        """إعجاب بمنشور"""
        try:
            response = requests.post(f'http://127.0.0.1:5000/api/like_post/{post["id"]}')
            if response.status_code == 200:
                self.load_home()
        except:
            pass
    
    def show_comments(self, post):
        """عرض التعليقات"""
        # نافذة منبسطة لعرض التعليقات
        win = ctk.CTkToplevel(self)
        win.title("التعليقات")
        win.geometry("400x400")
        
        text = ctk.CTkTextbox(win, font=("Arial", 13))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.configure(state="normal")
        
        text.insert("end", f"📝 {post.get('display_name', '')}\n")
        text.insert("end", f"{post.get('content', '')}\n\n")
        text.insert("end", "━"*30 + "\n\n")
        
        if post.get('comments'):
            for c in post['comments']:
                text.insert("end", f"👤 {c.get('display_name', '')}\n")
                text.insert("end", f"   {c.get('content', '')}\n")
                text.insert("end", f"   ⏰ {c.get('created_at', '')}\n\n")
        else:
            text.insert("end", "لا توجد تعليقات")
        
        text.configure(state="disabled")
    
    def load_reels(self):
        """تحميل الريلزات"""
        for widget in self.reels_container.winfo_children():
            widget.destroy()
        
        label = ctk.CTkLabel(self.reels_container, text="🎬 الريلزات\n(سيتم إضافة دعم الفيديو قريباً)",
                            font=("Arial", 16), text_color="#65676b")
        label.pack(pady=50)
    
    def load_friends(self):
        """تحميل الأصدقاء"""
        for widget in self.friends_container.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get('http://127.0.0.1:5000/api/friends')
            if response.status_code == 200:
                data = response.json()
                
                # الطلبات المعلقة
                if data.get('pending'):
                    title = ctk.CTkLabel(self.friends_container, text="📨 طلبات الصداقة", font=("Arial", 16, "bold"))
                    title.pack(anchor="w", pady=5)
                    
                    for friend in data['pending']:
                        self.create_friend_item(self.friends_container, friend, pending=True)
                
                # الأصدقاء
                if data.get('accepted'):
                    title = ctk.CTkLabel(self.friends_container, text="👥 أصدقائي", font=("Arial", 16, "bold"))
                    title.pack(anchor="w", pady=5)
                    
                    for friend in data['accepted']:
                        self.create_friend_item(self.friends_container, friend, pending=False)
                
                if not data.get('accepted') and not data.get('pending'):
                    label = ctk.CTkLabel(self.friends_container, text="لا توجد أصدقاء",
                                        font=("Arial", 14), text_color="#65676b")
                    label.pack(pady=20)
                
                # زر البحث
                search_frame = ctk.CTkFrame(self.friends_container)
                search_frame.pack(fill="x", pady=10)
                
                self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="🔍 بحث عن مستخدم...", height=35)
                self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
                
                search_btn = ctk.CTkButton(search_frame, text="بحث", width=60, height=35,
                                          command=self.search_users)
                search_btn.pack(side="right")
                
                # حاوية نتائج البحث
                self.search_results = ctk.CTkFrame(self.friends_container)
                self.search_results.pack(fill="x", pady=5)
                
        except Exception as e:
            label = ctk.CTkLabel(self.friends_container, text=f"خطأ: {str(e)}",
                                font=("Arial", 12), text_color="#e74c3c")
            label.pack(pady=20)
    
    def create_friend_item(self, parent, friend, pending=False):
        """إنشاء عنصر صديق"""
        frame = ctk.CTkFrame(parent, corner_radius=8)
        frame.pack(fill="x", pady=2, padx=5)
        
        # صورة
        pic = ctk.CTkLabel(frame, text="👤", font=("Arial", 18))
        pic.pack(side="left", padx=5)
        
        # الاسم
        name = friend.get('display_name', friend.get('username', ''))
        name_label = ctk.CTkLabel(frame, text=name, font=("Arial", 13, "bold"))
        name_label.pack(side="left", padx=5)
        
        username = f"@{friend.get('username', '')}"
        user_label = ctk.CTkLabel(frame, text=username, font=("Arial", 10), text_color="#65676b")
        user_label.pack(side="left", padx=5)
        
        # أزرار
        if pending:
            accept_btn = ctk.CTkButton(frame, text="قبول", width=60, height=28,
                                      command=lambda f=friend: self.accept_friend(f),
                                      fg_color="#45bd62")
            accept_btn.pack(side="right", padx=2)
        else:
            chat_btn = ctk.CTkButton(frame, text="💬", width=40, height=28,
                                    command=lambda f=friend: self.open_chat(f['id']),
                                    fg_color="#1877f2")
            chat_btn.pack(side="right", padx=2)
            
            block_btn = ctk.CTkButton(frame, text="🚫", width=40, height=28,
                                     command=lambda f=friend: self.block_user(f['id']),
                                     fg_color="#e74c3c")
            block_btn.pack(side="right", padx=2)
    
    def accept_friend(self, friend):
        """قبول طلب صداقة"""
        try:
            response = requests.post(f'http://127.0.0.1:5000/api/accept_friend/{friend["id"]}')
            if response.status_code == 200:
                self.load_friends()
        except:
            pass
    
    def block_user(self, user_id):
        """حظر مستخدم"""
        if messagebox.askyesno("تأكيد", "هل تريد حظر هذا المستخدم؟"):
            try:
                requests.post(f'http://127.0.0.1:5000/api/block_user/{user_id}')
                self.load_friends()
            except:
                pass
    
    def search_users(self):
        """البحث عن مستخدمين"""
        query = self.search_entry.get()
        if len(query) < 1:
            return
        
        # تنظيف النتائج السابقة
        for widget in self.search_results.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get(f'http://127.0.0.1:5000/api/search_users/{query}')
            if response.status_code == 200:
                users = response.json()
                
                if not users:
                    label = ctk.CTkLabel(self.search_results, text="لا توجد نتائج",
                                        font=("Arial", 12), text_color="#65676b")
                    label.pack(pady=5)
                    return
                
                for user in users:
                    frame = ctk.CTkFrame(self.search_results, corner_radius=8)
                    frame.pack(fill="x", pady=2)
                    
                    name = user.get('display_name', user.get('username', ''))
                    name_label = ctk.CTkLabel(frame, text=name, font=("Arial", 13))
                    name_label.pack(side="left", padx=5)
                    
                    if user.get('is_friend'):
                        status = ctk.CTkLabel(frame, text="✅ صديق", text_color="#45bd62", font=("Arial", 11))
                        status.pack(side="right", padx=5)
                    else:
                        add_btn = ctk.CTkButton(frame, text="➕", width=40, height=28,
                                               command=lambda u=user: self.send_friend_request(u),
                                               fg_color="#1877f2")
                        add_btn.pack(side="right", padx=2)
        except:
            pass
    
    def send_friend_request(self, user):
        """إرسال طلب صداقة"""
        try:
            response = requests.post(f'http://127.0.0.1:5000/api/send_friend_request/{user["id"]}')
            if response.status_code == 200 and response.json().get('success'):
                messagebox.showinfo("نجاح", "تم إرسال الطلب")
                self.search_users()
            else:
                messagebox.showerror("خطأ", "فشل إرسال الطلب")
        except:
            pass
    
    def open_chat(self, user_id):
        """فتح دردشة خاصة"""
        self.show_content("chat", user_id=user_id)
    
    def load_messages(self):
        """تحميل قائمة الرسائل"""
        for widget in self.messages_container.winfo_children():
            widget.destroy()
        
        try:
            # جلب قائمة المحادثات من الأصدقاء
            response = requests.get('http://127.0.0.1:5000/api/friends')
            if response.status_code == 200:
                data = response.json()
                friends = data.get('accepted', [])
                
                if not friends:
                    label = ctk.CTkLabel(self.messages_container, text="لا توجد محادثات\nأضف أصدقاء للبدء",
                                        font=("Arial", 14), text_color="#65676b")
                    label.pack(pady=30)
                    return
                
                for friend in friends:
                    frame = ctk.CTkFrame(self.messages_container, corner_radius=8)
                    frame.pack(fill="x", pady=2, padx=5)
                    
                    # صورة
                    pic = ctk.CTkLabel(frame, text="👤", font=("Arial", 18))
                    pic.pack(side="left", padx=5)
                    
                    # الاسم
                    name = friend.get('display_name', friend.get('username', ''))
                    name_label = ctk.CTkLabel(frame, text=name, font=("Arial", 13, "bold"))
                    name_label.pack(side="left", padx=5)
                    
                    # زر الدردشة
                    chat_btn = ctk.CTkButton(frame, text="💬 فتح", width=80, height=30,
                                            command=lambda f=friend: self.open_chat(f['id']),
                                            fg_color="#1877f2")
                    chat_btn.pack(side="right", padx=5)
                    
        except Exception as e:
            label = ctk.CTkLabel(self.messages_container, text=f"خطأ: {str(e)}",
                                font=("Arial", 12), text_color="#e74c3c")
            label.pack(pady=20)
    
    def load_chat(self):
        """تحميل الدردشة الخاصة"""
        self.chat_messages.configure(state="normal")
        self.chat_messages.delete("1.0", "end")
        
        if not self.current_chat_user:
            self.chat_messages.insert("end", "اختر مستخدم للدردشة")
            self.chat_messages.configure(state="disabled")
            return
        
        try:
            response = requests.get(f'http://127.0.0.1:5000/api/messages/{self.current_chat_user}')
            if response.status_code == 200:
                messages = response.json()
                
                if not messages:
                    self.chat_messages.insert("end", "لا توجد رسائل")
                else:
                    for msg in messages:
                        sender = "أنت" if msg['is_sent'] else msg['sender_name']
                        prefix = "🗣️" if not msg['is_sent'] else "📤"
                        self.chat_messages.insert("end", f"{prefix} {sender}: {msg['content']}\n")
                        if msg.get('image'):
                            self.chat_messages.insert("end", "   🖼️ [صورة]\n")
                        self.chat_messages.insert("end", f"   ⏰ {msg['created_at']}\n\n")
            else:
                self.chat_messages.insert("end", "حدث خطأ في تحميل الرسائل")
        except Exception as e:
            self.chat_messages.insert("end", f"خطأ: {str(e)}")
        
        self.chat_messages.configure(state="disabled")
        self.chat_messages.see("end")
    
    def send_chat_message(self):
        """إرسال رسالة خاصة"""
        content = self.chat_input.get()
        if not content or not self.current_chat_user:
            return
        
        try:
            response = requests.post('http://127.0.0.1:5000/api/send_message',
                                    data={'receiver_id': self.current_chat_user, 'content': content})
            if response.status_code == 200 and response.json().get('success'):
                self.chat_input.delete(0, 'end')
                self.load_chat()
            else:
                messagebox.showerror("خطأ", "فشل إرسال الرسالة")
        except:
            messagebox.showerror("خطأ", "تعذر الاتصال بالخادم")
    
    def load_groups(self):
        """تحميل المجموعات"""
        for widget in self.groups_container.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get('http://127.0.0.1:5000/api/group_chats')
            if response.status_code == 200:
                groups = response.json()
                
                # زر إنشاء مجموعة
                create_btn = ctk.CTkButton(self.groups_container, text="➕ إنشاء مجموعة جديدة",
                                          command=self.create_group_dialog,
                                          fg_color="#1877f2", height=35)
                create_btn.pack(fill="x", pady=5, padx=5)
                
                if not groups:
                    label = ctk.CTkLabel(self.groups_container, text="لا توجد مجموعات",
                                        font=("Arial", 14), text_color="#65676b")
                    label.pack(pady=20)
                    return
                
                for group in groups:
                    frame = ctk.CTkFrame(self.groups_container, corner_radius=8)
                    frame.pack(fill="x", pady=3, padx=5)
                    
                    # اسم المجموعة
                    name = group.get('name', '')
                    name_label = ctk.CTkLabel(frame, text=f"👥 {name}", font=("Arial", 14, "bold"))
                    name_label.pack(side="left", padx=10)
                    
                    # عدد الأعضاء
                    members = len(group.get('members', []))
                    members_label = ctk.CTkLabel(frame, text=f"{members} عضو", font=("Arial", 11), text_color="#65676b")
                    members_label.pack(side="left", padx=5)
                    
                    # زر الدخول
                    join_btn = ctk.CTkButton(frame, text="دخول", width=70, height=30,
                                            command=lambda g=group: self.open_group_chat(g['id']),
                                            fg_color="#1877f2")
                    join_btn.pack(side="right", padx=5)
                    
        except Exception as e:
            label = ctk.CTkLabel(self.groups_container, text=f"خطأ: {str(e)}",
                                font=("Arial", 12), text_color="#e74c3c")
            label.pack(pady=20)
    
    def create_group_dialog(self):
        """نافذة إنشاء مجموعة"""
        win = ctk.CTkToplevel(self)
        win.title("إنشاء مجموعة")
        win.geometry("350x250")
        
        label = ctk.CTkLabel(win, text="إنشاء مجموعة جديدة", font=("Arial", 16, "bold"))
        label.pack(pady=10)
        
        name_entry = ctk.CTkEntry(win, placeholder_text="اسم المجموعة", width=250, height=35)
        name_entry.pack(pady=5)
        
        desc_entry = ctk.CTkEntry(win, placeholder_text="الوصف (اختياري)", width=250, height=35)
        desc_entry.pack(pady=5)
        
        def create():
            name = name_entry.get()
            if not name:
                messagebox.showerror("خطأ", "أدخل اسم المجموعة")
                return
            
            try:
                response = requests.post('http://127.0.0.1:5000/api/create_group_chat',
                                        json={'name': name, 'description': desc_entry.get()})
                if response.status_code == 200 and response.json().get('success'):
                    win.destroy()
                    self.load_groups()
                    messagebox.showinfo("نجاح", "تم إنشاء المجموعة")
                else:
                    messagebox.showerror("خطأ", "فشل إنشاء المجموعة")
            except:
                messagebox.showerror("خطأ", "تعذر الاتصال بالخادم")
        
        create_btn = ctk.CTkButton(win, text="إنشاء", command=create, fg_color="#1877f2", height=35)
        create_btn.pack(pady=10)
    
    def open_group_chat(self, chat_id):
        """فتح دردشة جماعية"""
        self.show_content("group_chat", chat_id=chat_id)
    
    def load_group_chat(self):
        """تحميل الدردشة الجماعية"""
        self.group_chat_messages.configure(state="normal")
        self.group_chat_messages.delete("1.0", "end")
        
        if not self.current_group_chat:
            self.group_chat_messages.insert("end", "اختر مجموعة للدردشة")
            self.group_chat_messages.configure(state="disabled")
            return
        
        try:
            response = requests.get(f'http://127.0.0.1:5000/api/group_chat/{self.current_group_chat}')
            if response.status_code == 200:
                chat = response.json()
                messages = chat.get('messages', [])
                
                if not messages:
                    self.group_chat_messages.insert("end", "لا توجد رسائل")
                else:
                    for msg in messages:
                        sender = msg.get('sender_name', 'مجهول')
                        content = msg.get('content', '')
                        self.group_chat_messages.insert("end", f"🗣️ {sender}: {content}\n")
                        if msg.get('image'):
                            self.group_chat_messages.insert("end", "   🖼️ [صورة]\n")
                        self.group_chat_messages.insert("end", f"   ⏰ {msg['created_at'][:19]}\n\n")
            else:
                self.group_chat_messages.insert("end", "حدث خطأ في تحميل الرسائل")
        except Exception as e:
            self.group_chat_messages.insert("end", f"خطأ: {str(e)}")
        
        self.group_chat_messages.configure(state="disabled")
        self.group_chat_messages.see("end")
    
    def send_group_chat_message(self):
        """إرسال رسالة جماعية"""
        content = self.group_chat_input.get()
        if not content or not self.current_group_chat:
            return
        
        try:
            response = requests.post('http://127.0.0.1:5000/api/send_group_message',
                                    data={'chat_id': self.current_group_chat, 'content': content})
            if response.status_code == 200 and response.json().get('success'):
                self.group_chat_input.delete(0, 'end')
                self.load_group_chat()
            else:
                messagebox.showerror("خطأ", "فشل إرسال الرسالة")
        except:
            messagebox.showerror("خطأ", "تعذر الاتصال بالخادم")
    
    def load_notifications(self):
        """تحميل الإشعارات"""
        for widget in self.notifications_container.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get('http://127.0.0.1:5000/api/notifications')
            if response.status_code == 200:
                notifications = response.json()
                
                if not notifications:
                    label = ctk.CTkLabel(self.notifications_container, text="لا توجد إشعارات",
                                        font=("Arial", 14), text_color="#65676b")
                    label.pack(pady=20)
                    return
                
                for n in notifications[:20]:
                    frame = ctk.CTkFrame(self.notifications_container, corner_radius=8)
                    frame.pack(fill="x", pady=2, padx=5)
                    
                    msg = n.get('message', '')
                    time_str = n.get('created_at', '')[:19]
                    
                    msg_label = ctk.CTkLabel(frame, text=f"📢 {msg}", font=("Arial", 12), wraplength=350, justify="right")
                    msg_label.pack(anchor="w", padx=10, pady=2)
                    
                    time_label = ctk.CTkLabel(frame, text=f"⏰ {time_str}", font=("Arial", 10), text_color="#65676b")
                    time_label.pack(anchor="w", padx=10, pady=2)
                    
        except Exception as e:
            label = ctk.CTkLabel(self.notifications_container, text=f"خطأ: {str(e)}",
                                font=("Arial", 12), text_color="#e74c3c")
            label.pack(pady=20)
    
    def load_profile(self):
        """تحميل الملف الشخصي"""
        for widget in self.profile_container.winfo_children():
            widget.destroy()
        
        if not self.current_user:
            label = ctk.CTkLabel(self.profile_container, text="غير مسجل دخول",
                                font=("Arial", 14), text_color="#e74c3c")
            label.pack(pady=20)
            return
        
        user = self.current_user
        
        # صورة
        pic = ctk.CTkLabel(self.profile_container, text="👤", font=("Arial", 60))
        pic.pack(pady=10)
        
        # الاسم
        name = user.get('display_name', user.get('username', ''))
        name_label = ctk.CTkLabel(self.profile_container, text=name, font=("Arial", 20, "bold"))
        name_label.pack()
        
        # اسم المستخدم
        username = f"@{user.get('username', '')}"
        user_label = ctk.CTkLabel(self.profile_container, text=username, font=("Arial", 14), text_color="#65676b")
        user_label.pack()
        
        # التوثيق
        if user.get('is_verified'):
            verify = ctk.CTkLabel(self.profile_container, text="✅ حساب موثق", font=("Arial", 12), text_color="#1877f2")
            verify.pack()
        
        if user.get('is_developer'):
            dev = ctk.CTkLabel(self.profile_container, text="👑 مطور", font=("Arial", 12), text_color="#ffd700")
            dev.pack()
        
        # أزرار
        edit_btn = ctk.CTkButton(self.profile_container, text="✏️ تعديل الملف", 
                                command=self.edit_profile_dialog,
                                fg_color="#1877f2", height=35)
        edit_btn.pack(pady=10)
    
    def edit_profile_dialog(self):
        """نافذة تعديل الملف الشخصي"""
        win = ctk.CTkToplevel(self)
        win.title("تعديل الملف الشخصي")
        win.geometry("350x300")
        
        label = ctk.CTkLabel(win, text="تعديل الملف الشخصي", font=("Arial", 16, "bold"))
        label.pack(pady=10)
        
        # الاسم الظاهر
        name_label = ctk.CTkLabel(win, text="الاسم الظاهر:", font=("Arial", 12))
        name_label.pack(anchor="w", padx=20)
        name_entry = ctk.CTkEntry(win, width=250, height=35)
        name_entry.insert(0, self.current_user.get('display_name', ''))
        name_entry.pack(pady=5)
        
        # السيرة الذاتية
        bio_label = ctk.CTkLabel(win, text="السيرة الذاتية:", font=("Arial", 12))
        bio_label.pack(anchor="w", padx=20)
        bio_entry = ctk.CTkEntry(win, width=250, height=35)
        bio_entry.insert(0, '')
        bio_entry.pack(pady=5)
        
        # زر حفظ
        def save_profile():
            messagebox.showinfo("معلومات", "سيتم إضافة هذه الميزة قريباً")
            win.destroy()
        
        save_btn = ctk.CTkButton(win, text="حفظ", command=save_profile, fg_color="#1877f2", height=35)
        save_btn.pack(pady=10)
    
    def create_post(self):
        """إنشاء منشور جديد"""
        content = self.post_content.get("1.0", "end").strip()
        if not content:
            messagebox.showerror("خطأ", "الرجاء كتابة محتوى المنشور")
            return
        
        try:
            response = requests.post('http://127.0.0.1:5000/api/create_post',
                                    data={'content': content})
            if response.status_code == 200 and response.json().get('success'):
                self.post_content.delete("1.0", "end")
                messagebox.showinfo("نجاح", "تم نشر المنشور")
                self.show_content("home")
            else:
                messagebox.showerror("خطأ", "فشل نشر المنشور")
        except:
            messagebox.showerror("خطأ", "تعذر الاتصال بالخادم")
    
    def open_developer_panel(self):
        """فتح لوحة المطور"""
        self.show_content("developer")
    
    def load_developer_panel(self):
        """تحميل لوحة المطور"""
        for widget in self.developer_container.winfo_children():
            widget.destroy()
        
        if not self.current_user or not self.current_user.get('is_developer', False):
            label = ctk.CTkLabel(self.developer_container, text="غير مصرح",
                                font=("Arial", 14), text_color="#e74c3c")
            label.pack(pady=20)
            return
        
        # إحصائيات
        stats = ctk.CTkFrame(self.developer_container, corner_radius=10)
        stats.pack(fill="x", pady=5, padx=5)
        
        # جلب الإحصائيات
        try:
            response = requests.get('http://127.0.0.1:5000/api/posts')
            posts = response.json() if response.status_code == 200 else []
            
            users = read_json('users')
            
            stats_label = ctk.CTkLabel(stats, 
                text=f"👥 المستخدمين: {len(users)}  |  📝 المنشورات: {len(posts)}",
                font=("Arial", 13))
            stats_label.pack(pady=10)
        except:
            pass
        
        # قائمة المستخدمين
        users_frame = ctk.CTkFrame(self.developer_container, corner_radius=10)
        users_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        title = ctk.CTkLabel(users_frame, text="👥 المستخدمين", font=("Arial", 14, "bold"))
        title.pack(anchor="w", pady=5, padx=10)
        
        try:
            users = read_json('users')
            for u in users[:20]:
                frame = ctk.CTkFrame(users_frame, corner_radius=5)
                frame.pack(fill="x", pady=1, padx=5)
                
                name = get_display_name(u)
                name_label = ctk.CTkLabel(frame, text=f"👤 {name} (@{u['username']})", font=("Arial", 11))
                name_label.pack(side="left", padx=5)
                
                if u.get('is_developer'):
                    dev = ctk.CTkLabel(frame, text="👑", font=("Arial", 12))
                    dev.pack(side="left")
                
                if u.get('is_verified'):
                    ver = ctk.CTkLabel(frame, text="✅", font=("Arial", 12), text_color="#1877f2")
                    ver.pack(side="left")
        except:
            pass

# ===================================================================
# تشغيل التطبيق
# ===================================================================

if __name__ == "__main__":
    # التأكد من وجود الملفات
    if not os.path.exists('static/uploads/default_profile.jpg'):
        try:
            response = requests.get('https://i.ibb.co/kgz0xgNj/a309ed3530e0f365781d8c2607ac4e7e.jpg', timeout=10)
            if response.status_code == 200:
                os.makedirs('static/uploads', exist_ok=True)
                with open('static/uploads/default_profile.jpg', 'wb') as f:
                    f.write(response.content)
        except:
            pass
    
    # إنشاء حسابات المطورين
    if not get_user_by_username('MBL'):
        users = read_json('users')
        users.append({
            'id': get_next_id('users'),
            'username': 'MBL',
            'password': generate_password_hash('MBL'),
            'display_name': 'المطور الرئيسي',
            'is_verified': True,
            'is_developer': True,
            'mini_pic_enabled': True,
            'mini_pic': None,
            'bio': 'المطور الرئيسي',
            'profile_pic': 'default_profile.jpg',
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('users', users)
    
    if not get_user_by_username('MBLL'):
        users = read_json('users')
        users.append({
            'id': get_next_id('users'),
            'username': 'MBLL',
            'password': generate_password_hash('MBMB'),
            'display_name': 'المطور الثاني',
            'is_verified': True,
            'is_developer': True,
            'mini_pic_enabled': True,
            'mini_pic': None,
            'bio': 'المطور الثاني',
            'profile_pic': 'default_profile.jpg',
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('users', users)
    
    # تشغيل التطبيق
    app = CAWApp()
    app.mainloop()
