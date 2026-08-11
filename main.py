# main.py - الكود الكامل مع جميع الأزرار العاملة

from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from markupsafe import escape
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import json
import os
import secrets
import requests
import time
import threading
from collections import defaultdict
from PIL import Image

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

# ==================== نظام الحماية ====================
class InvisibleProtection:
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked_ips = set()
        self.suspicious_ips = set()
        self.whitelist = set()
        self.lock = threading.Lock()
        self.is_under_attack = False
        self.load_data()
    
    def load_data(self):
        try:
            if os.path.exists('data/security_data.json'):
                with open('data/security_data.json', 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked_ips', []))
                    self.whitelist = set(data.get('whitelist', []))
        except:
            pass
    
    def save_data(self):
        try:
            with open('data/security_data.json', 'w') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_ips),
                    'whitelist': list(self.whitelist)
                }, f)
        except:
            pass
    
    def is_blocked(self, ip):
        if ip in self.whitelist:
            return False
        return ip in self.blocked_ips
    
    def block_ip(self, ip, duration=300):
        with self.lock:
            if ip not in self.blocked_ips and ip not in self.whitelist:
                self.blocked_ips.add(ip)
                self.save_data()
                def unblock():
                    time.sleep(duration)
                    with self.lock:
                        if ip in self.blocked_ips:
                            self.blocked_ips.remove(ip)
                            self.save_data()
                thread = threading.Thread(target=unblock, daemon=True)
                thread.start()
    
    def check_request(self, ip):
        if ip in self.whitelist:
            return True
        if self.is_blocked(ip):
            return False
        current_time = time.time()
        with self.lock:
            self.requests[ip] = [t for t in self.requests[ip] if current_time - t < 60]
            if len(self.requests[ip]) >= 30:
                self.block_ip(ip, 120)
                return False
            self.requests[ip].append(current_time)
            return True
    
    def add_to_whitelist(self, ip):
        with self.lock:
            self.whitelist.add(ip)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            self.save_data()
    
    def get_stats(self):
        return {
            'blocked_ips': len(self.blocked_ips),
            'suspicious_ips': len(self.suspicious_ips),
            'whitelisted_ips': len(self.whitelist),
            'is_under_attack': self.is_under_attack
        }

protection = InvisibleProtection()

# ==================== نظام الحظر ====================
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
            if b['blocker_id'] == user_id and b['blocked_id'] == target_id:
                return True
            if b['blocker_id'] == target_id and b['blocked_id'] == user_id:
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

# ==================== نظام الإبلاغ ====================
class ReportSystem:
    REPORT_REASONS = [
        ('fa-shield-halved', 'حساب وهمي أو منتحل شخصية'),
        ('fa-user-slash', 'تحرش أو مضايقة'),
        ('fa-comment-slash', 'خطاب كراهية'),
        ('fa-triangle-exclamation', 'عنف أو محتوى صادم'),
        ('fa-child-reaching', 'استغلال أو تعريض قاصر للخطر'),
        ('fa-pills', 'ترويج لمواد أو أنشطة غير قانونية'),
        ('fa-bullhorn', 'رسائل مزعجة أو سبام'),
        ('fa-copyright', 'انتهاك حقوق الملكية'),
        ('fa-circle-question', 'معلومات مضللة'),
        ('fa-ellipsis', 'سبب آخر'),
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
            if r['reporter_id'] == reporter_id and r['target_id'] == target_id and r['target_type'] == target_type and r.get('content_id') == content_id:
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

# ==================== تطبيق الحماية ====================
@app.before_request
def before_request():
    if request.path.startswith('/static/'):
        return
    ip = request.remote_addr
    if 'user_id' in session:
        user = get_user(session['user_id'])
        if user and user.get('is_developer', False):
            protection.add_to_whitelist(ip)
            return
    if not protection.check_request(ip):
        return jsonify({'error': 'حدث خطأ غير متوقع'}), 500

# ==================== الصورة الافتراضية ====================
DEFAULT_PROFILE_PIC = 'https://i.ibb.co/kgz0xgNj/a309ed3530e0f365781d8c2607ac4e7e.jpg'

def download_default_image():
    try:
        response = requests.get(DEFAULT_PROFILE_PIC, timeout=10)
        if response.status_code == 200:
            with open('static/uploads/default_profile.jpg', 'wb') as f:
                f.write(response.content)
            print('✓ تم تحميل الصورة الافتراضية')
            return True
    except:
        pass
    return False

download_default_image()

# ==================== ملفات JSON ====================
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
    if user and user.get('profile_pic') and user['profile_pic'] != 'default.jpg' and user['profile_pic'] != 'default_profile.jpg':
        return user['profile_pic']
    return 'default_profile.jpg'

def get_mini_pic(user):
    if not user:
        return None
    if not user.get('mini_pic_enabled', False):
        return None
    if user.get('mini_pic') and user['mini_pic'] != 'default_mini.jpg':
        return user['mini_pic']
    return None

def safe_text(text):
    if not text:
        return ''
    return str(escape(text)).replace('\n', '<br>')

def get_display_name(user):
    if not user:
        return ''
    return user.get('display_name', user.get('username', ''))

def get_user_badges(user):
    badges = []
    if user.get('is_developer'):
        badges.append({'type': 'developer', 'icon': '👑', 'label': 'مطور'})
    if user.get('is_verified'):
        badges.append({'type': 'verified', 'icon': '✓', 'label': ''})
    return badges

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('الرجاء تسجيل الدخول اولا', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def developer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('الرجاء تسجيل الدخول اولا', 'danger')
            return redirect(url_for('login'))
        user = get_user(session['user_id'])
        if not user or not user.get('is_developer', False):
            flash('هذه الميزة متاحة فقط للمطورين', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

def save_video(file):
    if file and file.filename:
        filename = secure_filename('reel_' + str(int(datetime.utcnow().timestamp())) + '.mp4')
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

def save_image(file, prefix):
    if file and file.filename:
        filename = secure_filename(prefix + '_' + str(int(datetime.utcnow().timestamp())) + '.jpg')
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

def save_mini_pic(file, user_id):
    if file and file.filename:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
        filename = secure_filename(f'mini_{user_id}_{int(datetime.utcnow().timestamp())}.{ext}')
        filepath = os.path.join(app.config['MINI_PIC_FOLDER'], filename)
        
        file.save(filepath)
        
        try:
            img = Image.open(filepath)
            img.thumbnail((40, 40), Image.Resampling.LANCZOS)
            mini_filename = secure_filename(f'mini_{user_id}_{int(datetime.utcnow().timestamp())}.jpg')
            mini_filepath = os.path.join(app.config['MINI_PIC_FOLDER'], mini_filename)
            img.save(mini_filepath, 'JPEG', quality=85)
            os.remove(filepath)
            return mini_filename
        except Exception as e:
            print(f'خطأ في معالجة الصورة المصغرة: {e}')
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

def get_blocked_user_ids(user_id):
    blocks = block_system.get_blocks()
    blocked = []
    for b in blocks:
        if b['blocker_id'] == user_id:
            blocked.append(b['blocked_id'])
        if b['blocked_id'] == user_id:
            blocked.append(b['blocker_id'])
    return list(set(blocked))

def is_user_blocked(user_id, target_id):
    return block_system.is_blocked(user_id, target_id)

def render_user_display(user, size='normal'):
    if not user:
        return ''
    
    display_name = get_display_name(user)
    
    verified_badge = ''
    if user.get('is_verified', False):
        badge_class = 'verified-badge'
        if size == 'small':
            badge_class += ' verified-badge-sm'
        elif size == 'large':
            badge_class += ' verified-badge-lg'
        verified_badge = f'<span class="{badge_class}"><i class="fas fa-check"></i></span>'
    
    dev_badge = ''
    if user.get('is_developer', False):
        dev_badge = '<span class="badge-item badge-developer">👑</span>'
    
    mini_pic_html = ''
    if user.get('mini_pic_enabled', False) and user.get('mini_pic'):
        pic_class = 'mini-profile-pic'
        if size == 'small':
            pic_class += ' mini-profile-pic-sm'
        elif size == 'large':
            pic_class += ' mini-profile-pic-lg'
        
        mini_pic_path = f'/static/mini_pics/{user["mini_pic"]}'
        mini_pic_html = f'<img src="{mini_pic_path}" class="{pic_class}" alt="صورة مصغرة">'
    
    return f'''
    <span class="display-name-wrapper">
        <span class="display-name-text">{display_name}</span>
        <span class="badges-container">
            {verified_badge}
            {dev_badge}
        </span>
        {mini_pic_html}
    </span>
    '''

# ==================== القالب ====================
TEMPLATE = '''
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{ title }} - CAW</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        :root {
            --fb-blue: #1877f2;
            --fb-blue-dark: #0d47a1;
            --fb-gray: #65676b;
            --fb-light-gray: #f0f2f5;
            --fb-white: #ffffff;
            --fb-red: #e74c3c;
            --fb-green: #45bd62;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: var(--fb-light-gray); 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            padding-bottom: 75px; 
            padding-top: 55px; 
            max-width: 100%; 
            overflow-x: hidden; 
            color: #1a1a1e;
        }
        
        .caw-header { 
            background: #ffffff; 
            padding: 5px 8px; 
            position: fixed; 
            top: 0; 
            left: 0; 
            right: 0; 
            z-index: 1000; 
            box-shadow: 0 1px 8px rgba(0,0,0,0.12); 
            height: 50px; 
            display: flex; 
            align-items: center; 
            border-bottom: 1px solid #e4e6eb;
        }
        .caw-header .container { 
            display: flex; 
            align-items: center; 
            justify-content: space-between; 
            width: 100%; 
            padding: 0 5px; 
        }
        .caw-logo { 
            color: var(--fb-blue); 
            font-size: 18px; 
            font-weight: bold; 
            text-decoration: none; 
            white-space: nowrap; 
        }
        .caw-logo i { margin-left: 4px; }
        
        .header-search { 
            background: var(--fb-light-gray); 
            border: none; 
            border-radius: 20px; 
            padding: 4px 12px; 
            display: flex; 
            align-items: center; 
            flex: 1; 
            max-width: 160px; 
            margin: 0 8px; 
        }
        .header-search input { 
            background: transparent; 
            border: none; 
            outline: none; 
            color: #1a1a1e; 
            width: 100%; 
            padding: 4px; 
            font-size: 12px; 
        }
        .header-search input::placeholder { 
            color: var(--fb-gray); 
            font-size: 11px; 
        }
        .header-search i { color: var(--fb-gray); font-size: 13px; }
        
        .header-icons { display: flex; align-items: center; gap: 4px; }
        .header-icon { 
            color: var(--fb-gray); 
            font-size: 18px; 
            padding: 5px 7px; 
            border-radius: 50%; 
            transition: 0.2s; 
            cursor: pointer; 
            position: relative; 
            text-decoration: none; 
            background: transparent; 
            border: none; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
        }
        .header-icon:hover { background: var(--fb-light-gray); }
        .header-icon .badge-count { 
            position: absolute; 
            top: -2px; 
            right: -2px; 
            background: var(--fb-red); 
            color: white; 
            font-size: 8px; 
            border-radius: 50%; 
            padding: 1px 4px; 
            min-width: 14px; 
            text-align: center; 
            box-shadow: 0 0 0 1px white; 
        }
        .header-profile { 
            display: flex; 
            align-items: center; 
            gap: 4px; 
            color: #1a1a1e; 
            text-decoration: none; 
            padding: 3px 6px; 
            border-radius: 20px; 
            transition: 0.2s; 
            cursor: pointer; 
        }
        .header-profile:hover { background: var(--fb-light-gray); }
        .header-profile img { 
            width: 28px; 
            height: 28px; 
            border-radius: 50%; 
            object-fit: cover; 
        }
        .header-profile span { 
            font-weight: 600; 
            font-size: 12px; 
            white-space: nowrap; 
            max-width: 60px; 
            overflow: hidden; 
            text-overflow: ellipsis; 
        }
        
        .bottom-nav { 
            position: fixed; 
            bottom: 0; 
            left: 0; 
            right: 0; 
            background: #ffffff; 
            display: flex; 
            justify-content: space-around; 
            align-items: center; 
            padding: 4px 0; 
            box-shadow: 0 -1px 8px rgba(0,0,0,0.08); 
            z-index: 999; 
            border-top: 1px solid #e4e6eb; 
            height: 58px; 
        }
        .bottom-nav a { 
            color: var(--fb-gray); 
            text-decoration: none; 
            font-size: 10px; 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            gap: 1px; 
            padding: 4px 10px; 
            border-radius: 8px; 
            transition: 0.2s; 
            position: relative; 
            min-width: 50px; 
        }
        .bottom-nav a i { font-size: 22px; }
        .bottom-nav a.active { color: var(--fb-blue); }
        .bottom-nav a:hover { background: var(--fb-light-gray); }
        .bottom-nav a .nav-label { font-size: 9px; margin-top: 1px; }
        
        .caw-main { 
            padding: 8px 10px 70px; 
            max-width: 500px; 
            margin: 0 auto; 
        }
        
        .post-card, .reel-card { 
            background: #ffffff; 
            border: none; 
            border-radius: 12px; 
            padding: 12px; 
            margin-bottom: 12px; 
            box-shadow: 0 1px 4px rgba(0,0,0,0.08); 
        }
        .post-header { 
            display: flex; 
            align-items: center; 
            justify-content: space-between; 
        }
        .post-user { 
            display: flex; 
            align-items: center; 
            gap: 8px; 
            cursor: pointer; 
            text-decoration: none; 
            color: #1a1a1e; 
        }
        .post-user img { 
            width: 36px; 
            height: 36px; 
            border-radius: 50%; 
            object-fit: cover; 
        }
        .post-user .display-name { 
            font-weight: 600; 
            font-size: 14px; 
        }
        .post-user .time { 
            font-size: 10px; 
            color: var(--fb-gray); 
        }
        .post-content { 
            margin: 8px 0; 
            font-size: 14px; 
            line-height: 1.6; 
            color: #1a1a1e; 
            word-wrap: break-word;
        }
        .post-image { 
            max-width: 100%; 
            border-radius: 8px; 
            margin-top: 6px; 
            max-height: 350px; 
            object-fit: cover; 
            cursor: pointer; 
            width: 100%;
        }
        .post-actions { 
            display: flex; 
            gap: 4px; 
            margin-top: 8px; 
            padding-top: 8px; 
            border-top: 1px solid #e4e6eb; 
        }
        .post-actions button { 
            flex: 1; 
            border: none; 
            background: none; 
            padding: 6px; 
            border-radius: 8px; 
            font-weight: 600; 
            color: var(--fb-gray); 
            transition: 0.2s; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            gap: 6px; 
            font-size: 13px; 
        }
        .post-actions button:hover { 
            background: var(--fb-light-gray); 
            color: var(--fb-blue); 
        }
        .post-actions button.liked { 
            color: var(--fb-blue); 
        }
        .post-actions button.liked-reel { 
            color: var(--fb-red); 
        }
        .post-actions button .like-count { font-weight: 600; }
        
        .post-comments { 
            margin-top: 8px; 
            border-top: 1px solid #e4e6eb; 
            padding-top: 8px; 
        }
        .comment-item { 
            display: flex; 
            gap: 6px; 
            margin-bottom: 6px; 
            align-items: flex-start;
        }
        .comment-item img { 
            width: 28px; 
            height: 28px; 
            border-radius: 50%; 
            object-fit: cover; 
            flex-shrink: 0;
        }
        .comment-item .comment-text { 
            background: var(--fb-light-gray); 
            padding: 6px 12px; 
            border-radius: 16px; 
            flex: 1; 
            font-size: 13px; 
            color: #1a1a1e; 
            word-wrap: break-word;
        }
        .comment-item .comment-text .comment-display-name { 
            font-weight: 600; 
            margin-left: 4px; 
            color: var(--fb-blue); 
        }
        .comment-more { 
            color: var(--fb-gray); 
            font-size: 12px; 
            cursor: pointer; 
        }
        .comment-more:hover { 
            text-decoration: underline; 
            color: var(--fb-blue); 
        }
        .comment-image { 
            max-width: 120px; 
            border-radius: 8px; 
            margin-top: 4px; 
            cursor: pointer; 
        }
        
        .reel-video { 
            width: 100%; 
            border-radius: 8px; 
            max-height: 400px; 
            background: #000;
        }
        
        .create-post { 
            background: #ffffff; 
            border: none; 
            border-radius: 12px; 
            padding: 12px; 
            margin-bottom: 12px; 
            box-shadow: 0 1px 4px rgba(0,0,0,0.08); 
        }
        .create-post-top { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
        }
        .create-post-top img { 
            width: 36px; 
            height: 36px; 
            border-radius: 50%; 
            object-fit: cover; 
            cursor: pointer; 
        }
        .create-post-top input { 
            flex: 1; 
            border: none; 
            background: var(--fb-light-gray); 
            color: #1a1a1e; 
            padding: 8px 14px; 
            border-radius: 20px; 
            font-size: 14px; 
            outline: none; 
        }
        .create-post-top input::placeholder { 
            color: var(--fb-gray); 
        }
        .create-post-divider { 
            height: 1px; 
            background: #e4e6eb; 
            margin: 8px 0; 
        }
        .create-post-bottom { 
            display: flex; 
            gap: 6px; 
        }
        .create-post-bottom button { 
            flex: 1; 
            border: none; 
            background: none; 
            padding: 6px; 
            border-radius: 8px; 
            font-weight: 600; 
            color: var(--fb-gray); 
            transition: 0.2s; 
            font-size: 13px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            gap: 6px; 
        }
        .create-post-bottom button:hover { 
            background: var(--fb-light-gray); 
        }
        .create-post-bottom .btn-photo { color: var(--fb-green); }
        .create-post-bottom .btn-video { color: var(--fb-red); }
        
        .modal-content { 
            border-radius: 14px; 
            background: #ffffff; 
            color: #1a1a1e; 
            border: none; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        .modal-header { 
            border-bottom: 1px solid #e4e6eb; 
            padding: 12px 16px; 
        }
        .modal-header .btn-close { font-size: 12px; }
        
        .comments-list { 
            max-height: 400px; 
            overflow-y: auto; 
            padding: 0 12px;
        }
        .comment-modal-item { 
            display: flex; 
            gap: 10px; 
            padding: 10px 0; 
            border-bottom: 1px solid #e4e6eb; 
        }
        .comment-modal-item img { 
            width: 32px; 
            height: 32px; 
            border-radius: 50%; 
            object-fit: cover; 
            flex-shrink: 0;
        }
        .comment-modal-item .text { flex: 1; }
        .comment-modal-item .text strong { 
            display: block; 
            font-size: 13px; 
            color: var(--fb-blue); 
        }
        .comment-modal-item .text span { font-size: 13px; }
        .comment-modal-item .text small { color: var(--fb-gray); font-size: 10px; }
        .comment-modal-image { 
            max-width: 100%; 
            border-radius: 8px; 
            margin-top: 4px; 
            cursor: pointer; 
            max-height: 200px;
        }
        
        .reel-upload-btn { 
            background: var(--fb-blue); 
            color: white; 
            border: none; 
            padding: 6px 16px; 
            border-radius: 20px; 
            font-weight: 600; 
            transition: 0.2s; 
            cursor: pointer; 
            font-size: 13px; 
            display: inline-flex; 
            align-items: center; 
            gap: 6px; 
            box-shadow: 0 2px 8px rgba(24,119,242,0.3); 
        }
        .reel-upload-btn:hover { 
            transform: scale(1.02); 
            opacity: 0.92; 
        }
        
        .three-dots { 
            background: none; 
            border: none; 
            padding: 4px 8px; 
            border-radius: 50%; 
            transition: 0.2s; 
            font-size: 16px; 
            color: var(--fb-gray); 
        }
        .three-dots:hover { 
            background: var(--fb-light-gray); 
        }
        
        .verified-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #4aa8ff, #1877f2 60%, #0e5fcc);
            color: white;
            width: 18px;
            height: 18px;
            font-size: 10px;
            font-weight: bold;
            margin-right: 2px;
            vertical-align: middle;
            flex-shrink: 0;
            clip-path: polygon(99.0% 50.0%, 94.2% 55.8%, 86.5% 59.8%, 85.8% 64.8%, 89.8% 73.0%, 88.7% 79.7%, 80.4% 80.4%, 72.6% 79.5%, 70.0% 84.6%, 68.1% 93.6%, 62.5% 96.6%, 55.4% 91.1%, 50.0% 87.0%, 44.6% 91.1%, 37.5% 96.6%, 31.9% 93.6%, 30.0% 84.6%, 27.4% 79.5%, 19.6% 80.4%, 11.3% 79.7%, 10.2% 73.0%, 14.2% 64.8%, 13.5% 59.8%, 5.8% 55.8%, 1.0% 50.0%, 5.8% 44.2%, 13.5% 40.2%, 14.2% 35.2%, 10.2% 27.0%, 11.3% 20.3%, 19.6% 19.6%, 27.4% 20.5%, 30.0% 15.4%, 31.9% 6.4%, 37.5% 3.4%, 44.6% 8.9%, 50.0% 13.0%, 55.4% 8.9%, 62.5% 3.4%, 68.1% 6.4%, 70.0% 15.4%, 72.6% 20.5%, 80.4% 19.6%, 88.7% 20.3%, 89.8% 27.0%, 85.8% 35.2%, 86.5% 40.2%, 94.2% 44.2%);
        }
        .verified-badge i { font-size: 9px; margin: 0; }
        .verified-badge-lg { width: 22px; height: 22px; font-size: 12px; }
        .verified-badge-sm { width: 14px; height: 14px; font-size: 7px; }
        
        .mini-profile-pic {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            object-fit: cover;
            margin-right: 3px;
            vertical-align: middle;
            border: 2px solid var(--fb-blue);
            display: inline-block;
            background: white;
        }
        .mini-profile-pic-sm { width: 16px; height: 16px; border-width: 1.5px; }
        .mini-profile-pic-lg { width: 26px; height: 26px; border-width: 2px; }
        
        .display-name-wrapper {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            flex-wrap: wrap;
        }
        .display-name-wrapper .display-name-text { font-weight: 600; }
        .display-name-wrapper .badges-container {
            display: inline-flex;
            align-items: center;
            gap: 1px;
        }
        
        .badge-item {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 9px;
            font-weight: 600;
            margin-right: 1px;
            vertical-align: middle;
        }
        .badge-developer { background: #ffd700; color: #000; }
        
        .notification-dropdown { 
            min-width: 300px; 
            max-height: 400px; 
            overflow-y: auto; 
            padding: 0; 
            background: #ffffff; 
            border: none; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            border-radius: 12px;
        }
        .notification-item { 
            padding: 10px 14px; 
            border-bottom: 1px solid #e4e6eb; 
            transition: 0.2s; 
            font-size: 13px; 
        }
        .notification-item:hover { background: var(--fb-light-gray); }
        .notification-item.unread { background: #e7f3ff; }
        .notification-item a { 
            text-decoration: none; 
            color: #1a1a1e; 
            display: block; 
        }
        .notification-item small { color: var(--fb-gray); font-size: 10px; }
        
        .blocked-banner {
            background: #fde8e8;
            border: 1px solid var(--fb-red);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            color: var(--fb-red);
            margin: 10px 0;
        }
        .blocked-banner i { font-size: 40px; display: block; margin-bottom: 10px; }
        .blocked-banner h6 { font-weight: bold; font-size: 16px; }
        
        .chat-box::-webkit-scrollbar {
            width: 6px;
        }
        .chat-box::-webkit-scrollbar-track {
            background: transparent;
        }
        .chat-box::-webkit-scrollbar-thumb {
            background: #c1c7cd;
            border-radius: 10px;
        }
        .chat-message-image {
            max-width: 150px;
            border-radius: 10px;
            margin-top: 4px;
            cursor: pointer;
        }
        .file-input-wrapper {
            display: flex;
            align-items: center;
        }
        .file-input-wrapper .chat-image-icon {
            padding: 8px 10px;
            border-radius: 50%;
            transition: 0.2s;
        }
        .file-input-wrapper .chat-image-icon:hover {
            background: var(--fb-light-gray);
        }
        
        .btn-primary {
            background: var(--fb-blue);
            border: none;
        }
        .btn-primary:hover {
            background: var(--fb-blue-dark);
        }
        .btn-success {
            background: var(--fb-green);
            border: none;
        }
        .btn-danger {
            background: var(--fb-red);
            border: none;
        }
        
        .dropdown-menu {
            border: none;
            box-shadow: 0 4px 20px rgba(0,0,0,0.12);
            border-radius: 12px;
            padding: 6px 0;
        }
        .dropdown-item {
            font-size: 13px;
            padding: 8px 16px;
        }
        .dropdown-item:hover {
            background: var(--fb-light-gray);
        }
        .dropdown-item.text-danger:hover {
            background: #fde8e8;
        }
        
        #searchResults { 
            position: fixed; 
            top: 50px; 
            left: 5px; 
            right: 5px; 
            background: #ffffff; 
            border: none; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.15); 
            z-index: 9999; 
            max-height: 350px; 
            overflow-y: auto; 
            display: none; 
        }
        .search-result-item { 
            padding: 10px 14px; 
            border-bottom: 1px solid #e4e6eb; 
            display: flex; 
            align-items: center; 
            justify-content: space-between; 
        }
        .search-result-item:last-child { border-bottom: none; }
        .search-result-item img { 
            width: 32px; 
            height: 32px; 
            border-radius: 50%; 
            object-fit: cover; 
            margin-left: 10px; 
        }
        .search-result-item .result-name { 
            font-weight: 600; 
            font-size: 13px; 
            color: #1a1a1e;
            text-decoration: none;
        }
        .search-result-item .result-name:hover { color: var(--fb-blue); }
        
        .report-reasons-list { 
            display: flex; 
            flex-direction: column; 
            border: none; 
            border-radius: 12px; 
            overflow: hidden; 
        }
        .report-reason-btn { 
            display: flex; 
            align-items: center; 
            gap: 12px; 
            width: 100%; 
            border: none; 
            background: none; 
            color: #1a1a1e; 
            padding: 12px 14px; 
            font-size: 13px; 
            text-align: right; 
            border-bottom: 1px solid #e4e6eb; 
            transition: 0.15s; 
            cursor: pointer; 
        }
        .report-reason-btn:last-child { border-bottom: none; }
        .report-reason-btn:hover { 
            background: #fde8e8; 
        }
        .report-reason-icon { 
            width: 28px; 
            height: 28px; 
            flex-shrink: 0; 
            border-radius: 50%; 
            background: #fde8e8; 
            color: var(--fb-red); 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 13px; 
        }
        .report-reason-text { flex: 1; }
        .report-reason-arrow { font-size: 10px; color: var(--fb-gray); }
        
        @media (max-width: 400px) {
            .caw-logo { font-size: 16px; }
            .header-search { max-width: 100px; }
            .header-search input { font-size: 10px; }
            .header-icon { font-size: 16px; padding: 4px 6px; }
            .header-profile span { font-size: 10px; max-width: 40px; }
            .bottom-nav a i { font-size: 20px; }
            .bottom-nav a .nav-label { font-size: 8px; }
            .post-user .display-name { font-size: 13px; }
            .post-content { font-size: 13px; }
            .post-actions button { font-size: 12px; }
        }
    </style>
</head>
<body>
    <header class="caw-header">
        <div class="container">
            <a href="/home" class="caw-logo"><i class="fas fa-comment-dots"></i> CAW</a>
            <div class="header-search">
                <i class="fas fa-search"></i>
                <input type="text" id="headerSearch" placeholder="بحث..." onkeyup="searchUsers()">
            </div>
            <div class="header-icons">
                <div class="dropdown" style="display:inline-block;">
                    <button class="header-icon" data-bs-toggle="dropdown">
                        <i class="fas fa-bell"></i>
                        {% if unread_notifications > 0 %}
                        <span class="badge-count">{{ unread_notifications }}</span>
                        {% endif %}
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end notification-dropdown">
                        <li class="dropdown-header fw-bold px-3 py-2">الإشعارات</li>
                        <li><hr class="dropdown-divider m-0"></li>
                        <div id="notificationsList">
                            {% for n in notifications[:8] %}
                            <li class="notification-item {% if not n.is_read %}unread{% endif %}">
                                <a href="{{ n.link or '#' }}">
                                    {{ n.message }}
                                    <br>
                                    <small class="text-muted">{{ n.created_at[:19] }}</small>
                                </a>
                            </li>
                            {% else %}
                            <li class="text-muted text-center p-3">لا توجد إشعارات</li>
                            {% endfor %}
                        </div>
                        <li><hr class="dropdown-divider m-0"></li>
                        <li><a class="dropdown-item text-center" href="/notifications">عرض الكل</a></li>
                    </ul>
                </div>
                <div class="dropdown" style="display:inline-block;">
                    <button class="header-profile" data-bs-toggle="dropdown">
                        <img src="/static/uploads/{{ user.profile_pic if user and user.profile_pic and user.profile_pic != 'default.jpg' and user.profile_pic != 'default_profile.jpg' else 'default_profile.jpg' }}">
                        <span>{{ user.display_name if user else '' }}</span>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="/profile/{{ session.user_id }}"><i class="fas fa-user me-2"></i> ملفي</a></li>
                        <li><a class="dropdown-item" href="/edit_profile"><i class="fas fa-edit me-2"></i> تعديل</a></li>
                        <li><a class="dropdown-item" href="/change_display_name"><i class="fas fa-tag me-2"></i> تغيير الاسم الظاهر</a></li>
                        <li><a class="dropdown-item" href="/change_username"><i class="fas fa-user-tag me-2"></i> تغيير اسم المستخدم</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="/create_reel"><i class="fas fa-video me-2"></i> رفع ريلز</a></li>
                        <li><a class="dropdown-item" href="/create_group_chat"><i class="fas fa-comments me-2"></i> دردشة جماعية</a></li>
                        {% if user and user.mini_pic_enabled %}
                        <li><a class="dropdown-item" href="/upload_mini_pic"><i class="fas fa-image me-2"></i> رفع صورة مصغرة</a></li>
                        {% endif %}
                        <li><a class="dropdown-item" href="/blocked_users"><i class="fas fa-ban me-2"></i> المستخدمين المحظورين</a></li>
                        {% if user and user.is_developer %}
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-warning" href="/developer_panel"><i class="fas fa-tools me-2"></i> لوحة المطور</a></li>
                        <li><a class="dropdown-item" href="/security_stats"><i class="fas fa-shield-alt me-2"></i> إحصائيات الحماية</a></li>
                        <li><a class="dropdown-item" href="/manage_mini_pics"><i class="fas fa-images me-2"></i> إدارة الصور المصغرة</a></li>
                        <li><a class="dropdown-item" href="/reports_panel"><i class="fas fa-flag me-2"></i> البلاغات</a></li>
                        {% endif %}
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href="/logout"><i class="fas fa-sign-out-alt me-2"></i> خروج</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </header>

    <nav class="bottom-nav">
        <a href="/home" class="active"><i class="fas fa-home"></i><span class="nav-label">الرئيسية</span></a>
        <a href="/reels"><i class="fas fa-film"></i><span class="nav-label">الريلزات</span></a>
        <a href="/friends"><i class="fas fa-user-friends"></i><span class="nav-label">الأصدقاء</span></a>
        <a href="/messages"><i class="fas fa-envelope"></i><span class="nav-label">الرسائل</span></a>
        <a href="/group_chats"><i class="fas fa-comments" style="color:#1877f2;"></i><span class="nav-label">مجموعات</span></a>
    </nav>

    <div class="caw-main">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" style="font-size:13px;padding:8px 12px;border-radius:10px;">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" style="font-size:10px;"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {{ content|safe }}
    </div>

    <!-- مودال عرض الصورة -->
    <div class="modal fade" id="imageModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content bg-dark">
                <div class="modal-body text-center p-2">
                    <img id="modalImage" style="max-width:100%; max-height:80vh; border-radius:8px;">
                </div>
                <div class="modal-footer border-0 p-2">
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">إغلاق</button>
                </div>
            </div>
        </div>
    </div>

    <!-- مودال عرض التعليقات -->
    <div class="modal fade" id="commentsModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h6 class="modal-title"><i class="fas fa-comments"></i> التعليقات</h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body comments-list" id="commentsModalBody"></div>
            </div>
        </div>
    </div>

    <!-- مودال إضافة تعليق -->
    <div class="modal fade" id="commentModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h6 class="modal-title"><i class="fas fa-comment"></i> إضافة تعليق</h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="d-flex gap-2 mb-2">
                        <img id="commentUserPic" src="/static/uploads/{{ user.profile_pic if user else 'default_profile.jpg' }}" style="width:38px;height:38px;border-radius:50%;object-fit:cover;">
                        <div style="flex:1;">
                            <textarea id="commentContent" class="form-control" rows="3" placeholder="اكتب تعليقك..." style="border-radius:12px;font-size:14px;resize:none;border:1px solid #e4e6eb;"></textarea>
                            <div id="commentImagePreview" style="display:none;margin-top:8px;position:relative;">
                                <img id="commentPreviewImg" src="" style="max-width:100%;max-height:150px;border-radius:8px;border:1px solid #e4e6eb;">
                                <button type="button" class="btn btn-sm btn-danger" onclick="removeCommentImage()" style="position:absolute;top:4px;right:4px;border-radius:50%;padding:2px 6px;font-size:12px;">✕</button>
                            </div>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button class="btn btn-outline-secondary btn-sm" onclick="document.getElementById('commentImageInput').click()" style="font-size:13px;border-radius:20px;">
                            <i class="fas fa-image"></i> صورة
                        </button>
                        <input type="file" id="commentImageInput" accept="image/*" style="display:none;" onchange="previewCommentImage(event)">
                        <button class="btn btn-primary btn-sm" onclick="submitComment()" style="margin-right:auto;border-radius:20px;font-size:13px;padding:6px 16px;">
                            <i class="fas fa-paper-plane"></i> نشر
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- مودال الإبلاغ -->
    <div class="modal fade" id="reportModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h6 class="modal-title"><i class="fas fa-flag" style="color:#e74c3c;"></i> الإبلاغ</h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p class="text-muted small mb-2">اختر سبب الإبلاغ، وسيتم مراجعة البلاغ من قِبل فريق الإدارة</p>
                    <div id="reportReasons" class="report-reasons-list">
                        {% for icon, reason in report_reasons %}
                        <button type="button" class="report-reason-btn" onclick="submitReport('{{ reason }}')">
                            <span class="report-reason-icon"><i class="fas {{ icon }}"></i></span>
                            <span class="report-reason-text">{{ reason }}</span>
                            <i class="fas fa-chevron-left report-reason-arrow"></i>
                        </button>
                        {% endfor %}
                    </div>
                    <div class="form-check mt-2" id="reportBlockTooWrap" style="display:none;">
                        <input class="form-check-input" type="checkbox" id="reportBlockToo">
                        <label class="form-check-label small text-muted" for="reportBlockToo">حظر هذا المستخدم أيضاً</label>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // متغيرات للتعليق
    var commentItemId = null;
    var commentType = null;
    var commentImageData = null;

    // عرض الصورة
    function showImage(src) {
        document.getElementById('modalImage').src = src;
        new bootstrap.Modal(document.getElementById('imageModal')).show();
    }
    
    // حذف منشور
    function deletePost(postId) {
        if(confirm('هل أنت متأكد من حذف هذا المنشور؟')) {
            fetch('/delete_post/' + postId, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if(data.success) location.reload();
                    else alert('خطأ');
                })
                .catch(() => alert('تعذر الاتصال بالخادم'));
        }
    }

    // حذف ريلز
    function deleteReel(reelId) {
        if(confirm('هل أنت متأكد من حذف هذا الريلز؟')) {
            fetch('/delete_reel/' + reelId, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if(data.success) location.reload();
                    else alert('خطأ');
                })
                .catch(() => alert('تعذر الاتصال بالخادم'));
        }
    }
    
    // إعجاب بمنشور
    function likePost(postId, btn) {
        fetch('/like_post/' + postId, {method: 'POST'})
            .then(res => res.json())
            .then(data => {
                $(btn).find('.like-count').text(data.likes);
                if(data.liked) $(btn).addClass('liked');
                else $(btn).removeClass('liked');
            })
            .catch(() => alert('تعذر تسجيل الإعجاب'));
    }
    
    // إعجاب بريلز
    function likeReel(reelId, btn) {
        fetch('/like_reel/' + reelId, {method: 'POST'})
            .then(res => res.json())
            .then(data => {
                $(btn).find('.like-count').text(data.likes);
                if(data.liked) $(btn).addClass('liked-reel');
                else $(btn).removeClass('liked-reel');
            })
            .catch(() => alert('تعذر تسجيل الإعجاب'));
    }
    
    // فتح مودال التعليق
    function openCommentModal(itemId, type) {
        commentItemId = itemId;
        commentType = type;
        commentImageData = null;
        document.getElementById('commentContent').value = '';
        document.getElementById('commentImagePreview').style.display = 'none';
        document.getElementById('commentPreviewImg').src = '';
        document.getElementById('commentImageInput').value = '';
        new bootstrap.Modal(document.getElementById('commentModal')).show();
    }
    
    // معاينة صورة التعليق
    function previewCommentImage(event) {
        var file = event.target.files[0];
        if (file) {
            var reader = new FileReader();
            reader.onload = function(e) {
                commentImageData = e.target.result;
                document.getElementById('commentPreviewImg').src = e.target.result;
                document.getElementById('commentImagePreview').style.display = 'block';
            };
            reader.readAsDataURL(file);
        }
    }
    
    // إزالة صورة التعليق
    function removeCommentImage() {
        commentImageData = null;
        document.getElementById('commentImagePreview').style.display = 'none';
        document.getElementById('commentPreviewImg').src = '';
        document.getElementById('commentImageInput').value = '';
    }
    
    // إرسال التعليق
    function submitComment() {
        var content = document.getElementById('commentContent').value.trim();
        if (!content && !commentImageData) {
            alert('الرجاء كتابة تعليق أو إضافة صورة');
            return;
        }
        
        var formData = new FormData();
        formData.append('content', content);
        formData.append('item_id', commentItemId);
        formData.append('type', commentType);
        
        if (commentImageData) {
            fetch(commentImageData)
                .then(res => res.blob())
                .then(blob => {
                    formData.append('image', blob, 'comment.jpg');
                    sendComment(formData);
                });
        } else {
            sendComment(formData);
        }
    }
    
    function sendComment(formData) {
        fetch('/add_comment', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if(data.success) {
                bootstrap.Modal.getInstance(document.getElementById('commentModal')).hide();
                location.reload();
            } else {
                alert('حدث خطأ: ' + (data.error || 'غير معروف'));
            }
        })
        .catch(() => alert('حدث خطأ في الاتصال'));
    }
    
    // عرض جميع التعليقات
    function showAllComments(itemId, type) {
        fetch('/get_comments/' + itemId + '/' + type)
            .then(res => res.json())
            .then(data => {
                var html = '';
                if(data.length === 0) {
                    html = '<p class="text-muted text-center p-3">لا توجد تعليقات</p>';
                } else {
                    data.forEach(function(c) {
                        var imageHtml = '';
                        if(c.image) {
                            imageHtml = '<img src="/static/uploads/' + c.image + '" class="comment-modal-image" onclick="showImage(this.src)">';
                        }
                        var miniPicHtml = '';
                        if(c.mini_pic) {
                            miniPicHtml = ' <img src="/static/mini_pics/' + c.mini_pic + '" style="width:16px;height:16px;border-radius:50%;vertical-align:middle;border:1px solid #1877f2;">';
                        }
                        var verifiedHtml = c.is_verified ? ' <span class="verified-badge" style="width:16px;height:16px;font-size:8px;"><i class="fas fa-check"></i></span>' : '';
                        var devHtml = c.is_developer ? ' 👑' : '';
                        html += '<div class="comment-modal-item">' +
                            '<img src="/static/uploads/' + c.profile_pic + '">' +
                            '<div class="text">' +
                                '<strong>' + c.display_name + '</strong>' +
                                verifiedHtml + devHtml + miniPicHtml +
                                '<div><span>' + c.content + '</span></div>' +
                                imageHtml +
                                '<small>' + c.created_at + '</small>' +
                            '</div>' +
                        '</div>';
                    });
                }
                document.getElementById('commentsModalBody').innerHTML = html;
                new bootstrap.Modal(document.getElementById('commentsModal')).show();
            });
    }
    
    // قبول صداقة
    function acceptFriend(userId) {
        fetch('/accept_friend/' + userId, {method: 'POST'})
            .then(res => res.json())
            .then(data => {
                if(data.success) location.reload();
                else alert('حدث خطأ');
            });
    }
    
    // إرسال طلب صداقة
    function sendFriendRequest(userId) {
        fetch('/send_friend_request/' + userId, {method: 'POST'})
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    alert('تم ارسال الطلب');
                    location.reload();
                } else {
                    alert(data.error || 'حدث خطأ');
                }
            });
    }
    
    // حظر مستخدم
    function blockUser(userId) {
        if(confirm('هل أنت متأكد من حظر هذا المستخدم؟\nلن يتمكن من رؤية أي منشوراتك أو ملفك الشخصي.')) {
            fetch('/block_user/' + userId, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if(data.success) {
                        alert('تم حظر المستخدم بنجاح');
                        location.reload();
                    } else {
                        alert(data.error || 'حدث خطأ');
                    }
                });
        }
    }
    
    // إلغاء حظر مستخدم
    function unblockUser(userId) {
        if(confirm('هل تريد إلغاء حظر هذا المستخدم؟')) {
            fetch('/unblock_user/' + userId, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if(data.success) {
                        alert('تم إلغاء الحظر');
                        location.reload();
                    } else {
                        alert('حدث خطأ');
                    }
                });
        }
    }
    
    // فتح مودال الإبلاغ
    var reportTargetId = null;
    var reportTargetType = null;
    var reportContentId = null;
    
    function openReportModal(targetId, targetType, contentId) {
        reportTargetId = targetId;
        reportTargetType = targetType;
        reportContentId = contentId || null;
        document.getElementById('reportBlockTooWrap').style.display = (targetType === 'user') ? 'block' : 'none';
        document.getElementById('reportBlockToo').checked = false;
        new bootstrap.Modal(document.getElementById('reportModal')).show();
    }
    
    // إرسال البلاغ
    function submitReport(reason) {
        if (!reportTargetId) return;
        var blockToo = document.getElementById('reportBlockToo').checked;
        
        fetch('/report', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target_id: reportTargetId,
                target_type: reportTargetType,
                content_id: reportContentId,
                reason: reason
            })
        })
        .then(res => res.json())
        .then(data => {
            bootstrap.Modal.getInstance(document.getElementById('reportModal')).hide();
            if(data.success) {
                if (blockToo && reportTargetType === 'user') {
                    fetch('/block_user/' + reportTargetId, {method: 'POST'})
                        .then(() => { alert('تم إرسال البلاغ وحظر المستخدم'); location.reload(); });
                } else {
                    alert('تم إرسال البلاغ بنجاح، سيتم مراجعته من قبل الإدارة');
                }
            } else {
                alert(data.error || 'حدث خطأ');
            }
        })
        .catch(() => alert('تعذر إرسال البلاغ، تحقق من الاتصال'));
    }
    
    // البحث عن مستخدمين
    function searchUsers() {
        var query = document.getElementById('headerSearch').value;
        if(query.length < 1) { $('#searchResults').hide(); return; }
        fetch('/search_users/' + query)
            .then(res => res.json())
            .then(data => {
                var html = '';
                if(data.length > 0) {
                    data.forEach(function(u) {
                        html += '<div class="search-result-item">' +
                            '<div class="d-flex align-items-center">' +
                                '<a href="/profile/' + u.id + '"><img src="/static/uploads/' + (u.profile_pic || "default_profile.jpg") + '"></a>' +
                                '<a href="/profile/' + u.id + '" class="result-name">' + u.display_name + '</a>' +
                            '</div>' +
                            '<div>' +
                                (u.is_friend ? '<span class="badge bg-success">صديق</span>' : '') +
                                (u.pending_sent ? '<span class="badge bg-secondary">مرسل</span>' : '') +
                                (u.pending_received ? '<button class="btn btn-sm btn-success" onclick="acceptFriend(' + u.id + ')">قبول</button>' : '') +
                                (!u.is_friend && !u.pending_sent && !u.pending_received ? '<button class="btn btn-sm btn-primary" onclick="sendFriendRequest(' + u.id + ')">+</button>' : '') +
                            '</div>' +
                        '</div>';
                    });
                } else {
                    html = '<div class="p-3 text-muted text-center">لا توجد نتائج</div>';
                }
                $('#searchResults').html(html).show();
            });
    }
    
    $(document).click(function(e) {
        if(!$(e.target).closest('#headerSearch').length && !$(e.target).closest('#searchResults').length) {
            $('#searchResults').hide();
        }
    });
    
    $(document).ready(function() {
        var path = window.location.pathname;
        $('.bottom-nav a').each(function() {
            var href = $(this).attr('href');
            if(path === href || (href !== '/' && path.startsWith(href))) {
                $(this).addClass('active');
            } else {
                $(this).removeClass('active');
            }
        });
    });
    </script>
</body>
</html>
'''

# ==================== دوال الإبلاغ والحظر ====================
@app.route('/report', methods=['POST'])
@login_required
def report_content():
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        target_type = data.get('target_type')
        reason = data.get('reason')
        content_id = data.get('content_id')
        
        if not target_id or not target_type or not reason:
            return jsonify({'success': False, 'error': 'بيانات غير مكتملة'})
        
        if target_type == 'user':
            target = get_user(target_id)
            if not target:
                return jsonify({'success': False, 'error': 'المستخدم غير موجود'})
            if target_id == session['user_id']:
                return jsonify({'success': False, 'error': 'لا يمكن الإبلاغ عن نفسك'})
        
        success = report_system.add_report(
            reporter_id=session['user_id'],
            target_id=target_id,
            target_type=target_type,
            reason=reason,
            content_id=content_id
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'تم الإبلاغ عن هذا المحتوى مسبقاً'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user_route(user_id):
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'لا يمكن حظر نفسك'})
    
    user = get_user(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'المستخدم غير موجود'})
    
    if block_system.is_blocked(session['user_id'], user_id):
        return jsonify({'success': False, 'error': 'المستخدم محظور بالفعل'})
    
    success = block_system.block_user(session['user_id'], user_id)
    return jsonify({'success': success})

@app.route('/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user_route(user_id):
    success = block_system.unblock_user(session['user_id'], user_id)
    return jsonify({'success': success})

@app.route('/blocked_users')
@login_required
def blocked_users():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    blocked_users = []
    for uid in blocked_ids:
        user = get_user(uid)
        if user:
            blocked_users.append(user)
    
    content = '''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-danger text-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-ban"></i> المستخدمين المحظورين</h6>
            <small style="font-size:10px;">هؤلاء المستخدمين لا يمكنهم رؤية أي من محتواك</small>
        </div>
        <div class="card-body p-3">
    '''
    
    if blocked_users:
        for u in blocked_users:
            u_pic = get_profile_pic(u)
            name_display = render_user_display(u)
            content += f'''
            <div class="d-flex align-items-center justify-content-between border-bottom p-2">
                <div class="d-flex align-items-center gap-2">
                    <img src="/static/uploads/{u_pic}" style="width:36px;height:36px;border-radius:50%;object-fit:cover;">
                    <div>
                        {name_display}
                        <br>
                        <small class="text-muted" style="font-size:10px;">@{u['username']}</small>
                    </div>
                </div>
                <button class="btn btn-sm btn-success" onclick="unblockUser({u['id']})" style="font-size:11px;padding:4px 12px;border-radius:20px;">
                    <i class="fas fa-unlock"></i> إلغاء الحظر
                </button>
            </div>
            '''
    else:
        content += '<div class="text-muted text-center p-3" style="font-size:13px;">لا يوجد مستخدمين محظورين</div>'
    
    content += '''
        </div>
    </div>
    '''
    return render_page('المستخدمين المحظورين', content)

@app.route('/reports_panel')
@developer_required
def reports_panel():
    reports = report_system.get_reports()
    reports.reverse()
    
    content = '''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-danger text-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-flag"></i> لوحة البلاغات</h6>
            <small style="font-size:10px;">البلاغات المقدمة من المستخدمين</small>
        </div>
        <div class="card-body p-3">
    '''
    
    if reports:
        for r in reports:
            reporter = get_user(r['reporter_id'])
            target = None
            if r['target_type'] == 'user':
                target = get_user(r['target_id'])
            
            status_badge = 'warning'
            status_text = 'قيد المراجعة'
            if r['status'] == 'resolved':
                status_badge = 'success'
                status_text = 'تم الحل'
            elif r['status'] == 'rejected':
                status_badge = 'danger'
                status_text = 'مرفوض'
            
            content += f'''
            <div class="border-bottom p-2" style="font-size:12px;">
                <div class="d-flex justify-content-between">
                    <strong>🔄 {r['target_type']}</strong>
                    <span class="badge bg-{status_badge}">{status_text}</span>
                </div>
                <div>
                    <small>من: {get_display_name(reporter) if reporter else 'غير معروف'}</small>
                    <br>
                    <small>الهدف: {get_display_name(target) if target else r['target_id']}</small>
                    <br>
                    <small>السبب: {r['reason']}</small>
                    <br>
                    <small class="text-muted">{r['created_at'][:19]}</small>
                </div>
                <div class="mt-1">
                    <button class="btn btn-sm btn-success" onclick="resolveReport({r['id']})" style="font-size:9px;padding:2px 10px;border-radius:15px;">حل</button>
                    <button class="btn btn-sm btn-danger" onclick="rejectReport({r['id']})" style="font-size:9px;padding:2px 10px;border-radius:15px;">رفض</button>
                </div>
            </div>
            '''
    else:
        content += '<div class="text-muted text-center p-3" style="font-size:13px;">لا توجد بلاغات</div>'
    
    content += '''
        </div>
    </div>
    
    <script>
    function resolveReport(reportId) {
        if(confirm('تأكيد حل البلاغ؟')) {
            fetch('/resolve_report/' + reportId, {method: 'POST'}).then(() => location.reload());
        }
    }
    function rejectReport(reportId) {
        if(confirm('تأكيد رفض البلاغ؟')) {
            fetch('/reject_report/' + reportId, {method: 'POST'}).then(() => location.reload());
        }
    }
    </script>
    '''
    return render_page('لوحة البلاغات', content)

@app.route('/resolve_report/<int:report_id>', methods=['POST'])
@developer_required
def resolve_report(report_id):
    reports = report_system.get_reports()
    for r in reports:
        if r['id'] == report_id:
            r['status'] = 'resolved'
            break
    report_system.save_reports(reports)
    return jsonify({'success': True})

@app.route('/reject_report/<int:report_id>', methods=['POST'])
@developer_required
def reject_report(report_id):
    reports = report_system.get_reports()
    for r in reports:
        if r['id'] == report_id:
            r['status'] = 'rejected'
            break
    report_system.save_reports(reports)
    return jsonify({'success': True})

# ==================== دوال عرض الصفحات ====================
def render_page(title, content):
    user = None
    unread_notifications = 0
    notifications = []
    
    if 'user_id' in session:
        user = get_user(session['user_id'])
        unread_notifications = get_unread_notifications_count(session['user_id'])
        notifications = get_user_notifications(session['user_id'])
    
    if user:
        user['display_name'] = get_display_name(user)
        user['badges'] = get_user_badges(user)
    
    return render_template_string(TEMPLATE, title=title, content=content, 
                                 session=session, user=user,
                                 unread_notifications=unread_notifications,
                                 notifications=notifications,
                                 report_reasons=ReportSystem.REPORT_REASONS,
                                 get_display_name=get_display_name,
                                 get_user_badges=get_user_badges)

# ==================== إدارة الصور المصغرة ====================
@app.route('/manage_mini_pics')
@developer_required
def manage_mini_pics():
    users = read_json('users')
    content = '''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-primary text-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-images"></i> إدارة الصور المصغرة</h6>
            <small style="font-size:10px;">تحكم في من يمكنه رفع صورة مصغرة بجانب اسمه</small>
        </div>
        <div class="card-body p-3">
            <div class="alert alert-info" style="font-size:12px;padding:8px;border-radius:10px;">
                <i class="fas fa-info-circle"></i> عند تفعيل الصورة المصغرة لمستخدم، سيظهر له خيار رفع صورة مصغرة في قائمته.
            </div>
            <div class="row g-2">
    '''
    
    for u in users:
        mini_pic_enabled = u.get('mini_pic_enabled', False)
        has_mini_pic = u.get('mini_pic') is not None
        
        mini_preview = ''
        if has_mini_pic and u['mini_pic']:
            mini_preview = '<img src="/static/mini_pics/' + u['mini_pic'] + '" style="width:24px;height:24px;border-radius:50%;object-fit:cover;border:2px solid #1877f2;margin-left:4px;">'
        
        content += '''
        <div class="col-12 col-sm-6 col-md-4">
            <div class="border rounded p-2 d-flex align-items-center justify-content-between" style="font-size:12px;background:#f8f9fa;">
                <div class="d-flex align-items-center">
                    <img src="/static/uploads/''' + get_profile_pic(u) + '''" style="width:30px;height:30px;border-radius:50%;object-fit:cover;margin-left:6px;">
                    <div>
                        <strong>''' + get_display_name(u) + '''</strong>
                        ''' + ('<span class="verified-badge" style="width:14px;height:14px;font-size:7px;"><i class="fas fa-check"></i></span>' if u.get('is_verified') else '') + '''
                        ''' + mini_preview + '''
                        <br>
                        <small style="font-size:8px;color:#65676b;">@''' + u['username'] + '''</small>
                    </div>
                </div>
                <div>
                    <a href="/toggle_mini_pic/''' + str(u['id']) + '''" class="btn btn-sm ''' + ('btn-success' if mini_pic_enabled else 'btn-secondary') + '''" style="font-size:9px;padding:2px 8px;border-radius:15px;">
                        ''' + ('✅ مفعل' if mini_pic_enabled else '❌ غير مفعل') + '''
                    </a>
                    ''' + ('<a href="/delete_mini_pic/' + str(u['id']) + '" class="btn btn-sm btn-danger" style="font-size:9px;padding:2px 8px;border-radius:15px;" onclick="return confirm(\'حذف الصورة المصغرة؟\')"><i class="fas fa-trash"></i></a>' if has_mini_pic else '') + '''
                </div>
            </div>
        </div>
        '''
    
    content += '''
            </div>
            <div class="mt-3">
                <a href="/developer_panel" class="btn btn-secondary btn-sm" style="font-size:11px;padding:4px 12px;border-radius:20px;">رجوع</a>
            </div>
        </div>
    </div>
    '''
    return render_page('إدارة الصور المصغرة', content)

@app.route('/toggle_mini_pic/<int:user_id>')
@developer_required
def toggle_mini_pic(user_id):
    users = read_json('users')
    for u in users:
        if u['id'] == user_id:
            u['mini_pic_enabled'] = not u.get('mini_pic_enabled', False)
            if not u['mini_pic_enabled']:
                if u.get('mini_pic'):
                    try:
                        os.remove(os.path.join(app.config['MINI_PIC_FOLDER'], u['mini_pic']))
                    except:
                        pass
                    u['mini_pic'] = None
            break
    write_json('users', users)
    flash('تم تغيير حالة الصورة المصغرة', 'success')
    return redirect(url_for('manage_mini_pics'))

@app.route('/delete_mini_pic/<int:user_id>')
@developer_required
def delete_mini_pic(user_id):
    users = read_json('users')
    for u in users:
        if u['id'] == user_id:
            if u.get('mini_pic'):
                try:
                    os.remove(os.path.join(app.config['MINI_PIC_FOLDER'], u['mini_pic']))
                except:
                    pass
                u['mini_pic'] = None
            break
    write_json('users', users)
    flash('تم حذف الصورة المصغرة', 'success')
    return redirect(url_for('manage_mini_pics'))

# ==================== رفع الصورة المصغرة ====================
@app.route('/upload_mini_pic', methods=['GET', 'POST'])
@login_required
def upload_mini_pic():
    user = get_user(session['user_id'])
    
    if not user.get('mini_pic_enabled', False):
        flash('ليس لديك صلاحية لرفع صورة مصغرة', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if 'mini_pic' not in request.files:
            flash('الرجاء اختيار صورة', 'danger')
            return redirect(url_for('upload_mini_pic'))
        
        file = request.files['mini_pic']
        if file.filename == '':
            flash('الرجاء اختيار صورة', 'danger')
            return redirect(url_for('upload_mini_pic'))
        
        mini_filename = save_mini_pic(file, session['user_id'])
        if mini_filename:
            if user.get('mini_pic'):
                try:
                    os.remove(os.path.join(app.config['MINI_PIC_FOLDER'], user['mini_pic']))
                except:
                    pass
            
            users = read_json('users')
            for u in users:
                if u['id'] == session['user_id']:
                    u['mini_pic'] = mini_filename
                    break
            write_json('users', users)
            
            flash('تم رفع الصورة المصغرة بنجاح!', 'success')
            return redirect(url_for('profile', user_id=session['user_id']))
        else:
            flash('حدث خطأ في رفع الصورة', 'danger')
    
    current_mini = user.get('mini_pic')
    preview_html = ''
    if current_mini:
        preview_html = f'''
        <div class="text-center mb-3">
            <img src="/static/mini_pics/{current_mini}" style="width:60px;height:60px;border-radius:50%;object-fit:cover;border:2px solid #1877f2;">
            <p class="text-muted" style="font-size:11px;">الصورة الحالية</p>
        </div>
        '''
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-image" style="color:#1877f2;"></i> رفع صورة مصغرة</h5>
                    <p class="text-muted text-center small" style="font-size:11px;">
                        الصورة ستظهر بجانب اسمك في كل مكان
                        <br>
                        <span class="text-primary">الحد الأقصى: 1 ميجابايت</span>
                    </p>
                    {preview_html}
                    <form method="POST" enctype="multipart/form-data">
                        <div class="mb-3">
                            <input type="file" name="mini_pic" class="form-control" accept="image/*" required style="font-size:13px;border-radius:12px;padding:8px;">
                            <small class="text-muted" style="font-size:11px;">اختر صورة (يفضل مربعة)</small>
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;">
                            <i class="fas fa-upload"></i> رفع الصورة
                        </button>
                    </form>
                    <hr>
                    <div class="text-center">
                        <a href="/profile/{session['user_id']}" class="text-decoration-none" style="font-size:13px;">رجوع</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('رفع صورة مصغرة', content)

# ==================== صفحات الدخول ====================
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']
        
        if not username.isalnum():
            flash('اسم المستخدم يجب أن يحتوي فقط على أحرف إنجليزية وأرقام', 'danger')
            return redirect(url_for('login'))
        
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
                print('تم انشاء حساب المطور MBL')
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('مرحبا بك ايها المطور MBL', 'success')
            return redirect(url_for('home'))
        
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
                print('تم انشاء حساب المطور MBLL')
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('مرحبا بك ايها المطور MBLL', 'success')
            return redirect(url_for('home'))
        
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('مرحبا بك ' + get_display_name(user), 'success')
            return redirect(url_for('home'))
        
        flash('اسم المستخدم أو كلمة السر غير صحيحة', 'danger')
    
    content = '''
    <div class="row justify-content-center mt-5" style="min-height:80vh;align-items:center;padding:0 10px;">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-4">
                    <div class="text-center mb-3">
                        <h1 style="color:#1877f2;font-size:36px;font-weight:bold;"><i class="fas fa-comment-dots"></i> CAW</h1>
                        <p class="text-muted" style="font-size:14px;">Chat & Wellness</p>
                    </div>
                    <form method="POST">
                        <div class="mb-2">
                            <input type="text" name="username" class="form-control" placeholder="اسم المستخدم" pattern="[A-Za-z0-9]+" required style="font-size:14px;padding:10px 14px;border-radius:12px;border:1px solid #e4e6eb;">
                        </div>
                        <div class="mb-2">
                            <input type="password" name="password" class="form-control" placeholder="كلمة السر" required style="font-size:14px;padding:10px 14px;border-radius:12px;border:1px solid #e4e6eb;">
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:10px;font-size:15px;font-weight:600;">تسجيل الدخول</button>
                    </form>
                    <hr>
                    <div class="text-center">
                        <a href="/register" class="text-decoration-none" style="font-size:13px;color:#1877f2;">انشاء حساب جديد</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('تسجيل دخول', content)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']
        display_name = request.form.get('display_name', '').strip()
        bio = request.form.get('bio', '')
        
        if not username.isalnum():
            flash('اسم المستخدم يجب أن يحتوي فقط على أحرف إنجليزية وأرقام', 'danger')
            return redirect(url_for('register'))
        
        if username == 'MBL' or username == 'MBLL':
            flash('هذا الاسم محجوز للمطورين', 'danger')
            return redirect(url_for('register'))
        
        if get_user_by_username(username):
            flash('اسم المستخدم موجود', 'danger')
            return redirect(url_for('register'))
        
        if not display_name:
            display_name = username
        
        profile_pic = 'default_profile.jpg'
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                filename = secure_filename(username + '_' + str(int(datetime.utcnow().timestamp())) + '.jpg')
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
        
        users = read_json('users')
        new_id = get_next_id('users')
        users.append({
            'id': new_id,
            'username': username,
            'password': generate_password_hash(password),
            'display_name': display_name,
            'is_verified': False,
            'is_developer': False,
            'mini_pic_enabled': False,
            'mini_pic': None,
            'bio': bio,
            'profile_pic': profile_pic,
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('users', users)
        
        flash('تم التسجيل بنجاح', 'success')
        return redirect(url_for('login'))
    
    content = '''
    <div class="row justify-content-center mt-5" style="min-height:80vh;align-items:center;padding:0 10px;">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-4">
                    <div class="text-center mb-3">
                        <h1 style="color:#1877f2;font-size:36px;font-weight:bold;"><i class="fas fa-comment-dots"></i> CAW</h1>
                        <p class="text-muted" style="font-size:14px;">انشاء حساب جديد</p>
                    </div>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="mb-2">
                            <input type="text" name="username" class="form-control" placeholder="اسم المستخدم (للحساب)" pattern="[A-Za-z0-9]+" required style="font-size:14px;padding:10px 14px;border-radius:12px;border:1px solid #e4e6eb;">
                            <small class="text-muted" style="font-size:10px;">يستخدم لتسجيل الدخول (أحرف إنجليزية وأرقام فقط)</small>
                        </div>
                        <div class="mb-2">
                            <input type="text" name="display_name" class="form-control" placeholder="الاسم الظاهر (للعرض)" style="font-size:14px;padding:10px 14px;border-radius:12px;border:1px solid #e4e6eb;">
                            <small class="text-muted" style="font-size:10px;">الاسم الذي سيراه الآخرون (اختياري)</small>
                        </div>
                        <div class="mb-2">
                            <input type="password" name="password" class="form-control" placeholder="كلمة السر" required style="font-size:14px;padding:10px 14px;border-radius:12px;border:1px solid #e4e6eb;">
                        </div>
                        <div class="mb-2">
                            <textarea name="bio" class="form-control" rows="2" placeholder="السيرة الذاتية (اختياري)" style="font-size:13px;border-radius:12px;border:1px solid #e4e6eb;"></textarea>
                        </div>
                        <div class="mb-2">
                            <input type="file" name="profile_pic" class="form-control" accept="image/*" style="font-size:12px;padding:6px 10px;border-radius:12px;border:1px solid #e4e6eb;">
                            <small class="text-muted" style="font-size:11px;">اختر صورة شخصية (اختياري)</small>
                        </div>
                        <button type="submit" class="btn btn-success w-100" style="border-radius:25px;padding:10px;font-size:15px;font-weight:600;">تسجيل</button>
                    </form>
                    <hr>
                    <div class="text-center">
                        <a href="/login" class="text-decoration-none" style="font-size:13px;color:#1877f2;">لديك حساب؟ سجل دخول</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('تسجيل جديد', content)

# ==================== تغيير الاسم الظاهر ====================
@app.route('/change_display_name', methods=['GET', 'POST'])
@login_required
def change_display_name():
    if request.method == 'POST':
        new_display_name = request.form.get('display_name', '').strip()
        
        if not new_display_name:
            flash('الرجاء إدخال اسم ظاهر', 'danger')
            return redirect(url_for('change_display_name'))
        
        users = read_json('users')
        for u in users:
            if u['id'] == session['user_id']:
                u['display_name'] = new_display_name
                break
        write_json('users', users)
        
        flash('تم تغيير الاسم الظاهر بنجاح', 'success')
        return redirect(url_for('profile', user_id=session['user_id']))
    
    user = get_user(session['user_id'])
    content = f'''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-tag"></i> تغيير الاسم الظاهر</h5>
                    <p class="text-muted text-center small" style="font-size:11px;">هذا الاسم سيراه الآخرون في المنشورات والمحادثات</p>
                    <form method="POST">
                        <div class="mb-2">
                            <label style="font-size:13px;">الاسم الظاهر الجديد</label>
                            <input type="text" name="display_name" class="form-control" value="{user.get('display_name', user.get('username', ''))}" required style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;">تغيير</button>
                    </form>
                    <hr>
                    <div class="text-center">
                        <a href="/profile/{{ session.user_id }}" class="text-decoration-none" style="font-size:13px;color:#1877f2;">رجوع</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('تغيير الاسم الظاهر', content)

# ==================== تغيير اسم المستخدم ====================
@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    if request.method == 'POST':
        new_username = request.form['new_username'].upper()
        password = request.form['password']
        
        user = get_user(session['user_id'])
        
        if not check_password_hash(user['password'], password):
            flash('كلمة السر غير صحيحة', 'danger')
            return redirect(url_for('change_username'))
        
        if not new_username.isalnum():
            flash('اسم المستخدم يجب أن يحتوي فقط على أحرف إنجليزية وأرقام', 'danger')
            return redirect(url_for('change_username'))
        
        if new_username == 'MBL' or new_username == 'MBLL':
            flash('هذا الاسم محجوز للمطورين', 'danger')
            return redirect(url_for('change_username'))
        
        if get_user_by_username(new_username) and new_username != user['username']:
            flash('هذا الاسم موجود بالفعل', 'danger')
            return redirect(url_for('change_username'))
        
        users = read_json('users')
        for u in users:
            if u['id'] == session['user_id']:
                u['username'] = new_username
                break
        write_json('users', users)
        
        session['username'] = new_username
        flash('تم تغيير اسم المستخدم بنجاح', 'success')
        return redirect(url_for('profile', user_id=session['user_id']))
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-user-tag"></i> تغيير اسم المستخدم</h5>
                    <p class="text-muted text-center small" style="font-size:11px;">أدخل اسم المستخدم الجديد (أحرف إنجليزية وأرقام فقط)</p>
                    <form method="POST">
                        <div class="mb-2">
                            <label style="font-size:13px;">اسم المستخدم الجديد</label>
                            <input type="text" name="new_username" class="form-control" pattern="[A-Za-z0-9]+" required style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <div class="mb-2">
                            <label style="font-size:13px;">كلمة السر الحالية</label>
                            <input type="password" name="password" class="form-control" required style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;">تغيير</button>
                    </form>
                    <hr>
                    <div class="text-center">
                        <a href="/profile/{{ session.user_id }}" class="text-decoration-none" style="font-size:13px;color:#1877f2;">رجوع</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('تغيير اسم المستخدم', content)

# ==================== إحصائيات الحماية ====================
@app.route('/security_stats')
@developer_required
def security_stats():
    stats = protection.get_stats()
    content = f'''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-success text-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-shield-alt"></i> إحصائيات الحماية</h6>
            <small style="font-size:10px;">نظام حماية خفي ضد هجمات DDoS والفيضانات</small>
        </div>
        <div class="card-body p-3">
            <div class="row text-center">
                <div class="col-6 mb-2">
                    <div class="border rounded p-2" style="background:#f8f9fa;">
                        <h5>{stats['blocked_ips']}</h5>
                        <small class="text-muted">IPs محظورة</small>
                    </div>
                </div>
                <div class="col-6 mb-2">
                    <div class="border rounded p-2" style="background:#f8f9fa;">
                        <h5>{stats['suspicious_ips']}</h5>
                        <small class="text-muted">IPs مشبوهة</small>
                    </div>
                </div>
                <div class="col-6 mb-2">
                    <div class="border rounded p-2" style="background:#f8f9fa;">
                        <h5>{stats['whitelisted_ips']}</h5>
                        <small class="text-muted">IPs في القائمة البيضاء</small>
                    </div>
                </div>
                <div class="col-6 mb-2">
                    <div class="border rounded p-2" style="background:#f8f9fa;">
                        <h5>{'نعم' if stats['is_under_attack'] else 'لا'}</h5>
                        <small class="text-muted">تحت الهجوم</small>
                    </div>
                </div>
            </div>
            <div class="mt-2 text-center">
                <span class="badge {'bg-danger' if stats['is_under_attack'] else 'bg-success'}" style="font-size:12px;padding:6px 12px;">
                    {'⚠️ تحت الهجوم' if stats['is_under_attack'] else '✅ آمن'}
                </span>
                <small class="text-muted d-block mt-1">الحماية تعمل بشكل خفي</small>
            </div>
        </div>
    </div>
    '''
    return render_page('إحصائيات الحماية', content)

# ==================== الصفحة الرئيسية ====================
@app.route('/home')
@login_required
def home():
    current_user = get_user(session['user_id'])
    blocked_ids = get_blocked_user_ids(session['user_id'])
    
    all_posts = read_json('posts')
    all_posts = [p for p in all_posts if p['user_id'] not in blocked_ids]
    all_posts.reverse()
    
    all_reels = read_json('reels')
    all_reels = [r for r in all_reels if r['user_id'] not in blocked_ids]
    all_reels.reverse()
    
    feed_items = []
    for post in all_posts:
        author = get_user(post['user_id'])
        if author and author['id'] not in blocked_ids:
            feed_items.append({
                'type': 'post',
                'id': post['id'],
                'content': post['content'],
                'image': post.get('image'),
                'user_id': post['user_id'],
                'username': author['username'],
                'display_name': get_display_name(author),
                'profile_pic': get_profile_pic(author),
                'is_verified': author.get('is_verified', False),
                'is_developer': author.get('is_developer', False),
                'mini_pic_enabled': author.get('mini_pic_enabled', False),
                'mini_pic': author.get('mini_pic'),
                'created_at': post['created_at'],
                'author': author,
                'badges': get_user_badges(author)
            })
    
    for reel in all_reels:
        author = get_user(reel['user_id'])
        if author and author['id'] not in blocked_ids:
            feed_items.append({
                'type': 'reel',
                'id': reel['id'],
                'description': reel.get('description', ''),
                'video': reel['video'],
                'user_id': reel['user_id'],
                'username': author['username'],
                'display_name': get_display_name(author),
                'profile_pic': get_profile_pic(author),
                'is_verified': author.get('is_verified', False),
                'is_developer': author.get('is_developer', False),
                'mini_pic_enabled': author.get('mini_pic_enabled', False),
                'mini_pic': author.get('mini_pic'),
                'created_at': reel['created_at'],
                'author': author,
                'badges': get_user_badges(author)
            })
    
    feed_items.sort(key=lambda x: x['created_at'], reverse=True)
    
    feed_html = ''
    for item in feed_items:
        all_likes = read_json('likes')
        
        author = item['author']
        name_display = render_user_display(author)
        
        three_dots_menu = f'''
        <div class="dropdown">
            <button class="three-dots" data-bs-toggle="dropdown"><i class="fas fa-ellipsis-v"></i></button>
            <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="#" onclick="openReportModal({item['user_id']}, 'user')"><i class="fas fa-flag text-danger"></i> إبلاغ عن المستخدم</a></li>
                <li><a class="dropdown-item" href="#" onclick="blockUser({item['user_id']})"><i class="fas fa-ban text-danger"></i> حظر المستخدم</a></li>
        '''
        
        if item['user_id'] == session['user_id'] or current_user.get('is_developer', False):
            three_dots_menu += f'''
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item text-danger" href="#" onclick="deletePost({item['id']})"><i class="fas fa-trash"></i> حذف</a></li>
            '''
        
        three_dots_menu += '''
            </ul>
        </div>
        '''
        
        if item['type'] == 'post':
            likes_count = len([l for l in all_likes if l.get('post_id') == item['id']])
            comments_list = [c for c in read_json('comments') if c.get('post_id') == item['id'] and c['user_id'] not in blocked_ids]
            comments_count = len(comments_list)
            user_liked = any(l.get('user_id') == session['user_id'] and l.get('post_id') == item['id'] for l in all_likes)
            
            image_html = ''
            if item.get('image'):
                image_html = '<img src="/static/uploads/' + item['image'] + '" class="post-image" onclick="showImage(this.src)">'
            
            recent_comments_html = ''
            for comment in comments_list[-2:]:
                comment_user = get_user(comment['user_id'])
                if comment_user and comment_user['id'] not in blocked_ids:
                    comment_name = render_user_display(comment_user, size='small')
                    comment_img_html = ''
                    if comment.get('image'):
                        comment_img_html = '<br><img src="/static/uploads/' + comment['image'] + '" class="comment-image" onclick="showImage(this.src)">'
                    recent_comments_html += '''
                    <div class="comment-item">
                        <img src="/static/uploads/''' + get_profile_pic(comment_user) + '''">
                        <div class="comment-text">
                            ''' + comment_name + '''
                            <span>''' + safe_text(comment['content']) + '''</span>
                            ''' + comment_img_html + '''
                        </div>
                    </div>
                    '''
            
            feed_html += '''
            <div class="post-card">
                <div class="post-header">
                    <a href="/profile/''' + str(item['user_id']) + '''" class="post-user">
                        <img src="/static/uploads/''' + item['profile_pic'] + '''">
                        <div>
                            <div class="display-name-wrapper">''' + name_display + '''</div>
                            <span class="time"> · ''' + item['created_at'][:19] + '''</span>
                        </div>
                    </a>
                    ''' + three_dots_menu + '''
                </div>
                <div class="post-content">''' + safe_text(item['content']) + '''</div>
                ''' + image_html + '''
                <div class="post-actions">
                    <button class="''' + ('liked' if user_liked else '') + '''" onclick="likePost(''' + str(item['id']) + ''', this)"><i class="fas fa-thumbs-up"></i> <span class="like-count">''' + str(likes_count) + '''</span></button>
                    <button onclick="openCommentModal(''' + str(item['id']) + ''', 'post')"><i class="fas fa-comment"></i> تعليق</button>
                    <button onclick="showAllComments(''' + str(item['id']) + ''', 'post')"><i class="fas fa-comments"></i> ''' + str(comments_count) + '''</button>
                </div>
                <div class="post-comments">
                    ''' + recent_comments_html + '''
                    ''' + ('''<div class="comment-more" onclick="showAllComments(''' + str(item['id']) + ''', 'post')">عرض التعليقات السابقة</div>''' if comments_count > 2 else '') + '''
                </div>
            </div>
            '''
        else:
            likes_count = len([l for l in all_likes if l.get('reel_id') == item['id']])
            comments_list = [c for c in read_json('comments') if c.get('reel_id') == item['id'] and c['user_id'] not in blocked_ids]
            comments_count = len(comments_list)
            user_liked = any(l.get('user_id') == session['user_id'] and l.get('reel_id') == item['id'] for l in all_likes)
            
            feed_html += '''
            <div class="reel-card">
                <div class="post-header">
                    <a href="/profile/''' + str(item['user_id']) + '''" class="post-user">
                        <img src="/static/uploads/''' + item['profile_pic'] + '''">
                        <div>
                            <div class="display-name-wrapper">''' + name_display + '''</div>
                            <span class="time"> · ''' + item['created_at'][:19] + '''</span>
                        </div>
                    </a>
                    ''' + three_dots_menu + '''
                </div>
                <video class="reel-video" controls preload="metadata">
                    <source src="/static/uploads/''' + item['video'] + '''" type="video/mp4">
                </video>
                <p class="mt-2" style="font-size:13px;">''' + safe_text(item.get('description', '')) + '''</p>
                <div class="post-actions">
                    <button class="''' + ('liked-reel' if user_liked else '') + '''" onclick="likeReel(''' + str(item['id']) + ''', this)"><i class="fas fa-heart"></i> <span class="like-count">''' + str(likes_count) + '''</span></button>
                    <button onclick="openCommentModal(''' + str(item['id']) + ''', 'reel')"><i class="fas fa-comment"></i> تعليق</button>
                    <button onclick="showAllComments(''' + str(item['id']) + ''', 'reel')"><i class="fas fa-comments"></i> ''' + str(comments_count) + '''</button>
                </div>
            </div>
            '''
    
    if not feed_html:
        feed_html = '<div class="alert alert-info text-center" style="font-size:13px;padding:12px;border-radius:12px;">لا توجد منشورات أو ريلزات بعد</div>'
    
    current_user_pic = get_profile_pic(current_user)
    current_display_name = get_display_name(current_user)
    
    content = '''
    <div class="create-post">
        <div class="create-post-top">
            <a href="/profile/''' + str(session['user_id']) + '''">
                <img src="/static/uploads/''' + current_user_pic + '''">
            </a>
            <input type="text" placeholder="ماذا يحدث يا ''' + current_display_name + '''؟" onclick="document.getElementById('postModal').click()" style="font-size:13px;">
            <button id="postModal" style="display:none;" data-bs-toggle="modal" data-bs-target="#createPostModal"></button>
        </div>
        <div class="create-post-divider"></div>
        <div class="create-post-bottom">
            <button class="btn-photo" onclick="document.getElementById('photoInput').click()"><i class="fas fa-image"></i> صورة</button>
            <button class="btn-video" onclick="location.href='/create_reel'"><i class="fas fa-video"></i> ريلز</button>
        </div>
        <input type="file" id="photoInput" accept="image/*" style="display:none;" onchange="document.getElementById('postForm').submit()">
    </div>
    
    <div class="modal fade" id="createPostModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h6 class="modal-title">إنشاء منشور</h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="POST" action="/create_post" enctype="multipart/form-data" id="postForm">
                        <textarea name="content" class="form-control" rows="4" placeholder="ماذا يحدث؟" required style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:10px;"></textarea>
                        <div class="mt-2">
                            <input type="file" name="image" class="form-control" accept="image/*" style="font-size:12px;border-radius:12px;border:1px solid #e4e6eb;padding:6px 10px;">
                        </div>
                        <button type="submit" class="btn btn-primary w-100 mt-3" style="border-radius:25px;padding:8px;font-size:14px;">نشر</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    ''' + feed_html + '''
    
    <div id="searchResults"></div>
    '''
    return render_page('الرئيسية', content)

# ==================== باقي المسارات ====================
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    posts = read_json('posts')
    post_to_delete = None
    for p in posts:
        if p['id'] == post_id:
            post_to_delete = p
            break
    
    if not post_to_delete:
        return jsonify({'success': False, 'error': 'المنشور غير موجود'})
    
    if post_to_delete['user_id'] != session['user_id']:
        user = get_user(session['user_id'])
        if not user.get('is_developer', False):
            return jsonify({'success': False, 'error': 'ليس لديك صلاحية'})
    
    posts = [p for p in posts if p['id'] != post_id]
    write_json('posts', posts)
    
    likes = read_json('likes')
    likes = [l for l in likes if l.get('post_id') != post_id]
    write_json('likes', likes)
    
    comments = read_json('comments')
    comments = [c for c in comments if c.get('post_id') != post_id]
    write_json('comments', comments)
    
    return jsonify({'success': True})

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form['content']
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
    flash('تم النشر', 'success')
    return redirect(url_for('home'))

@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
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

@app.route('/like_reel/<int:reel_id>', methods=['POST'])
@login_required
def like_reel(reel_id):
    likes = read_json('likes')
    existing = None
    for l in likes:
        if l.get('user_id') == session['user_id'] and l.get('reel_id') == reel_id:
            existing = l
            break
    
    if existing:
        likes.remove(existing)
        liked = False
    else:
        likes.append({'id': get_next_id('likes'), 'user_id': session['user_id'], 'reel_id': reel_id})
        liked = True
    write_json('likes', likes)
    likes_count = len([l for l in likes if l.get('reel_id') == reel_id])
    return jsonify({'liked': liked, 'likes': likes_count})

@app.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    try:
        content = request.form.get('content', '').strip()
        item_id = request.form.get('item_id')
        item_type = request.form.get('type')
        image = None
        
        if 'image' in request.files and request.files['image'].filename:
            image = save_image(request.files['image'], 'comment')
        
        if not content and not image:
            return jsonify({'success': False, 'error': 'التعليق فارغ'})
        
        comments = read_json('comments')
        new_comment = {
            'id': get_next_id('comments'),
            'content': content,
            'user_id': session['user_id'],
            'image': image,
            'created_at': datetime.utcnow().isoformat()
        }
        
        if item_type == 'post':
            new_comment['post_id'] = int(item_id)
        else:
            new_comment['reel_id'] = int(item_id)
        
        comments.append(new_comment)
        write_json('comments', comments)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_comments/<int:item_id>/<string:item_type>')
@login_required
def get_comments(item_id, item_type):
    blocked_ids = get_blocked_user_ids(session['user_id'])
    comments = read_json('comments')
    
    if item_type == 'post':
        item_comments = [c for c in comments if c.get('post_id') == item_id and c['user_id'] not in blocked_ids]
    else:
        item_comments = [c for c in comments if c.get('reel_id') == item_id and c['user_id'] not in blocked_ids]
    item_comments.reverse()
    
    result = []
    for c in item_comments:
        user = get_user(c['user_id'])
        if user and user['id'] not in blocked_ids:
            result.append({
                'username': user['username'],
                'display_name': get_display_name(user),
                'profile_pic': get_profile_pic(user),
                'is_verified': user.get('is_verified', False),
                'is_developer': user.get('is_developer', False),
                'mini_pic': user.get('mini_pic') if user.get('mini_pic_enabled', False) else None,
                'content': safe_text(c['content']),
                'image': c.get('image'),
                'created_at': c['created_at'][:19]
            })
    
    return jsonify(result)

@app.route('/reels')
@login_required
def reels():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    all_reels = read_json('reels')
    all_reels = [r for r in all_reels if r['user_id'] not in blocked_ids]
    all_reels.reverse()
    
    reels_html = ''
    for reel in all_reels:
        author = get_user(reel['user_id'])
        if not author or author['id'] in blocked_ids:
            continue
            
        author_pic = get_profile_pic(author)
        all_likes = read_json('likes')
        likes_count = len([l for l in all_likes if l.get('reel_id') == reel['id']])
        comments_list = [c for c in read_json('comments') if c.get('reel_id') == reel['id'] and c['user_id'] not in blocked_ids]
        comments_count = len(comments_list)
        user_liked = any(l.get('user_id') == session['user_id'] and l.get('reel_id') == reel['id'] for l in all_likes)
        
        name_display = render_user_display(author)
        
        three_dots_menu = f'''
        <div class="dropdown">
            <button class="three-dots" data-bs-toggle="dropdown"><i class="fas fa-ellipsis-v"></i></button>
            <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="#" onclick="openReportModal({reel['user_id']}, 'user')"><i class="fas fa-flag text-danger"></i> إبلاغ عن المستخدم</a></li>
                <li><a class="dropdown-item" href="#" onclick="blockUser({reel['user_id']})"><i class="fas fa-ban text-danger"></i> حظر المستخدم</a></li>
        '''
        
        if reel['user_id'] == session['user_id'] or get_user(session['user_id']).get('is_developer', False):
            three_dots_menu += f'''
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item text-danger" href="#" onclick="deleteReel({reel['id']})"><i class="fas fa-trash"></i> حذف</a></li>
            '''
        
        three_dots_menu += '''
            </ul>
        </div>
        '''
        
        reels_html += '''
        <div class="reel-card">
            <div class="post-header">
                <a href="/profile/''' + str(author['id']) + '''" class="post-user">
                    <img src="/static/uploads/''' + author_pic + '''">
                    <div>
                        <div class="display-name-wrapper">''' + name_display + '''</div>
                        <span class="time">''' + reel['created_at'][:19] + '''</span>
                    </div>
                </a>
                ''' + three_dots_menu + '''
            </div>
            <video class="reel-video" controls preload="metadata">
                <source src="/static/uploads/''' + reel['video'] + '''" type="video/mp4">
            </video>
            <p class="mt-2" style="font-size:13px;">''' + safe_text(reel.get('description', '')) + '''</p>
            <div class="post-actions">
                <button class="''' + ('liked-reel' if user_liked else '') + '''" onclick="likeReel(''' + str(reel['id']) + ''', this)"><i class="fas fa-heart"></i> <span class="like-count">''' + str(likes_count) + '''</span></button>
                <button onclick="openCommentModal(''' + str(reel['id']) + ''', 'reel')"><i class="fas fa-comment"></i> تعليق</button>
                <button onclick="showAllComments(''' + str(reel['id']) + ''', 'reel')"><i class="fas fa-comments"></i> ''' + str(comments_count) + '''</button>
            </div>
        </div>
        '''
    
    if not reels_html:
        reels_html = '<div class="alert alert-info text-center" style="font-size:13px;padding:12px;border-radius:12px;">لا توجد ريلزات بعد</div>'
    
    content = '''
    <div style="text-align:center;margin-bottom:10px;">
        <a href="/create_reel" class="reel-upload-btn"><i class="fas fa-plus"></i> رفع ريلز جديد</a>
    </div>
    ''' + reels_html
    
    return render_page('الريلزات', content)

@app.route('/create_reel', methods=['GET', 'POST'])
@login_required
def create_reel():
    if request.method == 'POST':
        description = request.form.get('description', '')
        video = None
        if 'video' in request.files and request.files['video'].filename:
            video = save_video(request.files['video'])
        
        if not video:
            flash('الرجاء اختيار فيديو (حد أقصى 1MB)', 'danger')
            return redirect(url_for('create_reel'))
        
        reels = read_json('reels')
        new_id = get_next_id('reels')
        reels.append({
            'id': new_id,
            'description': description,
            'video': video,
            'user_id': session['user_id'],
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('reels', reels)
        flash('تم رفع الريلز بنجاح!', 'success')
        return redirect(url_for('reels'))
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-video" style="color:#e74c3c;"></i> رفع ريلز جديد</h5>
                    <p class="text-muted text-center small" style="font-size:11px;">حد أقصى للحجم: 1MB</p>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="mb-2">
                            <textarea name="description" class="form-control" rows="3" placeholder="وصف الريلز (اختياري)" style="font-size:13px;border-radius:12px;border:1px solid #e4e6eb;padding:8px;"></textarea>
                        </div>
                        <div class="mb-2">
                            <input type="file" name="video" class="form-control" accept="video/mp4" required style="font-size:12px;border-radius:12px;border:1px solid #e4e6eb;padding:6px 10px;">
                        </div>
                        <button type="submit" class="btn btn-danger w-100" style="border-radius:25px;padding:8px;font-size:14px;"><i class="fas fa-upload"></i> رفع</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('رفع ريلز', content)

@app.route('/delete_reel/<int:reel_id>', methods=['POST'])
@login_required
def delete_reel(reel_id):
    reels = read_json('reels')
    reel_to_delete = None
    for r in reels:
        if r['id'] == reel_id:
            reel_to_delete = r
            break
    
    if not reel_to_delete:
        return jsonify({'success': False, 'error': 'الريلز غير موجود'})
    
    if reel_to_delete['user_id'] != session['user_id']:
        user = get_user(session['user_id'])
        if not user.get('is_developer', False):
            return jsonify({'success': False, 'error': 'ليس لديك صلاحية'})
    
    reels = [r for r in reels if r['id'] != reel_id]
    write_json('reels', reels)
    
    likes = read_json('likes')
    likes = [l for l in likes if l.get('reel_id') != reel_id]
    write_json('likes', likes)
    
    comments = read_json('comments')
    comments = [c for c in comments if c.get('reel_id') != reel_id]
    write_json('comments', comments)
    
    return jsonify({'success': True})

# ==================== البحث والأصدقاء ====================
@app.route('/search_users/<query>')
@login_required
def search_users(query):
    blocked_ids = get_blocked_user_ids(session['user_id'])
    users = read_json('users')
    friends = read_json('friends')
    
    friends_ids = []
    pending_sent_ids = []
    pending_received_ids = []
    
    for f in friends:
        if f['from_user_id'] == session['user_id'] and f['status'] == 'accepted':
            friends_ids.append(f['to_user_id'])
        elif f['to_user_id'] == session['user_id'] and f['status'] == 'accepted':
            friends_ids.append(f['from_user_id'])
        elif f['from_user_id'] == session['user_id'] and f['status'] == 'pending':
            pending_sent_ids.append(f['to_user_id'])
        elif f['to_user_id'] == session['user_id'] and f['status'] == 'pending':
            pending_received_ids.append(f['from_user_id'])
    
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
                'bio': u.get('bio', ''),
                'profile_pic': get_profile_pic(u),
                'is_verified': u.get('is_verified', False),
                'is_developer': u.get('is_developer', False),
                'mini_pic': u.get('mini_pic') if u.get('mini_pic_enabled', False) else None,
                'is_friend': u['id'] in friends_ids,
                'pending_sent': u['id'] in pending_sent_ids,
                'pending_received': u['id'] in pending_received_ids
            })
    
    return jsonify(results)

@app.route('/send_friend_request/<int:user_id>', methods=['POST'])
@login_required
def send_friend_request(user_id):
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'لا يمكن اضافة نفسك'})
    
    if is_user_blocked(session['user_id'], user_id):
        return jsonify({'success': False, 'error': 'لا يمكن إرسال طلب لهذا المستخدم'})
    
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
    else:
        return jsonify({'success': False, 'error': 'طلب موجود بالفعل'})

@app.route('/accept_friend/<int:user_id>', methods=['POST'])
@login_required
def accept_friend(user_id):
    if is_user_blocked(session['user_id'], user_id):
        return jsonify({'success': False, 'error': 'لا يمكن قبول طلب هذا المستخدم'})
    
    friends = read_json('friends')
    for f in friends:
        if f['from_user_id'] == user_id and f['to_user_id'] == session['user_id'] and f['status'] == 'pending':
            f['status'] = 'accepted'
            write_json('friends', friends)
            return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'لا يوجد طلب'})

@app.route('/friends')
@login_required
def friends():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    all_friends = read_json('friends')
    pending = []
    accepted = []
    
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
    
    pending = [p for p in pending if p]
    accepted = [a for a in accepted if a]
    
    content = '''
    <div class="row">
        <div class="col-12">
            <h5 class="mb-2"><i class="fas fa-user-plus"></i> طلبات الصداقة</h5>
            <div class="row g-2">
                ''' + (''.join([f'''
                <div class="col-4 mb-2">
                    <div class="card text-center border-0 shadow-sm" style="border-radius:12px;">
                        <div class="card-body p-2">
                            <a href="/profile/{p['id']}">
                                <img src="/static/uploads/{p['profile_pic'] if p['profile_pic'] and p['profile_pic'] != 'default.jpg' and p['profile_pic'] != 'default_profile.jpg' else 'default_profile.jpg'}" style="width:50px;height:50px;border-radius:50%;object-fit:cover;">
                            </a>
                            <h6 class="mt-1" style="font-size:12px;">{render_user_display(p)}</h6>
                            <div>
                                <button class="btn btn-success btn-sm" onclick="acceptFriend({p['id']})" style="font-size:10px;padding:2px 10px;border-radius:15px;">قبول</button>
                                <a href="/profile/{p['id']}" class="btn btn-secondary btn-sm" style="font-size:10px;padding:2px 10px;border-radius:15px;">عرض</a>
                            </div>
                        </div>
                    </div>
                </div>
                ''' for p in pending]) if pending else '<div class="alert alert-secondary" style="font-size:13px;padding:10px;border-radius:12px;">لا توجد طلبات</div>') + '''
            </div>
        </div>
        <div class="col-12 mt-3">
            <h5 class="mb-2"><i class="fas fa-user-friends"></i> اصدقائي</h5>
            <div class="row g-2">
                ''' + (''.join([f'''
                <div class="col-4 mb-2">
                    <div class="card text-center border-0 shadow-sm" style="border-radius:12px;">
                        <div class="card-body p-2">
                            <a href="/profile/{a['id']}">
                                <img src="/static/uploads/{a['profile_pic'] if a['profile_pic'] and a['profile_pic'] != 'default.jpg' and a['profile_pic'] != 'default_profile.jpg' else 'default_profile.jpg'}" style="width:50px;height:50px;border-radius:50%;object-fit:cover;">
                            </a>
                            <h6 class="mt-1" style="font-size:12px;">{render_user_display(a)}</h6>
                            <div>
                                <a href="/profile/{a['id']}" class="btn btn-primary btn-sm" style="font-size:10px;padding:2px 10px;border-radius:15px;">ملف</a>
                                <a href="/chat/{a['id']}" class="btn btn-info btn-sm" style="font-size:10px;padding:2px 10px;border-radius:15px;">راسل</a>
                            </div>
                        </div>
                    </div>
                </div>
                ''' for a in accepted]) if accepted else '<div class="alert alert-info" style="font-size:13px;padding:10px;border-radius:12px;">لا يوجد اصدقاء</div>') + '''
            </div>
        </div>
    </div>
    '''
    return render_page('الأصدقاء', content)

# ==================== الملف الشخصي ====================
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    if is_user_blocked(session['user_id'], user_id):
        content = '''
        <div class="blocked-banner">
            <i class="fas fa-ban"></i>
            <h6>هذا المستخدم محظور</h6>
            <p style="font-size:13px;">لا يمكنك رؤية محتوى هذا المستخدم</p>
        </div>
        '''
        return render_page('محظور', content)
    
    user = get_user(user_id)
    if not user:
        flash('مستخدم غير موجود', 'danger')
        return redirect(url_for('home'))
    
    blocked_ids = get_blocked_user_ids(session['user_id'])
    
    posts = [p for p in read_json('posts') if p['user_id'] == user_id and p['user_id'] not in blocked_ids]
    posts.reverse()
    reels = [r for r in read_json('reels') if r['user_id'] == user_id and r['user_id'] not in blocked_ids]
    reels.reverse()
    
    user_pic = get_profile_pic(user)
    display_name = get_display_name(user)
    badges = get_user_badges(user)
    
    name_display = render_user_display(user, size='large')
    
    posts_html = ''
    for post in posts:
        image_html = '<img src="/static/uploads/' + post['image'] + '" class="post-image" onclick="showImage(this.src)">' if post.get('image') else ''
        posts_html += '''
        <div class="post-card">
            <div class="post-content" style="font-size:13px;">''' + post['content'] + '''</div>
            ''' + image_html + '''
            <small class="text-muted" style="font-size:10px;">''' + post['created_at'][:19] + '''</small>
        </div>
        '''
    
    reels_html = ''
    for reel in reels:
        reels_html += '''
        <div class="reel-card">
            <video class="reel-video" controls preload="metadata" style="max-height:150px;">
                <source src="/static/uploads/''' + reel['video'] + '''" type="video/mp4">
            </video>
            <p class="mt-1" style="font-size:12px;"><small>''' + safe_text(reel.get('description', '')) + '''</small></p>
            <small class="text-muted" style="font-size:10px;">''' + reel['created_at'][:19] + '''</small>
        </div>
        '''
    
    friends = read_json('friends')
    is_friend = any((f['from_user_id'] == session['user_id'] and f['to_user_id'] == user_id and f['status'] == 'accepted') or 
                    (f['from_user_id'] == user_id and f['to_user_id'] == session['user_id'] and f['status'] == 'accepted') for f in friends)
    pending_sent = any(f['from_user_id'] == session['user_id'] and f['to_user_id'] == user_id and f['status'] == 'pending' for f in friends)
    pending_received = any(f['from_user_id'] == user_id and f['to_user_id'] == session['user_id'] and f['status'] == 'pending' for f in friends)
    
    is_blocked = is_user_blocked(session['user_id'], user_id)
    
    content = '''
    <div class="card text-center border-0 shadow-sm" style="border-radius:16px;">
        <div class="card-body p-3">
            <img src="/static/uploads/''' + user_pic + '''" style="width:80px;height:80px;border-radius:50%;object-fit:cover;">
            <h5 class="mt-2" style="font-size:16px;">''' + name_display + '''</h5>
            <p class="text-muted" style="font-size:12px;">@''' + user['username'] + '''</p>
            <p class="text-muted" style="font-size:12px;">''' + user.get('bio', '') + '''</p>
            <div class="mt-2">
                ''' + (f'<button class="btn btn-success btn-sm" onclick="sendFriendRequest({user["id"]})" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-user-plus"></i> اضف صديق</button>' if not is_friend and not pending_sent and not pending_received and user['id'] != session['user_id'] and not is_blocked else '') + '''
                ''' + ('<span class="badge bg-secondary" style="font-size:10px;padding:4px 10px;">طلب مرسل</span>' if pending_sent else '') + '''
                ''' + (f'<button class="btn btn-success btn-sm" onclick="acceptFriend({user["id"]})" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-check"></i> قبول الطلب</button>' if pending_received else '') + '''
                ''' + ('<span class="badge bg-success" style="font-size:10px;padding:4px 10px;">صديق</span>' if is_friend else '') + '''
                ''' + (f'<a href="/edit_profile" class="btn btn-secondary btn-sm" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-edit"></i> تعديل</a>' if user['id'] == session['user_id'] else '') + '''
                ''' + (f'<a href="/chat/{user["id"]}" class="btn btn-primary btn-sm" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-envelope"></i> راسل</a>' if is_friend else '') + '''
                ''' + (f'<button class="btn btn-danger btn-sm" onclick="blockUser({user["id"]})" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-ban"></i> حظر</button>' if user['id'] != session['user_id'] and not is_blocked else '') + '''
                ''' + (f'<button class="btn btn-danger btn-sm" onclick="unblockUser({user["id"]})" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-unlock"></i> إلغاء الحظر</button>' if is_blocked else '') + '''
                ''' + (f'<button class="btn btn-outline-danger btn-sm" onclick="openReportModal({user["id"]}, \'user\')" style="font-size:11px;padding:4px 14px;border-radius:20px;"><i class="fas fa-flag"></i> إبلاغ</button>' if user['id'] != session['user_id'] else '') + '''
            </div>
        </div>
    </div>
    <div class="mt-3">
        <ul class="nav nav-tabs" id="profileTab" style="font-size:12px;border-bottom:1px solid #e4e6eb;">
            <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#posts" style="color:#1a1a1e;border:none;">المنشورات</button></li>
            <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#reels" style="color:#1a1a1e;border:none;">الريلزات</button></li>
        </ul>
        <div class="tab-content mt-2">
            <div class="tab-pane fade show active" id="posts">''' + (posts_html if posts_html else '<div class="alert alert-info" style="font-size:12px;padding:10px;border-radius:12px;">لا توجد منشورات</div>') + '''</div>
            <div class="tab-pane fade" id="reels">''' + (reels_html if reels_html else '<div class="alert alert-info" style="font-size:12px;padding:10px;border-radius:12px;">لا توجد ريلزات</div>') + '''</div>
        </div>
    </div>
    '''
    return render_page('الملف الشخصي', content)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    users = read_json('users')
    idx = None
    for i, u in enumerate(users):
        if u['id'] == session['user_id']:
            idx = i
            break
    
    user = users[idx]
    
    if request.method == 'POST':
        user['bio'] = request.form.get('bio', '')
        if request.form.get('display_name'):
            user['display_name'] = request.form['display_name']
        if request.form.get('new_password'):
            user['password'] = generate_password_hash(request.form['new_password'])
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                filename = secure_filename(user['username'] + '_' + str(int(datetime.utcnow().timestamp())) + '.jpg')
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user['profile_pic'] = filename
        
        users[idx] = user
        write_json('users', users)
        flash('تم التحديث', 'success')
        return redirect(url_for('profile', user_id=session['user_id']))
    
    user_pic = get_profile_pic(user)
    display_name = get_display_name(user)
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-edit"></i> تعديل الملف الشخصي</h5>
                    <div class="text-center mb-2">
                        <img src="/static/uploads/''' + user_pic + '''" style="width:80px;height:80px;border-radius:50%;object-fit:cover;">
                    </div>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="mb-2">
                            <label style="font-size:13px;">الاسم الظاهر</label>
                            <input type="text" name="display_name" class="form-control" value="''' + display_name + '''" style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <div class="mb-2">
                            <textarea name="bio" class="form-control" rows="4" placeholder="السيرة الذاتية" style="font-size:13px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">''' + user.get('bio', '') + '''</textarea>
                        </div>
                        <div class="mb-2">
                            <input type="password" name="new_password" class="form-control" placeholder="كلمة سر جديدة (اتركها فارغة)" style="font-size:13px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <div class="mb-2">
                            <input type="file" name="profile_pic" class="form-control" accept="image/*" style="font-size:12px;border-radius:12px;border:1px solid #e4e6eb;padding:6px 10px;">
                            <small class="text-muted" style="font-size:11px;">اختر صورة جديدة</small>
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;">حفظ التغييرات</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('تعديل الملف', content)

# ==================== الدردشات الخاصة ====================
@app.route('/messages')
@login_required
def messages():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    all_messages = read_json('messages')
    conversations = {}
    for msg in all_messages:
        if msg['sender_id'] == session['user_id'] or msg['receiver_id'] == session['user_id']:
            other = msg['sender_id'] if msg['receiver_id'] == session['user_id'] else msg['receiver_id']
            if other in blocked_ids:
                continue
            if other not in conversations or msg['created_at'] > conversations[other]['created_at']:
                conversations[other] = msg
    
    conv_html = ''
    for other_id, msg in conversations.items():
        other = get_user(other_id)
        if not other or other['id'] in blocked_ids:
            continue
        other_pic = get_profile_pic(other)
        msg_preview = '[صورة]' if msg.get('image') else (msg['content'][:50] if msg.get('content') else '')
        name_display = render_user_display(other, size='small')
        conv_html += '''
        <a href="/chat/''' + str(other_id) + '''" class="text-decoration-none">
            <div class="d-flex align-items-center p-2 border-bottom" style="transition:0.2s;">
                <img src="/static/uploads/''' + other_pic + '''" style="width:36px;height:36px;border-radius:50%;object-fit:cover;">
                <div class="ms-2 flex-grow-1">
                    <div>''' + name_display + '''</div>
                    <div class="text-muted small" style="font-size:11px;">''' + msg_preview + '''</div>
                </div>
                <small class="text-muted" style="font-size:10px;">''' + msg['created_at'][11:16] + '''</small>
            </div>
        </a>
        '''
    
    if not conv_html:
        conv_html = '<div class="alert alert-info text-center" style="font-size:13px;padding:12px;border-radius:12px;">لا توجد رسائل</div>'
    
    content = '''
    <div class="card border-0 shadow-sm" style="border-radius:16px;">
        <div class="card-header bg-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-envelope"></i> رسائلي</h6>
        </div>
        <div class="card-body p-0">
            ''' + conv_html + '''
        </div>
    </div>
    '''
    return render_page('الرسائل', content)

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    if is_user_blocked(session['user_id'], user_id):
        content = '''
        <div class="blocked-banner">
            <i class="fas fa-ban"></i>
            <h6>لا يمكنك مراسلة هذا المستخدم</h6>
            <p style="font-size:13px;">تم حظر هذا المستخدم</p>
        </div>
        '''
        return render_page('محظور', content)
    
    receiver = get_user(user_id)
    if not receiver:
        flash('مستخدم غير موجود', 'danger')
        return redirect(url_for('home'))
    
    friends = read_json('friends')
    is_friend = any(
        (f['from_user_id'] == session['user_id'] and f['to_user_id'] == user_id and f['status'] == 'accepted') or
        (f['from_user_id'] == user_id and f['to_user_id'] == session['user_id'] and f['status'] == 'accepted')
        for f in friends
    )
    current_user = get_user(session['user_id'])
    if not is_friend and not current_user.get('is_developer', False) and user_id != session['user_id']:
        flash('يمكنك مراسلة الأصدقاء فقط', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        image = None
        if 'image' in request.files and request.files['image'].filename:
            image = save_image(request.files['image'], 'chat')
        
        if not content and not image:
            flash('الرجاء كتابة رسالة أو اختيار صورة', 'danger')
            return redirect(url_for('chat', user_id=user_id))
        
        messages = read_json('messages')
        new_msg = {
            'id': get_next_id('messages'),
            'sender_id': session['user_id'],
            'receiver_id': user_id,
            'content': content,
            'image': image,
            'is_read': False,
            'created_at': datetime.utcnow().isoformat()
        }
        messages.append(new_msg)
        write_json('messages', messages)
        
        return redirect(url_for('chat', user_id=user_id))
    
    all_messages = read_json('messages')
    chat_messages = []
    for msg in all_messages:
        if (msg['sender_id'] == session['user_id'] and msg['receiver_id'] == user_id) or (msg['sender_id'] == user_id and msg['receiver_id'] == session['user_id']):
            chat_messages.append(msg)
            if msg['receiver_id'] == session['user_id'] and not msg['is_read']:
                msg['is_read'] = True
    write_json('messages', all_messages)
    chat_messages.sort(key=lambda x: x['created_at'])
    
    msgs_html = ''
    for msg in chat_messages:
        is_sent = msg['sender_id'] == session['user_id']
        image_html = ''
        if msg.get('image'):
            image_html = '<div><img src="/static/uploads/' + msg['image'] + '" class="chat-message-image" onclick="showImage(this.src)"></div>'
        msg_content = safe_text(msg.get('content', ''))
        
        sender_name = get_display_name(get_user(msg['sender_id']))
        
        msgs_html += '''
        <div class="d-flex justify-content-''' + ('end' if is_sent else 'start') + ''' mb-2">
            <div class="p-2 rounded ''' + ('bg-primary text-white' if is_sent else 'bg-light') + '''" style="max-width:75%;border-radius:18px;font-size:13px;">
                ''' + (('<strong>' + sender_name + '</strong><br>' if not is_sent else '') ) + '''
                ''' + (('<span>' + msg_content + '</span>' if msg_content else '') ) + image_html + '''
                <br><small class="text-muted" style="font-size:9px;">''' + msg['created_at'][11:16] + '''</small>
            </div>
        </div>
        '''
    
    receiver_name_display = render_user_display(receiver, size='small')
    
    content = f'''
    <div class="card border-0 shadow-sm" style="border-radius:16px;height:85vh;">
        <div class="card-header bg-white border-0 d-flex align-items-center p-2" style="border-radius:16px 16px 0 0;">
            <a href="/profile/{user_id}" class="text-decoration-none d-flex align-items-center">
                <img src="/static/uploads/{get_profile_pic(receiver)}" style="width:32px;height:32px;border-radius:50%;object-fit:cover;">
                <span class="ms-2">{receiver_name_display}</span>
            </a>
            <div class="ms-auto">
                <button class="btn btn-sm btn-outline-danger" onclick="blockUser({user_id})" style="font-size:10px;padding:2px 10px;border-radius:15px;">
                    <i class="fas fa-ban"></i> حظر
                </button>
            </div>
        </div>
        <div class="card-body chat-box" id="chatBox" style="overflow-y:auto;height:calc(100% - 100px);background:#f0f2f5;padding:10px;">
            {msgs_html if msgs_html else '<div class="text-center text-muted mt-5" style="font-size:13px;">لا توجد رسائل</div>'}
        </div>
        <div class="card-footer bg-white border-0 p-2">
            <form method="POST" enctype="multipart/form-data" id="chatForm" class="d-flex gap-2">
                <input type="text" name="content" class="form-control" placeholder="اكتب رسالتك..." id="msgInput" style="border-radius:25px;font-size:13px;padding:6px 14px;border:1px solid #e4e6eb;">
                <div class="file-input-wrapper position-relative">
                    <i class="fas fa-image chat-image-icon" style="font-size:18px;color:#1877f2;cursor:pointer;padding:6px 8px;border-radius:50%;transition:0.2s;"></i>
                    <input type="file" name="image" accept="image/*" id="imageInput" style="position:absolute;left:0;top:0;opacity:0;width:100%;height:100%;cursor:pointer;">
                </div>
                <button type="submit" class="btn btn-primary" style="border-radius:50%;width:38px;height:38px;padding:0;display:flex;align-items:center;justify-content:center;"><i class="fas fa-paper-plane" style="font-size:14px;"></i></button>
            </form>
        </div>
    </div>
    
    <script>
    var chatBox = document.getElementById('chatBox');
    chatBox.scrollTop = chatBox.scrollHeight;
    
    $('#chatForm').on('submit', function(e) {{
        e.preventDefault();
        var formData = new FormData(this);
        fetch(window.location.href, {{method: 'POST', body: formData}})
            .then(() => {{
                $('#msgInput').val('');
                $('#imageInput').val('');
                $('#chatBox').scrollTop($('#chatBox')[0].scrollHeight);
            }});
    }});
    </script>
    '''
    return render_page('دردشة خاصة', content)

# ==================== الدردشات الجماعية ====================
@socketio.on('join')
def handle_join(data):
    join_room(data['room'])

@app.route('/group_chats')
@login_required
def group_chats():
    blocked_ids = get_blocked_user_ids(session['user_id'])
    all_chats = read_json('group_chats')
    my_chats = [c for c in all_chats if session['user_id'] in c.get('members', [])]
    
    chats_html = ''
    for c in my_chats:
        chats_html += '''
        <div class="col-12 mb-2">
            <div class="card border-0 shadow-sm" style="border-radius:12px;">
                <div class="card-body p-3">
                    <h6 style="font-size:14px;"><i class="fas fa-comments" style="color:#1877f2;"></i> ''' + c['name'] + '''</h6>
                    <p class="text-muted small" style="font-size:11px;">''' + c.get('description', '')[:80] + '''</p>
                    <small class="text-muted" style="font-size:11px;"><i class="fas fa-user-friends"></i> ''' + str(len(c.get('members', []))) + ''' عضو</small>
                    <a href="/group_chat/''' + str(c['id']) + '''" class="btn btn-primary btn-sm d-block mt-2" style="font-size:12px;padding:4px 10px;border-radius:20px;"><i class="fas fa-sign-in-alt"></i> دخول</a>
                </div>
            </div>
        </div>
        '''
    
    content = '''
    <div class="row">
        <div class="col-12 mb-2">
            <a href="/create_group_chat" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;"><i class="fas fa-plus-circle"></i> انشاء دردشة جماعية</a>
        </div>
        ''' + (chats_html if chats_html else '<div class="alert alert-info" style="font-size:13px;padding:12px;border-radius:12px;">لا توجد دردشات</div>') + '''
    </div>
    '''
    return render_page('الدردشات الجماعية', content)

@app.route('/create_group_chat', methods=['GET', 'POST'])
@login_required
def create_group_chat():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('ادخل اسم الدردشة', 'danger')
            return redirect(url_for('create_group_chat'))
        
        chats = read_json('group_chats')
        new_id = get_next_id('group_chats')
        chats.append({
            'id': new_id,
            'name': name,
            'description': request.form.get('description', ''),
            'created_by': session['user_id'],
            'members': [session['user_id']],
            'messages': [],
            'created_at': datetime.utcnow().isoformat()
        })
        write_json('group_chats', chats)
        flash('تم انشاء الدردشة', 'success')
        return redirect(url_for('group_chats'))
    
    content = '''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-body p-3">
                    <h5 class="text-center mb-2"><i class="fas fa-comments"></i> انشاء دردشة جماعية</h5>
                    <form method="POST">
                        <div class="mb-2">
                            <input type="text" name="name" class="form-control" placeholder="اسم الدردشة" required style="font-size:14px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;">
                        </div>
                        <div class="mb-2">
                            <textarea name="description" class="form-control" rows="3" placeholder="وصف الدردشة (اختياري)" style="font-size:13px;border-radius:12px;border:1px solid #e4e6eb;padding:8px 12px;"></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary w-100" style="border-radius:25px;padding:8px;font-size:14px;">انشاء</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page('انشاء دردشة جماعية', content)

@app.route('/group_chat/<int:chat_id>', methods=['GET', 'POST'])
@login_required
def group_chat(chat_id):
    chats = read_json('group_chats')
    chat = None
    for c in chats:
        if c['id'] == chat_id:
            chat = c
            break
    
    if not chat:
        flash('الدردشة غير موجودة', 'danger')
        return redirect(url_for('group_chats'))
    
    if session['user_id'] not in chat.get('members', []):
        flash('ليس لديك صلاحية للدخول', 'danger')
        return redirect(url_for('group_chats'))
    
    current_user_data = get_user(session['user_id'])
    is_creator = chat['created_by'] == session['user_id']
    is_dev = current_user_data.get('is_developer', False)
    room = f'group_{chat_id}'
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        image = None
        if 'image' in request.files and request.files['image'].filename:
            image = save_image(request.files['image'], 'groupchat')
        
        if not content and not image:
            flash('الرجاء كتابة رسالة أو اختيار صورة', 'danger')
            return redirect(url_for('group_chat', chat_id=chat_id))
        
        new_msg = {
            'id': len(chat['messages']) + 1,
            'sender_id': session['user_id'],
            'sender_name': get_display_name(current_user_data),
            'content': content,
            'image': image,
            'created_at': datetime.utcnow().isoformat()
        }
        chat['messages'].append(new_msg)
        write_json('group_chats', chats)
        
        return redirect(url_for('group_chat', chat_id=chat_id))
    
    msgs_html = ''
    for msg in chat.get('messages', []):
        is_sent = msg['sender_id'] == session['user_id']
        image_html = ''
        if msg.get('image'):
            image_html = '<div><img src="/static/uploads/' + msg['image'] + '" class="chat-message-image" onclick="showImage(this.src)"></div>'
        msg_content = safe_text(msg.get('content', ''))
        
        msgs_html += '''
        <div class="d-flex justify-content-''' + ('end' if is_sent else 'start') + ''' mb-2">
            <div class="p-2 rounded ''' + ('bg-primary text-white' if is_sent else 'bg-light') + '''" style="max-width:75%;border-radius:18px;font-size:13px;">
                <strong style="font-size:12px;">''' + msg['sender_name'] + ''':</strong><br>
                ''' + (('<span>' + msg_content + '</span>' if msg_content else '') ) + image_html + '''
                <br><small class="text-muted" style="font-size:9px;">''' + msg['created_at'][11:16] + '''</small>
            </div>
        </div>
        '''
    
    admin_buttons = ''
    if is_creator or is_dev:
        admin_buttons = f'<a href="/add_member_to_group_chat/{chat_id}" class="btn btn-info btn-sm mt-2" style="font-size:11px;padding:3px 12px;border-radius:20px;"><i class="fas fa-user-plus"></i> إدارة الأعضاء</a>'
    
    content = f'''
    <div class="card border-0 shadow-sm" style="border-radius:16px;height:85vh;">
        <div class="card-header bg-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0" style="font-size:14px;"><i class="fas fa-comments" style="color:#1877f2;"></i> {chat['name']}</h6>
            <small class="text-muted" style="font-size:10px;"><i class="fas fa-user-friends"></i> {len(chat.get('members', []))} عضو</small>
        </div>
        <div class="card-body chat-box" id="chatBox" style="overflow-y:auto;height:calc(100% - 100px);background:#f0f2f5;padding:10px;">
            {msgs_html if msgs_html else '<div class="text-center text-muted mt-5" style="font-size:13px;">لا توجد رسائل</div>'}
        </div>
        <div class="card-footer bg-white border-0 p-2">
            <form method="POST" enctype="multipart/form-data" id="groupChatForm" class="d-flex gap-2">
                <input type="text" name="content" class="form-control" placeholder="اكتب رسالتك للجميع..." id="msgInput" style="border-radius:25px;font-size:13px;padding:6px 14px;border:1px solid #e4e6eb;">
                <div class="file-input-wrapper position-relative">
                    <i class="fas fa-image chat-image-icon" style="font-size:18px;color:#1877f2;cursor:pointer;padding:6px 8px;border-radius:50%;transition:0.2s;"></i>
                    <input type="file" name="image" accept="image/*" id="imageInput" style="position:absolute;left:0;top:0;opacity:0;width:100%;height:100%;cursor:pointer;">
                </div>
                <button type="submit" class="btn btn-primary" style="border-radius:50%;width:38px;height:38px;padding:0;display:flex;align-items:center;justify-content:center;"><i class="fas fa-paper-plane" style="font-size:14px;"></i></button>
            </form>
        </div>
    </div>
    <div class="mt-2 d-flex gap-2">
        <a href="/group_chats" class="btn btn-secondary btn-sm" style="font-size:11px;padding:3px 12px;border-radius:20px;"><i class="fas fa-arrow-right"></i> رجوع</a>
        {admin_buttons}
    </div>
    
    <script>
    var chatBox = document.getElementById('chatBox');
    chatBox.scrollTop = chatBox.scrollHeight;
    
    $('#groupChatForm').on('submit', function(e) {{
        e.preventDefault();
        var formData = new FormData(this);
        fetch(window.location.href, {{method: 'POST', body: formData}})
            .then(() => {{
                $('#msgInput').val('');
                $('#imageInput').val('');
                $('#chatBox').scrollTop($('#chatBox')[0].scrollHeight);
            }});
    }});
    </script>
    '''
    return render_page(chat['name'], content)

# ==================== إدارة أعضاء الدردشات الجماعية ====================
@app.route('/add_member_to_group_chat/<int:chat_id>', methods=['GET', 'POST'])
@login_required
def add_member_to_group_chat(chat_id):
    group_chats = read_json('group_chats')
    chat = None
    for gc in group_chats:
        if gc['id'] == chat_id:
            chat = gc
            break
    
    if not chat:
        flash('الدردشة غير موجودة', 'danger')
        return redirect(url_for('group_chats'))
    
    current_user_data = get_user(session['user_id'])
    is_creator = chat['created_by'] == session['user_id']
    is_dev = current_user_data.get('is_developer', False)
    
    if not (is_creator or is_dev):
        flash('ليس لديك صلاحية لإضافة أعضاء', 'danger')
        return redirect(url_for('group_chat', chat_id=chat_id))
    
    if request.method == 'POST':
        username = request.form['username'].upper()
        user_to_add = get_user_by_username(username)
        
        if not user_to_add:
            flash('المستخدم غير موجود', 'danger')
        elif user_to_add['id'] in chat.get('members', []):
            flash('المستخدم موجود بالفعل في الدردشة', 'danger')
        elif is_user_blocked(session['user_id'], user_to_add['id']):
            flash('لا يمكن إضافة مستخدم محظور', 'danger')
        else:
            chat['members'].append(user_to_add['id'])
            write_json('group_chats', group_chats)
            flash(f'تم إضافة العضو {get_display_name(user_to_add)}', 'success')
        return redirect(url_for('group_chat', chat_id=chat_id))
    
    members_list = ''
    for mid in chat.get('members', []):
        member = get_user(mid)
        if not member:
            continue
        
        member_pic = get_profile_pic(member)
        name_display = render_user_display(member, size='small')
        members_list += f'''
        <li class="list-group-item d-flex justify-content-between align-items-center" style="font-size:13px;padding:6px 10px;border:none;border-bottom:1px solid #e4e6eb;">
            <div>
                <img src="/static/uploads/{member_pic}" style="width:28px;height:28px;border-radius:50%;object-fit:cover;margin-left:6px;">
                {name_display}
                {'<span class="badge bg-primary ms-1" style="font-size:8px;padding:2px 6px;">منشئ</span>' if mid == chat['created_by'] else ''}
                {'<span class="badge bg-warning ms-1" style="font-size:8px;padding:2px 6px;">مطور</span>' if member.get('is_developer') else ''}
            </div>
            {f'<button class="btn btn-sm btn-danger" onclick="removeMember({chat_id}, {mid})" style="font-size:10px;padding:2px 10px;border-radius:15px;">حذف</button>' if (is_creator or is_dev) and mid != session['user_id'] else ''}
        </li>
        '''
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-12">
            <div class="card shadow border-0" style="border-radius:16px;">
                <div class="card-header bg-info text-white border-0 p-2" style="border-radius:16px 16px 0 0;">
                    <h6 class="mb-0" style="font-size:14px;"><i class="fas fa-user-plus"></i> إدارة أعضاء الدردشة: {chat['name']}</h6>
                </div>
                <div class="card-body p-3">
                    <form method="POST" class="mb-3">
                        <div class="input-group" style="flex-wrap:nowrap;">
                            <input type="text" name="username" class="form-control" placeholder="أدخل اسم المستخدم" required style="font-size:13px;border-radius:12px 0 0 12px;border:1px solid #e4e6eb;">
                            <button type="submit" class="btn btn-primary" style="font-size:13px;border-radius:0 12px 12px 0;"><i class="fas fa-plus"></i> إضافة</button>
                        </div>
                        <small class="text-muted" style="font-size:10px;">أدخل اسم المستخدم (أحرف إنجليزية وأرقام فقط)</small>
                    </form>
                    
                    <hr>
                    <h6 style="font-size:13px;"><i class="fas fa-users"></i> الأعضاء الحاليين ({len(chat.get('members', []))})</h6>
                    <ul class="list-group">
                        {members_list if members_list else '<li class="list-group-item text-muted" style="font-size:13px;padding:6px 10px;border:none;">لا يوجد أعضاء</li>'}
                    </ul>
                    
                    <div class="mt-3">
                        <a href="/group_chat/{chat_id}" class="btn btn-secondary btn-sm" style="font-size:11px;padding:3px 12px;border-radius:20px;"><i class="fas fa-arrow-right"></i> رجوع</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    function removeMember(chatId, userId) {{
        if(confirm('هل أنت متأكد من حذف هذا العضو؟')) {{
            fetch('/remove_member_from_group_chat/' + chatId + '/' + userId, {{method: 'POST'}})
                .then(() => location.reload());
        }}
    }}
    </script>
    '''
    return render_page('إدارة الأعضاء', content)

@app.route('/remove_member_from_group_chat/<int:chat_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member_from_group_chat(chat_id, user_id):
    group_chats = read_json('group_chats')
    chat = None
    for gc in group_chats:
        if gc['id'] == chat_id:
            chat = gc
            break
    
    if not chat:
        return jsonify({'error': 'الدردشة غير موجودة'})
    
    current_user_data = get_user(session['user_id'])
    is_creator = chat['created_by'] == session['user_id']
    is_dev = current_user_data.get('is_developer', False)
    
    if not (is_creator or is_dev):
        return jsonify({'error': 'ليس لديك صلاحية'})
    
    if user_id in chat.get('members', []):
        chat['members'].remove(user_id)
        write_json('group_chats', group_chats)
    
    return jsonify({'success': True})

# ==================== الإشعارات ====================
@app.route('/notifications')
@login_required
def notifications_page():
    mark_notifications_read(session['user_id'])
    notifications = get_user_notifications(session['user_id'])
    
    content = '''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-white border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-bell"></i> جميع الإشعارات</h6>
        </div>
        <div class="card-body p-0">
            ''' + (''.join([f'''
            <div class="notification-item {'unread' if not n.get('is_read') else ''}" style="padding:10px 14px;border-bottom:1px solid #e4e6eb;font-size:13px;">
                <a href="{n.get('link', '#')}" class="text-decoration-none d-block">
                    {n['message']}
                    <br>
                    <small class="text-muted" style="font-size:10px;"><i class="fas fa-clock"></i> {n['created_at'][:19]}</small>
                </a>
            </div>
            ''' for n in notifications]) if notifications else '<div class="text-muted text-center p-3" style="font-size:13px;"><i class="fas fa-bell-slash"></i> لا توجد إشعارات</div>') + '''
        </div>
    </div>
    '''
    return render_page('الإشعارات', content)

# ==================== لوحة المطور ====================
@app.route('/developer_panel')
@developer_required
def developer_panel():
    users = read_json('users')
    posts = read_json('posts')
    reels = read_json('reels')
    group_chats = read_json('group_chats')
    reports = report_system.get_reports()
    pending_reports = [r for r in reports if r['status'] == 'pending']
    
    users_html = ''
    for u in users:
        u_pic = get_profile_pic(u)
        name_display = render_user_display(u, size='small')
        
        users_html += f'''
        <div class="col-6 mb-2">
            <div class="border rounded p-2 d-flex align-items-center justify-content-between" style="font-size:10px;background:#f8f9fa;">
                <div class="d-flex align-items-center">
                    <img src="/static/uploads/{u_pic}" style="width:24px;height:24px;border-radius:50%;object-fit:cover;margin-left:6px;">
                    <div>
                        {name_display}
                        <br>
                        <small style="font-size:8px;color:#65676b;">@{u['username']}</small>
                    </div>
                </div>
                <div>
                    <a href="/verify/{u['id']}" class="btn btn-sm btn-info" style="font-size:7px;padding:2px 6px;border-radius:12px;">{'إزالة' if u.get('is_verified') else 'توثيق'}</a>
                    <a href="/make_developer/{u['id']}" class="btn btn-sm btn-warning" style="font-size:7px;padding:2px 6px;border-radius:12px;">{'إزالة مطور' if u.get('is_developer') else 'مطور'}</a>
                    <a href="/delete_user/{u['id']}" class="btn btn-sm btn-danger" onclick="return confirm('حذف؟')" style="font-size:7px;padding:2px 6px;border-radius:12px;"><i class="fas fa-trash"></i></a>
                </div>
            </div>
        </div>
        '''
    
    reels_html = ''
    for r in reels:
        author = get_user(r['user_id'])
        reels_html += f'''
        <div class="col-6 mb-2">
            <div class="border rounded p-2 d-flex justify-content-between align-items-center" style="font-size:10px;background:#f8f9fa;">
                <div>
                    <strong><i class="fas fa-video"></i> {get_display_name(author)}</strong>
                    <br><small style="font-size:8px;">{r.get('description', '')[:20]}</small>
                </div>
                <a href="/delete_reel_admin/{r['id']}" class="btn btn-sm btn-danger" onclick="return confirm('حذف؟')" style="font-size:7px;padding:2px 6px;border-radius:12px;"><i class="fas fa-trash"></i></a>
            </div>
        </div>
        '''
    
    group_chats_html = ''
    for gc in group_chats:
        group_chats_html += f'''
        <div class="col-6 mb-2">
            <div class="border rounded p-2 d-flex justify-content-between" style="font-size:10px;background:#f8f9fa;">
                <strong>{gc['name']}</strong>
                <a href="/delete_group_chat_admin/{gc['id']}" class="btn btn-sm btn-danger" onclick="return confirm('حذف؟')" style="font-size:7px;padding:2px 6px;border-radius:12px;"><i class="fas fa-trash"></i></a>
            </div>
        </div>
        '''
    
    if not group_chats_html:
        group_chats_html = '<p style="font-size:10px;color:#65676b;">لا توجد دردشات</p>'
    
    content = f'''
    <div class="card shadow border-0" style="border-radius:16px;">
        <div class="card-header bg-warning border-0 p-2" style="border-radius:16px 16px 0 0;">
            <h6 class="mb-0"><i class="fas fa-tools"></i> لوحة تحكم المطور</h6>
            <small style="font-size:9px;">توثيق - مطور - حذف - إدارة البلاغات</small>
        </div>
        <div class="card-body p-3">
            <div class="alert alert-danger" style="font-size:12px;padding:8px;border-radius:10px;">
                <i class="fas fa-flag"></i> بلاغات معلقة: <strong>{len(pending_reports)}</strong>
                <a href="/reports_panel" class="btn btn-sm btn-danger ms-2" style="font-size:10px;padding:2px 10px;border-radius:15px;">عرض</a>
            </div>
            
            <h6 style="font-size:11px;"><i class="fas fa-users"></i> المستخدمين ({len(users)})</h6>
            <div class="row">{users_html}</div>
            
            <h6 class="mt-3" style="font-size:11px;"><i class="fas fa-film"></i> الريلزات ({len(reels)})</h6>
            <div class="row">{reels_html if reels_html else '<p style="font-size:10px;color:#65676b;">لا توجد ريلزات</p>'}</div>
            
            <h6 class="mt-3" style="font-size:11px;"><i class="fas fa-comments"></i> الدردشات الجماعية ({len(group_chats)})</h6>
            <div class="row">{group_chats_html}</div>
        </div>
    </div>
    '''
    return render_page('لوحة المطور', content)

@app.route('/make_developer/<int:user_id>')
@developer_required
def make_developer(user_id):
    users = read_json('users')
    for u in users:
        if u['id'] == user_id:
            u['is_developer'] = not u.get('is_developer', False)
            if u['is_developer']:
                u['is_verified'] = True
                flash(f'✅ تم إضافة {get_display_name(u)} كمطور', 'success')
            else:
                flash(f'❌ تم إزالة {get_display_name(u)} من المطورين', 'success')
            break
    write_json('users', users)
    return redirect(url_for('developer_panel'))

@app.route('/verify/<int:user_id>')
@developer_required
def verify_user(user_id):
    users = read_json('users')
    for u in users:
        if u['id'] == user_id:
            u['is_verified'] = not u.get('is_verified', False)
            break
    write_json('users', users)
    flash('تم تغيير التوثيق', 'success')
    return redirect(url_for('developer_panel'))

@app.route('/delete_user/<int:user_id>')
@developer_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('لا يمكن حذف نفسك', 'danger')
        return redirect(url_for('developer_panel'))
    
    users = read_json('users')
    users = [u for u in users if u['id'] != user_id]
    write_json('users', users)
    flash('تم حذف المستخدم', 'success')
    return redirect(url_for('developer_panel'))

@app.route('/delete_reel_admin/<int:reel_id>')
@developer_required
def delete_reel_admin(reel_id):
    reels = read_json('reels')
    reels = [r for r in reels if r['id'] != reel_id]
    write_json('reels', reels)
    flash('تم حذف الريلز', 'success')
    return redirect(url_for('developer_panel'))

@app.route('/delete_group_chat_admin/<int:chat_id>')
@developer_required
def delete_group_chat_admin(chat_id):
    chats = read_json('group_chats')
    chats = [c for c in chats if c['id'] != chat_id]
    write_json('group_chats', chats)
    flash('تم حذف الدردشة', 'success')
    return redirect(url_for('developer_panel'))

@app.route('/logout')
def logout():
    session.clear()
    flash('تم الخروج', 'info')
    return redirect(url_for('login'))

# ==================== إحصائيات المستخدمين ====================
@app.route('/user_stats')
def user_stats():
    users = read_json('users')
    blocked_ids = []
    if 'user_id' in session:
        blocked_ids = get_blocked_user_ids(session['user_id'])
    
    visible_users = [u for u in users if u['id'] not in blocked_ids]
    
    stats = {
        'total_users': len(visible_users),
        'verified_users': len([u for u in visible_users if u.get('is_verified', False)]),
        'developers': len([u for u in visible_users if u.get('is_developer', False)]),
        'mini_pic_users': len([u for u in visible_users if u.get('mini_pic_enabled', False) and u.get('mini_pic')]),
        'total_posts': len(read_json('posts')),
        'total_reels': len(read_json('reels')),
        'total_messages': len(read_json('messages')),
        'total_group_chats': len(read_json('group_chats'))
    }
    return jsonify(stats)

# ==================== إضافة إحصائيات المستخدمين ====================
original_render_page = render_page

def render_page_with_stats(title, content):
    html = original_render_page(title, content)
    user_stats_html = '''
    <div class="mt-4 pt-3 border-top" style="font-size:10px;color:#65676b;text-align:center;" id="userStats">
        <span class="text-muted">جاري تحميل الإحصائيات...</span>
    </div>
    <script>
    $(document).ready(function() {
        fetch('/user_stats')
            .then(res => res.json())
            .then(data => {
                var statsHtml = '<span class="text-muted">👥 ' + data.total_users + ' مستخدم';
                if (data.total_users > 1) statsHtml += 'ين';
                statsHtml += ' | ✅ ' + data.verified_users + ' موثق';
                statsHtml += ' | 👑 ' + data.developers + ' مطور';
                statsHtml += ' | 🖼️ ' + data.mini_pic_users + ' صورة مصغرة';
                statsHtml += ' | 📝 ' + data.total_posts + ' منشور';
                statsHtml += ' | 🎬 ' + data.total_reels + ' ريلز';
                statsHtml += ' | 💬 ' + data.total_messages + ' رسالة';
                statsHtml += ' | 🏠 ' + data.total_group_chats + ' مجموعة';
                statsHtml += '</span>';
                $('#userStats').html(statsHtml);
            })
            .catch(() => {
                $('#userStats').html('<span class="text-muted">الإحصائيات غير متاحة حالياً</span>');
            });
    });
    </script>
    '''
    return html.replace('</body>', user_stats_html + '</body>')

render_page = render_page_with_stats

if __name__ == '__main__':
    if not os.path.exists('static/uploads/default_profile.jpg'):
        download_default_image()
    
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
        print('تم انشاء حساب المطور MBL')
    
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
        print('تم انشاء حساب المطور MBLL')
    
    print('\n' + '='*60)
    print('🛡️ CAW | جميع الأزرار تعمل بشكل مثالي')
    print('📍 http://93.115.101.180:20219/')
    print('👑 المطور الأول: MBL / MBL')
    print('👑 المطور الثاني: MBLL / MBMB')
    print('✅ الأزرار العاملة:')
    print('   - حظر / إلغاء حظر')
    print('   - لايك / تعليق')
    print('   - إبلاغ')
    print('   - إضافة صداقة / قبول')
    print('   - 3 نقاط مع جميع الخيارات')
    print('='*60 + '\n')
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
