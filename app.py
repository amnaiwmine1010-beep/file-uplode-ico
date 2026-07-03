import os
import shutil
import mimetypes
import datetime
import random
import string
import bcrypt
import jwt
import psutil  # <-- নতুন যোগ
from functools import wraps
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename

# ========== কনফিগারেশন ==========
app = Flask(__name__, static_folder='static')
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///speedx.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'speedx_super_secret_123')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

BASE_STORAGE = os.path.join(os.getcwd(), 'storage')
if not os.path.exists(BASE_STORAGE):
    os.makedirs(BASE_STORAGE)

db = SQLAlchemy(app)

# ========== ডেটাবেজ মডেল ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    original_url = db.Column(db.String(500), nullable=False)
    custom_slug = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Popup(db.Model):  # <-- নতুন মডেল (Phase 6)
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    button_text = db.Column(db.String(50), default='Learn More')
    button_link = db.Column(db.String(500), default='#')
    scheduled_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Activity(db.Model):  # <-- নতুন মডেল (Phase 4)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ========== হেল্পার ও মিডলওয়্যার ==========
def generate_slug():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

def log_activity(user_id, action, ip=None):
    """অ্যাক্টিভিটি লগ সংরক্ষণ"""
    try:
        if not ip:
            ip = request.remote_addr if request else '0.0.0.0'
        activity = Activity(user_id=user_id, action=action, ip_address=ip)
        db.session.add(activity)
        db.session.commit()
    except:
        pass

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-auth-token')
        if not token:
            return jsonify({'msg': 'No token'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['id'])
            if not current_user or current_user.is_banned:
                return jsonify({'msg': 'User banned or not found'}), 403
        except:
            return jsonify({'msg': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'msg': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def get_safe_path(subpath):
    if not subpath or subpath == '/':
        return BASE_STORAGE
    safe_path = os.path.normpath(os.path.join(BASE_STORAGE, subpath.lstrip('/')))
    if not safe_path.startswith(os.path.realpath(BASE_STORAGE)):
        return None
    return safe_path

# ========== অথেন্টিকেশন API ==========
@app.route('/')
def home():
    return jsonify({'msg': '🚀 SpeedX Python Server Running'})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'msg': 'Username and password required'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'msg': 'User already exists'}), 400
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password=hashed.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'msg': 'User created successfully'}), 201
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'msg': 'Invalid credentials'}), 400
        if user.is_banned:
            return jsonify({'msg': 'You are banned by SpeedX Admin'}), 403
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            token = jwt.encode({
                'id': user.id,
                'role': user.role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            # লগইন অ্যাক্টিভিটি লগ
            log_activity(user.id, f'User logged in', request.remote_addr)
            return jsonify({'token': token, 'username': user.username, 'role': user.role})
        return jsonify({'msg': 'Invalid credentials'}), 400
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# ========== লিংক ম্যানেজমেন্ট API ==========
@app.route('/api/links', methods=['POST'])
@token_required
def create_link(current_user):
    try:
        data = request.json
        original_url = data.get('originalUrl')
        custom_slug = data.get('customSlug')
        if not original_url:
            return jsonify({'msg': 'URL is required'}), 400
        slug = custom_slug if custom_slug else generate_slug()
        if Link.query.filter_by(custom_slug=slug).first():
            return jsonify({'msg': 'Slug already taken'}), 400
        new_link = Link(user_id=current_user.id, original_url=original_url, custom_slug=slug)
        db.session.add(new_link)
        db.session.commit()
        log_activity(current_user.id, f'Created link: {slug}', request.remote_addr)
        return jsonify({'msg': 'Link created', 'shortUrl': f'https://yourdomain.com/{slug}', 'slug': slug})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/links', methods=['GET'])
@token_required
def get_links(current_user):
    try:
        links = Link.query.filter_by(user_id=current_user.id).all()
        result = [{'id': l.id, 'originalUrl': l.original_url, 'customSlug': l.custom_slug, 'isActive': l.is_active} for l in links]
        return jsonify(result)
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/links/<int:link_id>', methods=['PUT'])
@token_required
def update_link(current_user, link_id):
    try:
        link = Link.query.get(link_id)
        if not link or link.user_id != current_user.id:
            return jsonify({'msg': 'Link not found'}), 404
        data = request.json
        if 'originalUrl' in data:
            link.original_url = data['originalUrl']
        if 'customSlug' in data:
            if Link.query.filter_by(custom_slug=data['customSlug']).first():
                return jsonify({'msg': 'Slug already taken'}), 400
            link.custom_slug = data['customSlug']
        db.session.commit()
        log_activity(current_user.id, f'Updated link: {link.custom_slug}', request.remote_addr)
        return jsonify({'msg': 'Updated successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/links/<int:link_id>', methods=['DELETE'])
@token_required
def delete_link(current_user, link_id):
    try:
        link = Link.query.get(link_id)
        if not link or link.user_id != current_user.id:
            return jsonify({'msg': 'Link not found'}), 404
        db.session.delete(link)
        db.session.commit()
        log_activity(current_user.id, f'Deleted link: {link.custom_slug}', request.remote_addr)
        return jsonify({'msg': 'Deleted successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# ========== অ্যাডমিন: ইউজার ম্যানেজমেন্ট ==========
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    try:
        users = User.query.all()
        result = [{'id': u.id, 'username': u.username, 'role': u.role, 'isBanned': u.is_banned} for u in users]
        return jsonify(result)
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/admin/ban/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def ban_user(current_user, user_id):
    try:
        if current_user.id == user_id:
            return jsonify({'msg': 'You cannot ban yourself'}), 400
        user = User.query.get(user_id)
        if not user:
            return jsonify({'msg': 'User not found'}), 404
        data = request.json
        user.is_banned = data.get('isBanned', True)
        db.session.commit()
        status = 'Banned' if user.is_banned else 'Unbanned'
        log_activity(current_user.id, f'{status} user: {user.username}', request.remote_addr)
        return jsonify({'msg': f'User {status} by SpeedX Admin'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# =========================================
# ========== PHASE 2: ফাইল ম্যানেজার ==========
# =========================================
@app.route('/api/files/list', methods=['GET'])
@token_required
def list_files(current_user):
    try:
        path = request.args.get('path', '')
        safe_path = get_safe_path(path)
        if not safe_path:
            return jsonify({'msg': 'Invalid path'}), 400
        if not os.path.exists(safe_path):
            return jsonify({'msg': 'Path does not exist'}), 404
        if not os.path.isdir(safe_path):
            return jsonify({'msg': 'Not a directory'}), 400

        items = []
        for item in os.listdir(safe_path):
            if item.startswith('.'):
                continue
            item_full = os.path.join(safe_path, item)
            items.append({
                'name': item,
                'type': 'folder' if os.path.isdir(item_full) else 'file',
                'size': os.path.getsize(item_full) if os.path.isfile(item_full) else 0,
                'modified': datetime.datetime.fromtimestamp(os.path.getmtime(item_full)).isoformat()
            })
        items.sort(key=lambda x: (x['type'] != 'folder', x['name'].lower()))
        return jsonify({'path': path, 'items': items})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    try:
        path = request.form.get('path', '')
        safe_path = get_safe_path(path)
        if not safe_path:
            return jsonify({'msg': 'Invalid path'}), 400
        if not os.path.exists(safe_path):
            os.makedirs(safe_path)

        if 'file' not in request.files:
            return jsonify({'msg': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'msg': 'No selected file'}), 400

        filename = secure_filename(file.filename)
        save_to = os.path.join(safe_path, filename)
        file.save(save_to)
        log_activity(current_user.id, f'Uploaded file: {filename}', request.remote_addr)
        return jsonify({'msg': 'File uploaded successfully', 'name': filename})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/folder', methods=['POST'])
@token_required
def create_folder(current_user):
    try:
        data = request.json
        path = data.get('path', '')
        folder_name = data.get('folderName', '')
        if not folder_name:
            return jsonify({'msg': 'Folder name required'}), 400
        safe_path = get_safe_path(path)
        if not safe_path:
            return jsonify({'msg': 'Invalid path'}), 400
        new_folder = os.path.join(safe_path, secure_filename(folder_name))
        if os.path.exists(new_folder):
            return jsonify({'msg': 'Folder already exists'}), 400
        os.makedirs(new_folder)
        log_activity(current_user.id, f'Created folder: {folder_name}', request.remote_addr)
        return jsonify({'msg': 'Folder created'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/rename', methods=['PUT'])
@token_required
def rename_item(current_user):
    try:
        data = request.json
        path = data.get('path', '')
        new_name = data.get('newName', '')
        if not new_name:
            return jsonify({'msg': 'New name required'}), 400
        safe_path = get_safe_path(path)
        if not safe_path or not os.path.exists(safe_path):
            return jsonify({'msg': 'Item not found'}), 404
        dirname = os.path.dirname(safe_path)
        new_path = os.path.join(dirname, secure_filename(new_name))
        if os.path.exists(new_path):
            return jsonify({'msg': 'Name already taken'}), 400
        os.rename(safe_path, new_path)
        log_activity(current_user.id, f'Renamed item to: {new_name}', request.remote_addr)
        return jsonify({'msg': 'Renamed successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/delete', methods=['DELETE'])
@token_required
def delete_item(current_user):
    try:
        path = request.json.get('path', '')
        safe_path = get_safe_path(path)
        if not safe_path or not os.path.exists(safe_path):
            return jsonify({'msg': 'Item not found'}), 404
        if os.path.isfile(safe_path):
            os.remove(safe_path)
        else:
            shutil.rmtree(safe_path)
        log_activity(current_user.id, f'Deleted item: {path}', request.remote_addr)
        return jsonify({'msg': 'Deleted successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/preview/<path:filename>', methods=['GET'])
@token_required
def preview_file(current_user, filename):
    try:
        safe_path = get_safe_path(filename)
        if not safe_path or not os.path.isfile(safe_path):
            return jsonify({'msg': 'File not found'}), 404
        
        mime_type, _ = mimetypes.guess_type(safe_path)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        if mime_type.startswith('text') or filename.endswith(('.js', '.css', '.html', '.xml', '.json', '.py', '.txt', '.md')):
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return jsonify({'type': 'text', 'content': content, 'mime': mime_type})
        
        return send_file(safe_path, mimetype=mime_type)
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/files/download/<path:filename>', methods=['GET'])
@token_required
def download_file(current_user, filename):
    try:
        safe_path = get_safe_path(filename)
        if not safe_path or not os.path.isfile(safe_path):
            return jsonify({'msg': 'File not found'}), 404
        return send_file(safe_path, as_attachment=True)
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# =========================================
# ========== PHASE 3: কোড এডিটর API ==========
# =========================================
@app.route('/api/files/content', methods=['GET'])
@token_required
def get_file_content(current_user):
    try:
        path = request.args.get('path', '')
        safe_path = get_safe_path(path)
        if not safe_path or not os.path.isfile(safe_path):
            return jsonify({'msg': 'File not found'}), 404
        
        mime, _ = mimetypes.guess_type(safe_path)
        if mime and not mime.startswith('text') and not path.endswith(('.js','.css','.html','.xml','.json','.py','.txt','.md','.csv')):
            return jsonify({'msg': 'Not a text file'}), 400
        
        with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return jsonify({'path': path, 'content': content})
    except Exception as e:
        return jsonify({'msg': f'Error reading file: {str(e)}'}), 500

@app.route('/api/files/save', methods=['POST'])
@token_required
def save_file_content(current_user):
    try:
        data = request.json
        path = data.get('path', '')
        content = data.get('content', '')
        safe_path = get_safe_path(path)
        if not safe_path or not os.path.isfile(safe_path):
            return jsonify({'msg': 'File not found'}), 404
        
        with open(safe_path, 'w', encoding='utf-8') as f:
            f.write(content)
        log_activity(current_user.id, f'Saved file: {path}', request.remote_addr)
        return jsonify({'msg': 'File saved successfully!'})
    except Exception as e:
        return jsonify({'msg': f'Error saving: {str(e)}'}), 500

# =========================================
# ========== 🚀 PHASE 4: ড্যাশবোর্ড API ==========
# =========================================
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
@admin_required
def get_dashboard_stats(current_user):
    try:
        # CPU, RAM, Storage
        cpu = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage(BASE_STORAGE)
        
        # কাউন্ট
        total_users = User.query.count()
        total_links = Link.query.count()
        total_popups = Popup.query.count()
        total_activities = Activity.query.count()
        
        # রিসেন্ট অ্যাক্টিভিটি (সর্বশেষ ১০টি)
        recent = Activity.query.order_by(Activity.created_at.desc()).limit(10).all()
        recent_list = []
        for act in recent:
            user = User.query.get(act.user_id)
            recent_list.append({
                'username': user.username if user else 'Deleted',
                'action': act.action,
                'time': act.created_at.strftime('%Y-%m-%d %H:%M')
            })
        
        return jsonify({
            'cpu': cpu,
            'ram_total': round(ram.total / (1024**3), 2),
            'ram_used': round(ram.used / (1024**3), 2),
            'ram_percent': ram.percent,
            'storage_total': round(disk.total / (1024**3), 2),
            'storage_used': round(disk.used / (1024**3), 2),
            'storage_percent': disk.percent,
            'total_users': total_users,
            'total_links': total_links,
            'total_popups': total_popups,
            'total_activities': total_activities,
            'recent_activities': recent_list
        })
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# =========================================
# ========== 🚀 PHASE 6: পপআপ ম্যানেজার API ==========
# =========================================
@app.route('/api/popups', methods=['GET'])
@token_required
@admin_required
def get_popups(current_user):
    try:
        popups = Popup.query.order_by(Popup.created_at.desc()).all()
        result = []
        for p in popups:
            result.append({
                'id': p.id,
                'title': p.title,
                'description': p.description,
                'button_text': p.button_text,
                'button_link': p.button_link,
                'scheduled_at': p.scheduled_at.isoformat() if p.scheduled_at else None,
                'is_active': p.is_active,
                'created_at': p.created_at.isoformat()
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/popups', methods=['POST'])
@token_required
@admin_required
def create_popup(current_user):
    try:
        data = request.json
        title = data.get('title')
        if not title:
            return jsonify({'msg': 'Title is required'}), 400
        
        scheduled_at = None
        if data.get('scheduled_at'):
            try:
                scheduled_at = datetime.datetime.fromisoformat(data['scheduled_at'].replace('Z', '+00:00'))
            except:
                pass
        
        new_popup = Popup(
            title=title,
            description=data.get('description', ''),
            button_text=data.get('button_text', 'Learn More'),
            button_link=data.get('button_link', '#'),
            scheduled_at=scheduled_at,
            is_active=data.get('is_active', True)
        )
        db.session.add(new_popup)
        db.session.commit()
        log_activity(current_user.id, f'Created popup: {title}', request.remote_addr)
        return jsonify({'msg': 'Popup created successfully', 'id': new_popup.id})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/popups/<int:popup_id>', methods=['PUT'])
@token_required
@admin_required
def update_popup(current_user, popup_id):
    try:
        popup = Popup.query.get(popup_id)
        if not popup:
            return jsonify({'msg': 'Popup not found'}), 404
        
        data = request.json
        if 'title' in data: popup.title = data['title']
        if 'description' in data: popup.description = data['description']
        if 'button_text' in data: popup.button_text = data['button_text']
        if 'button_link' in data: popup.button_link = data['button_link']
        if 'is_active' in data: popup.is_active = data['is_active']
        if 'scheduled_at' in data:
            try:
                popup.scheduled_at = datetime.datetime.fromisoformat(data['scheduled_at'].replace('Z', '+00:00'))
            except:
                popup.scheduled_at = None
        
        db.session.commit()
        log_activity(current_user.id, f'Updated popup: {popup.title}', request.remote_addr)
        return jsonify({'msg': 'Popup updated successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

@app.route('/api/popups/<int:popup_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_popup(current_user, popup_id):
    try:
        popup = Popup.query.get(popup_id)
        if not popup:
            return jsonify({'msg': 'Popup not found'}), 404
        db.session.delete(popup)
        db.session.commit()
        log_activity(current_user.id, f'Deleted popup: {popup.title}', request.remote_addr)
        return jsonify({'msg': 'Popup deleted successfully'})
    except Exception as e:
        return jsonify({'msg': f'Error: {str(e)}'}), 500

# ========== ফ্রন্টেন্ড সার্ভ ==========
@app.route('/admin')
def serve_admin():
    return send_file('admin.html')
# ========== সার্ভার চালু ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            hashed = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            new_admin = User(username='admin', password=hashed.decode('utf-8'), role='admin')
            db.session.add(new_admin)
            db.session.commit()
            print('✅ Default Admin: admin / admin123')
    print('🚀 SpeedX v4.0 (Dashboard + Popups) running on http://0.0.0.0:5000')
    app.run(host='0.0.0.0', port=5000, debug=True)
