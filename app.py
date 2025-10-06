from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from decimal import Decimal
import boto3, uuid, json, re, os

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'change-this-in-production'),
    MAX_CONTENT_LENGTH=16*1024*1024
)

# AWS Setup - Uses IAM role credentials automatically (no hardcoded keys needed!)
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'meme-museum-storage')
LAMBDA_FUNC = os.environ.get('LAMBDA_FUNCTION_NAME', 'meme-auto-categorizer')

# Initialize AWS clients - They automatically use IAM role credentials from EC2
# No access keys or secret keys needed!
s3 = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
rekognition = boto3.client('rekognition', region_name=AWS_REGION)
lambda_client = boto3.client('lambda', region_name=AWS_REGION)

# DynamoDB Tables
MEMES_TABLE = os.environ.get('DYNAMODB_MEMES_TABLE', 'meme-museum-memes')
USERS_TABLE = os.environ.get('DYNAMODB_USERS_TABLE', 'meme-museum-users')
INTERACTIONS_TABLE = os.environ.get('DYNAMODB_INTERACTIONS_TABLE', 'meme-museum-interactions')
CATEGORIES_TABLE = os.environ.get('DYNAMODB_CATEGORIES_TABLE', 'meme-museum-categories')

memes_table = dynamodb.Table(MEMES_TABLE)
users_table = dynamodb.Table(USERS_TABLE)
interactions_table = dynamodb.Table(INTERACTIONS_TABLE)
categories_table = dynamodb.Table(CATEGORIES_TABLE)

ALLOWED_EXT = {'png','jpg','jpeg','gif','webp'}
CATEGORIES = ['Funny','Wholesome','Dank','Relatable','Cringe','Cursed','Trending','Classic','Animals','Tech']

# Helper Functions
allowed_file = lambda f: '.' in f and f.rsplit('.',1)[1].lower() in ALLOWED_EXT
decimal_default = lambda obj: float(obj) if isinstance(obj, Decimal) else TypeError

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    return True, "Valid"

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrap

def log_activity(user_id, username, meme_id, action):
    try:
        interactions_table.put_item(Item={
            'interaction_id': str(uuid.uuid4()),
            'user_id': user_id, 'username': username,
            'meme_id': meme_id, 'action': action,
            'timestamp': datetime.now().isoformat()
        })
    except: pass

def moderate_content(img_bytes):
    try:
        resp = rekognition.detect_moderation_labels(Image={'Bytes': img_bytes}, MinConfidence=60)
        blocked = ['Explicit Nudity','Violence','Visually Disturbing','Hate Symbols']
        for lbl in resp.get('ModerationLabels', []):
            if lbl['Name'] in blocked and lbl['Confidence'] > 75:
                return False, f"Blocked: {lbl['Name']}"
        return True, "Approved"
    except:
        return True, "Skipped"

def analyze_image(img_bytes):
    labels, text = [], ""
    try:
        l_resp = rekognition.detect_labels(Image={'Bytes': img_bytes}, MaxLabels=10, MinConfidence=70)
        labels = [l['Name'] for l in l_resp.get('Labels', [])]
        t_resp = rekognition.detect_text(Image={'Bytes': img_bytes})
        text = ' '.join([t['DetectedText'] for t in t_resp.get('TextDetections', []) if t['Type']=='LINE' and t['Confidence']>80])
    except: pass
    return labels, text

def auto_categorize(meme_data):
    try:
        resp = lambda_client.invoke(FunctionName=LAMBDA_FUNC, InvocationType='RequestResponse',
                                    Payload=json.dumps(meme_data))
        return json.loads(resp['Payload'].read()).get('suggested_category', 'Funny')
    except:
        return 'Funny'

def check_aws_resources():
    """Check if required AWS resources exist"""
    print("\n"+"="*60)
    print("Checking AWS Resources...")
    print("="*60)
    
    resources_ok = True
    
    # Check S3 bucket
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
        print(f"✓ S3 bucket '{BUCKET_NAME}' exists")
    except Exception as e:
        print(f"✗ S3 bucket '{BUCKET_NAME}' not found")
        print(f"  Error: {str(e)}")
        resources_ok = False
    
    # Check DynamoDB tables
    tables_to_check = {
        MEMES_TABLE: 'Memes table',
        USERS_TABLE: 'Users table',
        INTERACTIONS_TABLE: 'Interactions table',
        CATEGORIES_TABLE: 'Categories table'
    }
    
    for table_name, description in tables_to_check.items():
        try:
            table = dynamodb.Table(table_name)
            table.load()
            print(f"✓ DynamoDB table '{table_name}' exists")
        except Exception as e:
            print(f"✗ DynamoDB table '{table_name}' not found")
            print(f"  Error: {str(e)}")
            resources_ok = False
    
    # Check Lambda function (optional)
    try:
        lambda_client.get_function(FunctionName=LAMBDA_FUNC)
        print(f"✓ Lambda function '{LAMBDA_FUNC}' exists")
    except:
        print(f"⚠ Lambda function '{LAMBDA_FUNC}' not found (optional)")
        print(f"  Auto-categorization will use fallback")
    
    # Check Rekognition (just test access)
    try:
        rekognition.describe_projects(MaxResults=1)
        print(f"✓ AWS Rekognition access confirmed")
    except Exception as e:
        print(f"⚠ AWS Rekognition access issue")
        print(f"  Error: {str(e)}")
    
    print("="*60)
    
    if not resources_ok:
        print("\n⚠ WARNING: Some required AWS resources are missing!")
        print("Please ensure:")
        print("\n1. EC2 instance has an IAM role attached")
        print("2. IAM role has required permissions (S3, DynamoDB, Rekognition, Lambda)")
        print("3. All AWS resources are created in the correct region")
        print("="*60 + "\n")
    else:
        print("\n✓ All required AWS resources are available!")
        print("="*60 + "\n")
    
    return resources_ok

def initialize_categories():
    """Initialize default categories in database"""
    try:
        print("Initializing categories...")
        for cat in CATEGORIES:
            try:
                categories_table.put_item(
                    Item={
                        'category_name': cat,
                        'meme_count': 0,
                        'created_at': datetime.now().isoformat()
                    },
                    ConditionExpression='attribute_not_exists(category_name)'
                )
                print(f"  ✓ Added category: {cat}")
            except:
                pass
        print("✓ Categories initialized\n")
    except Exception as e:
        print(f"✗ Error initializing categories: {e}\n")

# HTML Routes
@app.route('/') 
def home(): return render_template('home.html')

@app.route('/gallery') 
def gallery(): return render_template('gallery.html', categories=CATEGORIES)

@app.route('/upload') 
@login_required
def upload_page(): return render_template('upload.html', categories=CATEGORIES)

@app.route('/meme/<meme_id>') 
def meme_detail(meme_id): return render_template('meme_detail.html', meme_id=meme_id)

@app.route('/category/<category_name>') 
def category_page(category_name): return render_template('category.html', category=category_name)

@app.route('/login') 
def login_page(): 
    return redirect(url_for('dashboard')) if 'username' in session else render_template('login.html')

@app.route('/register') 
def register_page(): 
    return redirect(url_for('dashboard')) if 'username' in session else render_template('register.html')

@app.route('/dashboard') 
@login_required
def dashboard(): return render_template('dashboard.html', username=session['username'])

@app.route('/profile') 
@login_required
def profile(): return render_template('profile.html', username=session['username'])

@app.route('/search') 
def search_page(): return render_template('search.html')

@app.route('/trending') 
def trending_page(): return render_template('trending.html')

# Auth API
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        password = data['password']
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if not re.match(r'^[a-z0-9_]+$', username):
            return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        is_valid, msg = validate_password(password)
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        existing_user = users_table.get_item(Key={'username': username})
        if 'Item' in existing_user:
            return jsonify({'error': 'Username already exists'}), 400
        
        try:
            email_check = users_table.scan(
                FilterExpression='email = :e',
                ExpressionAttributeValues={':e': email}
            )
            if email_check.get('Items'):
                return jsonify({'error': 'Email already registered'}), 400
        except:
            pass
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        users_table.put_item(Item={
            'username': username,
            'user_id': str(uuid.uuid4()),
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'memes_uploaded': 0,
            'total_likes': 0,
            'bio': data.get('bio', '').strip()
        })
        
        return jsonify({
            'success': True,
            'message': 'Registration successful! Please login.',
            'redirect': url_for('login_page')
        }), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip().lower()
        password = data['password']
        
        resp = users_table.get_item(Key={'username': username})
        if 'Item' not in resp:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        user = resp['Item']
        
        if 'password_hash' not in user:
            return jsonify({'error': 'Account needs password reset. Please contact support.'}), 401
        
        if not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        session.update({
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email']
        })
        
        log_activity(user['user_id'], user['username'], 'N/A', 'login')
        
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'username': user['username'],
            'redirect': url_for('dashboard')
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@app.route('/api/logout', methods=['POST','GET'])
def api_logout():
    if 'username' in session:
        log_activity(session.get('user_id', 'N/A'), session.get('username', 'unknown'), 'N/A', 'logout')
    session.clear()
    if request.method == 'GET':
        flash('Logged out successfully', 'success')
        return redirect(url_for('home'))
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    try:
        data = request.get_json()
        
        if not data or 'current_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        user = users_table.get_item(Key={'username': session['username']}).get('Item')
        if not user or 'password_hash' not in user:
            return jsonify({'error': 'User not found'}), 404
        
        if not check_password_hash(user['password_hash'], data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        is_valid, msg = validate_password(data['new_password'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        new_password_hash = generate_password_hash(data['new_password'], method='pbkdf2:sha256')
        users_table.update_item(
            Key={'username': session['username']},
            UpdateExpression='SET password_hash = :p',
            ExpressionAttributeValues={':p': new_password_hash}
        )
        
        log_activity(session['user_id'], session['username'], 'N/A', 'password_change')
        
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        print(f"Password change error: {str(e)}")
        return jsonify({'error': 'Failed to change password'}), 500

# Meme API
@app.route('/api/upload-meme', methods=['POST'])
@login_required
def api_upload_meme():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image'}), 400
        
        file = request.files['image']
        title = request.form.get('title', '').strip()
        if not title or file.filename == '' or not allowed_file(file.filename):
            return jsonify({'error': 'Invalid input'}), 400
        
        img_bytes = file.read()
        approved, msg = moderate_content(img_bytes)
        if not approved:
            return jsonify({'error': msg}), 400
        
        labels, text = analyze_image(img_bytes)
        meme_id = str(uuid.uuid4())
        filename = f"memes/{session['user_id']}/{meme_id}/{secure_filename(file.filename)}"
        
        s3.put_object(Bucket=BUCKET_NAME, Key=filename, Body=img_bytes, ContentType=file.content_type,
                     Metadata={'meme-id': meme_id, 'uploader': session['username']})
        
        category = request.form.get('category', 'Funny')
        if category == 'Auto':
            category = auto_categorize({'meme_id': meme_id, 'labels': labels, 'text': text, 'title': title})
        
        tags = [t.strip() for t in request.form.get('tags', '').split(',') if t.strip()]
        
        memes_table.put_item(Item={
            'meme_id': meme_id, 'title': title, 'description': request.form.get('description', '').strip(),
            'category': category, 'tags': tags, 'labels': labels, 'detected_text': text,
            's3_key': filename, 's3_url': f"https://{BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{filename}",
            'uploader_id': session['user_id'], 'uploader_username': session['username'],
            'created_at': datetime.now().isoformat(), 'likes': 0, 'views': 0, 'downloads': 0
        })
        
        users_table.update_item(Key={'username': session['username']},
                               UpdateExpression='SET memes_uploaded = memes_uploaded + :i',
                               ExpressionAttributeValues={':i': 1})
        categories_table.update_item(Key={'category_name': category},
                                    UpdateExpression='SET meme_count = meme_count + :i',
                                    ExpressionAttributeValues={':i': 1})
        
        log_activity(session['user_id'], session['username'], meme_id, 'upload')
        return jsonify({'success': True, 'meme_id': meme_id, 'category': category, 'redirect': url_for('meme_detail', meme_id=meme_id)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/memes', methods=['GET'])
def api_get_memes():
    try:
        category = request.args.get('category')
        limit = int(request.args.get('limit', 50))
        
        if category and category != 'All':
            resp = memes_table.scan(FilterExpression='category = :c', ExpressionAttributeValues={':c': category}, Limit=limit)
        else:
            resp = memes_table.scan(Limit=limit)
        
        memes = resp.get('Items', [])
        sort_by = request.args.get('sort_by', 'created_at')
        
        # Ensure numeric fields exist for sorting
        for meme in memes:
            if 'likes' not in meme:
                meme['likes'] = 0
            if 'views' not in meme:
                meme['views'] = 0
            if 'downloads' not in meme:
                meme['downloads'] = 0
        
        memes.sort(key=lambda x: x.get(sort_by if sort_by in ['likes','views'] else 'created_at', 0), reverse=True)
        
        return jsonify({'success': True, 'count': len(memes), 'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>', methods=['GET'])
def api_get_meme(meme_id):
    try:
        resp = memes_table.get_item(Key={'meme_id': meme_id})
        if 'Item' not in resp:
            return jsonify({'error': 'Not found'}), 404
        
        # Safely increment views - handle case where attribute doesn't exist
        try:
            memes_table.update_item(
                Key={'meme_id': meme_id}, 
                UpdateExpression='SET #v = if_not_exists(#v, :start) + :inc',
                ExpressionAttributeNames={'#v': 'views'},
                ExpressionAttributeValues={':start': 0, ':inc': 1}
            )
        except Exception as view_error:
            print(f"View count update error: {view_error}")
        
        if 'username' in session:
            log_activity(session['user_id'], session['username'], meme_id, 'view')
        
        # Fetch the updated item
        resp = memes_table.get_item(Key={'meme_id': meme_id})
        meme = resp['Item']
        
        # Ensure numeric fields exist
        if 'views' not in meme:
            meme['views'] = 0
        if 'likes' not in meme:
            meme['likes'] = 0
        if 'downloads' not in meme:
            meme['downloads'] = 0
        
        return jsonify({'success': True, 'meme': json.loads(json.dumps(meme, default=decimal_default))}), 200
    except Exception as e:
        print(f"Error in api_get_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>/like', methods=['POST'])
@login_required
def api_like_meme(meme_id):
    try:
        memes_table.update_item(
            Key={'meme_id': meme_id}, 
            UpdateExpression='SET likes = if_not_exists(likes, :start) + :inc',
            ExpressionAttributeValues={':start': 0, ':inc': 1}
        )
        log_activity(session['user_id'], session['username'], meme_id, 'like')
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Error in api_like_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>/download', methods=['POST'])
def api_download_meme(meme_id):
    try:
        memes_table.update_item(
            Key={'meme_id': meme_id}, 
            UpdateExpression='SET downloads = if_not_exists(downloads, :start) + :inc',
            ExpressionAttributeValues={':start': 0, ':inc': 1}
        )
        if 'username' in session:
            log_activity(session['user_id'], session['username'], meme_id, 'download')
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Error in api_download_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>/delete', methods=['DELETE'])
@login_required
def api_delete_meme(meme_id):
    try:
        resp = memes_table.get_item(Key={'meme_id': meme_id})
        if 'Item' not in resp:
            return jsonify({'error': 'Not found'}), 404
        
        meme = resp['Item']
        if meme['uploader_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete from S3
        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=meme['s3_key'])
        except Exception as s3_error:
            print(f"S3 deletion error: {s3_error}")
        
        # Delete from DynamoDB
        memes_table.delete_item(Key={'meme_id': meme_id})
        
        # Update user stats - safely decrement
        try:
            users_table.update_item(
                Key={'username': session['username']}, 
                UpdateExpression='SET memes_uploaded = if_not_exists(memes_uploaded, :start) - :dec',
                ExpressionAttributeValues={':start': 1, ':dec': 1}
            )
        except Exception as user_error:
            print(f"User stats update error: {user_error}")
        
        # Update category stats - safely decrement
        try:
            categories_table.update_item(
                Key={'category_name': meme['category']}, 
                UpdateExpression='SET meme_count = if_not_exists(meme_count, :start) - :dec',
                ExpressionAttributeValues={':start': 1, ':dec': 1}
            )
        except Exception as cat_error:
            print(f"Category stats update error: {cat_error}")
        
        log_activity(session['user_id'], session['username'], meme_id, 'delete')
        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Error in api_delete_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Search & Filter
@app.route('/api/search', methods=['GET'])
def api_search_memes():
    try:
        q = request.args.get('q', '').strip().lower()
        if not q:
            return jsonify({'error': 'Query required'}), 400
        
        resp = memes_table.scan()
        matches = [m for m in resp.get('Items', []) if q in m.get('title','').lower() or 
                  q in m.get('description','').lower() or q in ' '.join(m.get('tags',[])).lower() or 
                  q in m.get('detected_text','').lower()]
        
        return jsonify({'success': True, 'query': q, 'count': len(matches), 
                       'memes': json.loads(json.dumps(matches, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trending', methods=['GET'])
def api_trending_memes():
    try:
        limit = int(request.args.get('limit', 20))
        resp = memes_table.scan(Limit=100)
        memes = resp.get('Items', [])
        memes.sort(key=lambda x: x.get('likes', 0) + x.get('views', 0), reverse=True)
        return jsonify({'success': True, 'count': len(memes[:limit]), 
                       'memes': json.loads(json.dumps(memes[:limit], default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Dashboard
@app.route('/api/user/memes', methods=['GET'])
@login_required
def api_user_memes():
    try:
        resp = memes_table.scan(FilterExpression='uploader_id = :u', ExpressionAttributeValues={':u': session['user_id']})
        memes = resp.get('Items', [])
        memes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return jsonify({'success': True, 'count': len(memes), 'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/stats', methods=['GET'])
@login_required
def api_user_stats():
    try:
        user = users_table.get_item(Key={'username': session['username']}).get('Item', {})
        memes = memes_table.scan(FilterExpression='uploader_id = :u', ExpressionAttributeValues={':u': session['user_id']}).get('Items', [])
        
        stats = {
            'username': user.get('username'), 'email': user.get('email'), 'bio': user.get('bio', ''),
            'memes_uploaded': len(memes), 'total_likes': sum(m.get('likes', 0) for m in memes),
            'total_views': sum(m.get('views', 0) for m in memes), 'total_downloads': sum(m.get('downloads', 0) for m in memes),
            'member_since': user.get('created_at'),
            'recent_activity': interactions_table.scan(FilterExpression='user_id = :u', 
                                                      ExpressionAttributeValues={':u': session['user_id']}, Limit=5).get('Items', [])
        }
        return jsonify({'success': True, 'stats': json.loads(json.dumps(stats, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['PUT'])
@login_required
def api_update_profile():
    try:
        data = request.get_json()
        expr, vals = [], {}
        if 'email' in data:
            if not validate_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            expr.append('email = :e')
            vals[':e'] = data['email']
        if 'bio' in data:
            expr.append('bio = :b')
            vals[':b'] = data['bio']
        
        if not expr:
            return jsonify({'error': 'No fields to update'}), 400
        
        users_table.update_item(Key={'username': session['username']}, UpdateExpression='SET '+', '.join(expr),
                               ExpressionAttributeValues=vals)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Categories
@app.route('/api/categories', methods=['GET'])
def api_get_categories():
    try:
        resp = categories_table.scan()
        cats = resp.get('Items', [])
        cats.sort(key=lambda x: x.get('meme_count', 0), reverse=True)
        return jsonify({'success': True, 'count': len(cats), 'categories': json.loads(json.dumps(cats, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/<category_name>/memes', methods=['GET'])
def api_get_category_memes(category_name):
    try:
        limit = int(request.args.get('limit', 50))
        resp = memes_table.scan(FilterExpression='category = :c', ExpressionAttributeValues={':c': category_name}, Limit=limit)
        memes = resp.get('Items', [])
        memes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return jsonify({'success': True, 'category': category_name, 'count': len(memes), 
                       'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Analytics
@app.route('/api/analytics/overview', methods=['GET'])
def api_analytics_overview():
    try:
        memes = memes_table.scan().get('Items', [])
        users_count = users_table.scan(Select='COUNT')['Count']
        
        cat_dist = {}
        for m in memes:
            cat = m.get('category', 'Unknown')
            cat_dist[cat] = cat_dist.get(cat, 0) + 1
        
        analytics = {
            'total_memes': len(memes), 'total_users': users_count,
            'total_likes': sum(m.get('likes', 0) for m in memes),
            'total_views': sum(m.get('views', 0) for m in memes),
            'total_downloads': sum(m.get('downloads', 0) for m in memes),
            'top_memes': sorted(memes, key=lambda x: x.get('likes', 0), reverse=True)[:5],
            'category_distribution': cat_dist, 'generated_at': datetime.now().isoformat()
        }
        return jsonify({'success': True, 'analytics': json.loads(json.dumps(analytics, default=decimal_default))}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin/Debug
@app.route('/api/admin/test-rekognition', methods=['POST'])
@login_required
def api_test_rekognition():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image'}), 400
        img = request.files['image'].read()
        
        mod = rekognition.detect_moderation_labels(Image={'Bytes': img}, MinConfidence=60)
        lbl = rekognition.detect_labels(Image={'Bytes': img}, MaxLabels=10, MinConfidence=70)
        txt = rekognition.detect_text(Image={'Bytes': img})
        
        return jsonify({'success': True, 'rekognition_results': {
            'moderation_labels': mod.get('ModerationLabels', []),
            'detected_labels': [l['Name'] for l in lbl.get('Labels', [])],
            'detected_text': [t['DetectedText'] for t in txt.get('TextDetections', []) if t['Type']=='LINE']
        }}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}) if request.path.startswith('/api/') else render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Server error'}) if request.path.startswith('/api/') else render_template('500.html'), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 16MB)'}), 413

@app.route('/health')
def health():
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
        memes_table.load()
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200
    except:
        return jsonify({'status': 'unhealthy'}), 500

if __name__ == '__main__':
    # Check AWS resources instead of creating them
    resources_ok = check_aws_resources()
    
    if resources_ok:
        # Initialize categories if everything is set up
        initialize_categories()
    
    print("\n" + "="*60)
    print("MEME MUSEUM - Starting Server...")
    print("="*60)
    print(f"Server URL: http://localhost:5000")
    print(f"Server URL: http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    if not resources_ok:
        print("⚠ WARNING: Starting with missing AWS resources!")
        print("Some features may not work properly.\n")
    

    app.run(host='0.0.0.0', port=5000, debug=True)
