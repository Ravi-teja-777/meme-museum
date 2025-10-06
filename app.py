from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from decimal import Decimal
from botocore.exceptions import ClientError
from io import BytesIO
import boto3, uuid, json, re, os

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'change-this-in-production'),
    MAX_CONTENT_LENGTH=16*1024*1024
)

# AWS Setup
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'meme-museum-storage')
LAMBDA_FUNC = os.environ.get('LAMBDA_FUNCTION_NAME', 'meme-auto-categorizer')

# Initialize AWS clients with signature version for presigned URLs
from botocore.client import Config
s3 = boto3.client('s3', region_name=AWS_REGION, config=Config(signature_version='s3v4'))
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

def generate_presigned_url(s3_key, expiration=3600):
    """Generate presigned URL for S3 object"""
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        print(f"Error generating presigned URL: {e}")
        return None

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
    """Log user activity with better error handling"""
    try:
        interaction_key = f"{user_id}#{meme_id}#{action}"
        interactions_table.put_item(Item={
            'interaction_key': interaction_key,
            'interaction_id': str(uuid.uuid4()),
            'user_id': user_id, 
            'username': username,
            'meme_id': meme_id, 
            'action': action,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        print(f"⚠ Activity logging failed: {str(e)}")

def check_user_liked(user_id, meme_id):
    """Check if user already liked a meme"""
    try:
        response = interactions_table.query(
            KeyConditionExpression='interaction_key = :key',
            ExpressionAttributeValues={
                ':key': f"{user_id}#{meme_id}#like"
            },
            Limit=1
        )
        return len(response.get('Items', [])) > 0
    except:
        try:
            response = interactions_table.scan(
                FilterExpression='user_id = :u AND meme_id = :m AND #a = :action',
                ExpressionAttributeNames={'#a': 'action'},
                ExpressionAttributeValues={
                    ':u': user_id,
                    ':m': meme_id,
                    ':action': 'like'
                },
                Limit=1
            )
            return len(response.get('Items', [])) > 0
        except:
            return False

def moderate_content(img_bytes):
    try:
        resp = rekognition.detect_moderation_labels(Image={'Bytes': img_bytes}, MinConfidence=60)
        blocked = ['Explicit Nudity','Violence','Visually Disturbing','Hate Symbols']
        for lbl in resp.get('ModerationLabels', []):
            if lbl['Name'] in blocked and lbl['Confidence'] > 75:
                return False, f"Blocked: {lbl['Name']}"
        return True, "Approved"
    except Exception as e:
        print(f"⚠ Content moderation failed: {str(e)}")
        return True, "Skipped"

def analyze_image(img_bytes):
    labels, text = [], ""
    try:
        l_resp = rekognition.detect_labels(Image={'Bytes': img_bytes}, MaxLabels=10, MinConfidence=70)
        labels = [l['Name'] for l in l_resp.get('Labels', [])]
        t_resp = rekognition.detect_text(Image={'Bytes': img_bytes})
        text = ' '.join([t['DetectedText'] for t in t_resp.get('TextDetections', []) if t['Type']=='LINE' and t['Confidence']>80])
    except Exception as e:
        print(f"⚠ Image analysis failed: {str(e)}")
    return labels, text

def auto_categorize(meme_data):
    try:
        resp = lambda_client.invoke(FunctionName=LAMBDA_FUNC, InvocationType='RequestResponse',
                                    Payload=json.dumps(meme_data))
        return json.loads(resp['Payload'].read()).get('suggested_category', 'Funny')
    except Exception as e:
        print(f"⚠ Auto-categorization failed: {str(e)}")
        return 'Funny'

def check_aws_resources():
    """Check if required AWS resources exist"""
    print("\n"+"="*60)
    print("Checking AWS Resources...")
    print("="*60)
    
    resources_ok = True
    
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
        print(f"✓ S3 bucket '{BUCKET_NAME}' exists")
    except Exception as e:
        print(f"✗ S3 bucket '{BUCKET_NAME}' not found")
        print(f"  Error: {str(e)}")
        resources_ok = False
    
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
    
    try:
        lambda_client.get_function(FunctionName=LAMBDA_FUNC)
        print(f"✓ Lambda function '{LAMBDA_FUNC}' exists")
    except:
        print(f"⚠ Lambda function '{LAMBDA_FUNC}' not found (optional)")
    
    try:
        rekognition.describe_projects(MaxResults=1)
        print(f"✓ AWS Rekognition access confirmed")
    except Exception as e:
        print(f"⚠ AWS Rekognition access issue: {str(e)}")
    
    print("="*60)
    
    if not resources_ok:
        print("\n⚠ WARNING: Some required AWS resources are missing!")
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

# Auth API (keeping existing auth endpoints unchanged)
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

# Meme API - MODIFIED FOR PRESIGNED URLS
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
        
        # Upload to S3 with public-read ACL (optional, depends on bucket policy)
        s3.put_object(
            Bucket=BUCKET_NAME, 
            Key=filename, 
            Body=img_bytes, 
            ContentType=file.content_type,
            Metadata={'meme-id': meme_id, 'uploader': session['username']}
        )
        
        category = request.form.get('category', 'Funny')
        if category == 'Auto':
            category = auto_categorize({'meme_id': meme_id, 'labels': labels, 'text': text, 'title': title})
        
        tags = [t.strip() for t in request.form.get('tags', '').split(',') if t.strip()]
        
        # Store S3 key, NOT the direct URL
        memes_table.put_item(Item={
            'meme_id': meme_id, 
            'title': title, 
            'description': request.form.get('description', '').strip(),
            'category': category, 
            'tags': tags, 
            'labels': labels, 
            'detected_text': text,
            's3_key': filename,
            'uploader_id': session['user_id'], 
            'uploader_username': session['username'],
            'created_at': datetime.now().isoformat(), 
            'likes': 0, 
            'views': 0, 
            'downloads': 0
        })
        
        try:
            users_table.update_item(
                Key={'username': session['username']},
                UpdateExpression='SET memes_uploaded = if_not_exists(memes_uploaded, :zero) + :inc',
                ExpressionAttributeValues={':zero': 0, ':inc': 1}
            )
        except Exception as e:
            print(f"User stats update error: {e}")
        
        try:
            categories_table.update_item(
                Key={'category_name': category},
                UpdateExpression='SET meme_count = if_not_exists(meme_count, :zero) + :inc',
                ExpressionAttributeValues={':zero': 0, ':inc': 1}
            )
        except Exception as e:
            print(f"Category stats update error: {e}")
        
        log_activity(session['user_id'], session['username'], meme_id, 'upload')
        return jsonify({'success': True, 'meme_id': meme_id, 'category': category, 'redirect': url_for('meme_detail', meme_id=meme_id)}), 201
    except Exception as e:
        print(f"Upload error: {str(e)}")
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
        
        for meme in memes:
            meme.setdefault('likes', 0)
            meme.setdefault('views', 0)
            meme.setdefault('downloads', 0)
            # Generate presigned URL for each meme
            if 's3_key' in meme:
                meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        memes.sort(key=lambda x: x.get(sort_by if sort_by in ['likes','views'] else 'created_at', 0), reverse=True)
        
        return jsonify({'success': True, 'count': len(memes), 'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        print(f"Get memes error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>', methods=['GET'])
def api_get_meme(meme_id):
    try:
        resp = memes_table.get_item(Key={'meme_id': meme_id})
        if 'Item' not in resp:
            return jsonify({'error': 'Not found'}), 404
        
        meme = resp['Item']
        
        # Generate presigned URL
        if 's3_key' in meme:
            meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        try:
            memes_table.update_item(
                Key={'meme_id': meme_id}, 
                UpdateExpression='SET #v = if_not_exists(#v, :zero) + :inc',
                ExpressionAttributeNames={'#v': 'views'},
                ExpressionAttributeValues={':zero': 0, ':inc': 1}
            )
            # Update local copy
            meme['views'] = meme.get('views', 0) + 1
        except Exception as view_error:
            print(f"View count update error: {view_error}")
        
        if 'username' in session:
            log_activity(session['user_id'], session['username'], meme_id, 'view')
        
        meme.setdefault('views', 0)
        meme.setdefault('likes', 0)
        meme.setdefault('downloads', 0)
        
        has_liked = False
        if 'username' in session:
            has_liked = check_user_liked(session['user_id'], meme_id)
        
        meme['has_liked'] = has_liked
        
        return jsonify({'success': True, 'meme': json.loads(json.dumps(meme, default=decimal_default))}), 200
    except Exception as e:
        print(f"Error in api_get_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>/like', methods=['POST'])
@login_required
def api_like_meme(meme_id):
    try:
        if check_user_liked(session['user_id'], meme_id):
            return jsonify({'error': 'You already liked this meme', 'already_liked': True}), 400
        
        memes_table.update_item(
            Key={'meme_id': meme_id}, 
            UpdateExpression='SET likes = if_not_exists(likes, :zero) + :inc',
            ExpressionAttributeValues={':zero': 0, ':inc': 1}
        )
        
        log_activity(session['user_id'], session['username'], meme_id, 'like')
        
        return jsonify({'success': True, 'message': 'Meme liked!'}), 200
    except Exception as e:
        print(f"Error in api_like_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/meme/<meme_id>/unlike', methods=['POST'])
@login_required
def api_unlike_meme(meme_id):
    try:
        if not check_user_liked(session['user_id'], meme_id):
            return jsonify({'error': 'You have not liked this meme'}), 400
        
        try:
            memes_table.update_item(
                Key={'meme_id': meme_id},
                UpdateExpression='SET likes = if_not_exists(likes, :zero) - :dec',
                ConditionExpression='likes > :zero',
                ExpressionAttributeValues={':zero': 0, ':dec': 1}
            )
        except:
            pass
        
        try:
            interaction_key = f"{session['user_id']}#{meme_id}#like"
            interactions_table.delete_item(Key={'interaction_key': interaction_key})
        except:
            try:
                response = interactions_table.scan(
                    FilterExpression='user_id = :u AND meme_id = :m AND #a = :action',
                    ExpressionAttributeNames={'#a': 'action'},
                    ExpressionAttributeValues={
                        ':u': session['user_id'],
                        ':m': meme_id,
                        ':action': 'like'
                    },
                    Limit=1
                )
                if response.get('Items'):
                    item = response['Items'][0]
                    interactions_table.delete_item(Key={'interaction_key': item['interaction_key']})
            except Exception as e:
                print(f"Failed to remove interaction: {e}")
        
        return jsonify({'success': True, 'message': 'Like removed'}), 200
    except Exception as e:
        print(f"Error in api_unlike_meme: {str(e)}")
        return jsonify({'error': str(e)}), 500

# FIXED DOWNLOAD ENDPOINT
@app.route('/api/meme/<meme_id>/download', methods=['POST', 'GET'])
def api_download_meme(meme_id):
    try:
        # Get meme from database
        resp = memes_table.get_item(Key={'meme_id': meme_id})
        if 'Item' not in resp:
            return jsonify({'error': 'Meme not found'}), 404
        
        meme = resp['Item']
        s3_key = meme.get('s3_key')
        
        if not s3_key:
            return jsonify({'error': 'S3 key not found'}), 404
        
        # Increment download counter
        try:
            memes_table.update_item(
                Key={'meme_id': meme_id}, 
                UpdateExpression='SET downloads = if_not_exists(downloads, :zero) + :inc',
                ExpressionAttributeValues={':zero': 0, ':inc': 1}
            )
        except Exception as e:
            print(f"Download count update error: {e}")
        
        # Log activity
        if 'username' in session:
            log_activity(session['user_id'], session['username'], meme_id, 'download')
        
        # Option 1: Return presigned URL (recommended - less server load)
        download_url = generate_presigned_url(s3_key, expiration=300)  # 5 minutes
        if not download_url:
            return jsonify({'error': 'Failed to generate download URL'}), 500
        
        return jsonify({
            'success': True, 
            'download_url': download_url,
            'filename': meme.get('title', 'meme') + '.jpg'
        }), 200
        
        # Option 2: Stream file directly (uncomment if you prefer this method)
        # try:
        #     obj = s3.get_object(Bucket=BUCKET_NAME, Key=s3_key)
        #     file_stream = BytesIO(obj['Body'].read())
        #     filename = f"{meme.get('title', 'meme')}_{meme_id}.{s3_key.split('.')[-1]}"
        #     
        #     return send_file(
        #         file_stream,
        #         mimetype=obj['ContentType'],
        #         as_attachment=True,
        #         download_name=filename
        #     )
        # except ClientError as e:
        #     print(f"S3 download error: {e}")
        #     return jsonify({'error': 'Failed to download from S3'}), 500
        
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
        
        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=meme['s3_key'])
        except Exception as s3_error:
            print(f"S3 deletion error: {s3_error}")
        
        memes_table.delete_item(Key={'meme_id': meme_id})
        
        try:
            users_table.update_item(
                Key={'username': session['username']}, 
                UpdateExpression='SET memes_uploaded = if_not_exists(memes_uploaded, :zero) - :dec',
                ConditionExpression='memes_uploaded > :zero',
                ExpressionAttributeValues={':zero': 0, ':dec': 1}
            )
        except Exception as user_error:
            print(f"User stats update error: {user_error}")
        
        try:
            categories_table.update_item(
                Key={'category_name': meme['category']}, 
                UpdateExpression='SET meme_count = if_not_exists(meme_count, :zero) - :dec',
                ConditionExpression='meme_count > :zero',
                ExpressionAttributeValues={':zero': 0, ':dec': 1}
            )
        except Exception as cat_error:
            print(f"Category stats update error: {cat_error}")
        
        log_activity(session['user_id'], session['username'], meme_id, 'delete')
        return jsonify({'success': True, 'message': 'Meme deleted successfully'}), 200
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
        matches = []
        for m in resp.get('Items', []):
            if q in m.get('title','').lower() or \
               q in m.get('description','').lower() or \
               q in ' '.join(m.get('tags',[])).lower() or \
               q in m.get('detected_text','').lower():
                # Generate presigned URL
                if 's3_key' in m:
                    m['s3_url'] = generate_presigned_url(m['s3_key'])
                matches.append(m)
        
        return jsonify({'success': True, 'query': q, 'count': len(matches), 
                       'memes': json.loads(json.dumps(matches, default=decimal_default))}), 200
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trending', methods=['GET'])
def api_trending_memes():
    try:
        limit = int(request.args.get('limit', 20))
        resp = memes_table.scan(Limit=100)
        memes = resp.get('Items', [])
        
        for meme in memes:
            meme.setdefault('likes', 0)
            meme.setdefault('views', 0)
            meme.setdefault('downloads', 0)
            # Generate presigned URL
            if 's3_key' in meme:
                meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        memes.sort(key=lambda x: x.get('likes', 0) + (x.get('views', 0) / 10), reverse=True)
        
        return jsonify({'success': True, 'count': len(memes[:limit]), 
                       'memes': json.loads(json.dumps(memes[:limit], default=decimal_default))}), 200
    except Exception as e:
        print(f"Trending error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# User Dashboard
@app.route('/api/user/memes', methods=['GET'])
@login_required
def api_user_memes():
    try:
        resp = memes_table.scan(FilterExpression='uploader_id = :u', ExpressionAttributeValues={':u': session['user_id']})
        memes = resp.get('Items', [])
        
        # Generate presigned URLs
        for meme in memes:
            if 's3_key' in meme:
                meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        memes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return jsonify({'success': True, 'count': len(memes), 'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        print(f"User memes error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/stats', methods=['GET'])
@login_required
def api_user_stats():
    try:
        user = users_table.get_item(Key={'username': session['username']}).get('Item', {})
        memes = memes_table.scan(FilterExpression='uploader_id = :u', ExpressionAttributeValues={':u': session['user_id']}).get('Items', [])
        
        stats = {
            'username': user.get('username'), 
            'email': user.get('email'), 
            'bio': user.get('bio', ''),
            'memes_uploaded': len(memes), 
            'total_likes': sum(m.get('likes', 0) for m in memes),
            'total_views': sum(m.get('views', 0) for m in memes), 
            'total_downloads': sum(m.get('downloads', 0) for m in memes),
            'member_since': user.get('created_at'),
            'recent_activity': []
        }
        
        try:
            activity = interactions_table.scan(
                FilterExpression='user_id = :u', 
                ExpressionAttributeValues={':u': session['user_id']}, 
                Limit=10
            ).get('Items', [])
            activity.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            stats['recent_activity'] = activity[:5]
        except Exception as e:
            print(f"Recent activity fetch error: {e}")
        
        return jsonify({'success': True, 'stats': json.loads(json.dumps(stats, default=decimal_default))}), 200
    except Exception as e:
        print(f"User stats error: {str(e)}")
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
            vals[':e'] = data['email'].strip().lower()
        
        if 'bio' in data:
            expr.append('bio = :b')
            vals[':b'] = data['bio'].strip()
        
        if not expr:
            return jsonify({'error': 'No fields to update'}), 400
        
        users_table.update_item(
            Key={'username': session['username']}, 
            UpdateExpression='SET ' + ', '.join(expr),
            ExpressionAttributeValues=vals
        )
        
        if 'email' in data:
            session['email'] = data['email'].strip().lower()
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'}), 200
    except Exception as e:
        print(f"Profile update error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Categories
@app.route('/api/categories', methods=['GET'])
def api_get_categories():
    try:
        resp = categories_table.scan()
        cats = resp.get('Items', [])
        
        for cat in cats:
            cat.setdefault('meme_count', 0)
        
        cats.sort(key=lambda x: x.get('meme_count', 0), reverse=True)
        return jsonify({'success': True, 'count': len(cats), 'categories': json.loads(json.dumps(cats, default=decimal_default))}), 200
    except Exception as e:
        print(f"Categories error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/<category_name>/memes', methods=['GET'])
def api_get_category_memes(category_name):
    try:
        limit = int(request.args.get('limit', 50))
        resp = memes_table.scan(FilterExpression='category = :c', ExpressionAttributeValues={':c': category_name}, Limit=limit)
        memes = resp.get('Items', [])
        
        # Generate presigned URLs
        for meme in memes:
            if 's3_key' in meme:
                meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        memes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return jsonify({'success': True, 'category': category_name, 'count': len(memes), 
                       'memes': json.loads(json.dumps(memes, default=decimal_default))}), 200
    except Exception as e:
        print(f"Category memes error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Analytics
@app.route('/api/analytics/overview', methods=['GET'])
def api_analytics_overview():
    try:
        memes = memes_table.scan().get('Items', [])
        users_count = users_table.scan(Select='COUNT')['Count']
        
        for m in memes:
            m.setdefault('likes', 0)
            m.setdefault('views', 0)
            m.setdefault('downloads', 0)
        
        cat_dist = {}
        for m in memes:
            cat = m.get('category', 'Unknown')
            cat_dist[cat] = cat_dist.get(cat, 0) + 1
        
        top_memes = sorted(memes, key=lambda x: x.get('likes', 0), reverse=True)[:5]
        # Generate presigned URLs for top memes
        for meme in top_memes:
            if 's3_key' in meme:
                meme['s3_url'] = generate_presigned_url(meme['s3_key'])
        
        analytics = {
            'total_memes': len(memes), 
            'total_users': users_count,
            'total_likes': sum(m.get('likes', 0) for m in memes),
            'total_views': sum(m.get('views', 0) for m in memes),
            'total_downloads': sum(m.get('downloads', 0) for m in memes),
            'top_memes': top_memes,
            'category_distribution': cat_dist, 
            'generated_at': datetime.now().isoformat()
        }
        return jsonify({'success': True, 'analytics': json.loads(json.dumps(analytics, default=decimal_default))}), 200
    except Exception as e:
        print(f"Analytics error: {str(e)}")
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
        print(f"Rekognition test error: {str(e)}")
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
    """Health check endpoint for monitoring"""
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
        memes_table.load()
        users_table.load()
        
        return jsonify({
            'status': 'healthy', 
            'timestamp': datetime.now().isoformat(),
            'services': {
                's3': 'ok',
                'dynamodb': 'ok'
            }
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    resources_ok = check_aws_resources()
    
    if resources_ok:
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
