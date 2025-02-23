from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from pymongo.server_api import ServerApi  # Import ServerApi here
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import datetime
import gridfs
from werkzeug.utils import secure_filename
from io import BytesIO
import traceback

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwtsecret")
jwt = JWTManager(app)

# MongoDB Configuration
uri = os.getenv("MONGODB_URI")
if not uri:
    raise ValueError("No MONGODB_URI environment variable set")

# Initialize MongoDB client with ServerApi
client = MongoClient(uri, server_api=ServerApi('1'))
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client["SignHub"]
fs = gridfs.GridFS(db)
users_collection = db["users"]
videos_collection = db['videos']

# Rest of your code remains the same...

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        if users_collection.find_one({"email": email}):
            flash("Email already registered! Please log in.", "danger")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.insert_one({"username": username, "email": email, "password": hashed_password})

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('login'))

        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            session.permanent = True
            session['user_id'] = str(user["_id"])
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first!", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = session['user_id']
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))

    if request.method == "POST":
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                # Delete the old profile picture if it exists
                if "profile_pic_id" in user:
                    try:
                        fs.delete(ObjectId(user["profile_pic_id"]))
                        print(f"Old profile picture deleted. File ID: {user['profile_pic_id']}")  # Debug log
                    except Exception as e:
                        print(f"Error deleting old profile picture: {e}")  # Debug log

                # Save the new profile picture in GridFS
                filename = secure_filename(file.filename)
                file_id = fs.put(file, filename=filename, content_type=file.content_type)
                print(f"New profile picture uploaded. File ID: {file_id}")  # Debug log

                # Update the user's profile_pic_id in the database
                users_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {"profile_pic_id": file_id}}
                )
                print(f"User profile updated with new profile_pic_id: {file_id}")  # Debug log

                flash("Profile picture updated successfully!", "success")
            else:
                flash("No file selected!", "danger")
        else:
            flash("No file uploaded!", "danger")

    videos = list(videos_collection.find({"user_id": user_id}))
    total_submissions = len(videos)
    approved_count = sum(1 for v in videos if v.get("status") == "approved")
    pending_count = sum(1 for v in videos if v.get("status") == "pending")
    rejected_count = sum(1 for v in videos if v.get("status") == "rejected")

    avg_rating = sum(v.get("rating", 0) for v in videos) / total_submissions if total_submissions > 0 else 0
    progress = user.get("progress", 50)

    return render_template('dashboard.html', 
        user=user, progress=progress, 
        total_submissions=total_submissions, approved_count=approved_count, 
        pending_count=pending_count, rejected_count=rejected_count, avg_rating=round(avg_rating, 1),
        videos=videos
    )

@app.route('/profile_pic/<user_id>')
def profile_pic(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        print("User not found. Serving default image.")  # Debug log
        return send_file("static/uploads/default.png", mimetype="image/png")

    if "profile_pic_id" not in user:
        print("Profile picture ID not found in user. Serving default image.")  # Debug log
        return send_file("static/uploads/default.png", mimetype="image/png")

    file_id = user["profile_pic_id"]
    try:
        file_data = fs.get(ObjectId(file_id))
        print(f"Profile picture found! File ID: {file_id}")  # Debug log
        return send_file(BytesIO(file_data.read()), mimetype=file_data.content_type)
    except Exception as e:
        print(f"Error retrieving profile picture: {e}")  # Debug log
        return send_file("static/uploads/default.png", mimetype="image/png")

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401

        user_id = session['user_id']
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"error": "User not found"}), 404

        videos = list(videos_collection.find({"user_id": user_id}))
        total_submissions = len(videos)
        approved_count = sum(1 for v in videos if v.get("status") == "approved")
        pending_count = sum(1 for v in videos if v.get("status") == "pending")
        rejected_count = sum(1 for v in videos if v.get("status") == "rejected")
        avg_rating = sum(v.get("rating", 0) for v in videos) / total_submissions if total_submissions > 0 else 0

        return jsonify({
            "user": {
                "name": user.get("username", "Unknown User"),
                "profile_pic": user.get("profile_pic", "/static/uploads/default.png")
            },
            "total_submissions": total_submissions,
            "approved_count": approved_count,
            "pending_count": pending_count,
            "rejected_count": rejected_count,
            "avg_rating": avg_rating,
            "videos": videos
        })

    except Exception as e:
        print("🔴 API Error:", traceback.format_exc())
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    app.run(debug=True)