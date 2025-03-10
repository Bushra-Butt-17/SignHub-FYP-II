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
from datetime import datetime
from waitress import serve
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
# Define the collections
pending_gestures_collection = db["pending_gestures"]
approved_gestures_collection = db["approved_gestures"]
rejected_gestures_collection = db["rejected_gestures"]

# Define the editors collection
editors_collection = db["editors"]
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

from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first!", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/stream_video/<video_id>')
def stream_video(video_id):
    try:
        video_file = fs.get(ObjectId(video_id))
        # Explicitly set the MIME type to 'video/mp4'
        return send_file(BytesIO(video_file.read()), mimetype='video/mp4')
    except Exception as e:
        print(f"Error streaming video: {e}")
        return "Video not found", 404
    




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
        if file_data:
            content_type = file_data.metadata["contentType"] if file_data.metadata else "application/octet-stream"
            return send_file(BytesIO(file_data.read()), mimetype=content_type)
        else:
            return "Profile picture not found", 404

    except Exception as e:
        print(f"Error retrieving profile picture: {e}")  # Debug log
        return send_file("static/uploads/default.png", mimetype="image/png")
    


    
@app.route('/logout')
def logout():
    session.clear()  # Clears entire session
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))

from flask import url_for
import traceback



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = session['user_id']
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))

    # Debugging: Print user data
    print(f"User Data: {user}")
    print(f"Username: {user.get('username')}")

    if request.method == "POST":
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
                print(f"File received: {file.filename}")  # Debug log

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
                result = users_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {"profile_pic_id": file_id}}
                )
                print(f"User profile update result: {result.modified_count} document(s) modified")  # Debug log

                flash("Profile picture updated successfully!", "success")
            else:
                flash("No file selected!", "danger")
        else:
            flash("No file uploaded!", "danger")

    # Fetch gestures from all three collections
    pending_gestures = list(pending_gestures_collection.find({"user_id": user_id}))
    approved_gestures = list(approved_gestures_collection.find({"user_id": user_id}))
    rejected_gestures = list(rejected_gestures_collection.find({"user_id": user_id}))

    # Calculate statistics
    total_submissions = len(pending_gestures) + len(approved_gestures) + len(rejected_gestures)
    approved_count = len(approved_gestures)
    pending_count = len(pending_gestures)
    rejected_count = len(rejected_gestures)

    # Calculate average rating (if applicable)
    avg_rating = 0  # You can update this logic if ratings are stored in the gestures

    # Fetch progress (if available)
    progress = user.get("progress", 50)

    # Fetch video details (e.g., video URLs from GridFS)
    def add_video_url(gestures):
        for gesture in gestures:
            if "video_file_id" in gesture:
                try:
                    video_file = fs.get(ObjectId(gesture["video_file_id"]))
                    gesture["video_url"] = url_for('stream_video', video_id=gesture["video_file_id"], _external=True)
                    print(f"Video URL for {gesture['name']}: {gesture['video_url']}")  # Debug log
                except Exception as e:
                    print(f"Error fetching video file: {e}")
                    gesture["video_url"] = None
        return gestures

    pending_gestures = add_video_url(pending_gestures)
    approved_gestures = add_video_url(approved_gestures)
    rejected_gestures = add_video_url(rejected_gestures)

    return render_template('dashboard.html', 
        user=user, progress=progress, 
        total_submissions=total_submissions, approved_count=approved_count, 
        pending_count=pending_count, rejected_count=rejected_count, avg_rating=round(avg_rating, 1),
        pending_gestures=pending_gestures,
        approved_gestures=approved_gestures,
        rejected_gestures=rejected_gestures
    )







from bson import ObjectId
import traceback

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    try:
        if 'user_id' not in session:
            print("User not logged in")  # Debug log
            return jsonify({"error": "User not logged in"}), 401

        user_id = session['user_id']
        print(f"Session user_id: {user_id}")  # Debug log
        print(f"Session user_id type: {type(user_id)}")  # Debug log

        # Fetch user from the database
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        print(f"User from DB: {user}")  # Debug log

        if not user:
            print("User not found in database")  # Debug log
            return jsonify({"error": "User not found"}), 404

        # Generate the profile picture URL dynamically
        profile_pic_url = url_for('profile_pic', user_id=user_id, _external=True)

        # Fetch user videos
        # Query user_id as a string (since it's stored as a string in pending_gestures)
        pending_videos = list(pending_gestures_collection.find({"user_id": user_id}))
        approved_videos = list(approved_gestures_collection.find({"user_id": user_id}))
        rejected_videos = list(rejected_gestures_collection.find({"user_id": user_id}))

        # Debug logs for video queries
        print(f"Pending Videos: {pending_videos}")  # Debug log
        print(f"Approved Videos: {approved_videos}")  # Debug log
        print(f"Rejected Videos: {rejected_videos}")  # Debug log

        approved_count = len(approved_videos)
        pending_count = len(pending_videos)
        rejected_count = len(rejected_videos)
        total_submissions = approved_count + pending_count + rejected_count
        avg_rating = 0  # Add logic if ratings are available

        # Convert ObjectId fields to strings for JSON serialization
        for video in pending_videos + approved_videos + rejected_videos:
            video['_id'] = str(video['_id'])
            video['video_file_id'] = str(video['video_file_id'])

        # Debug log the data being returned
        print(f"User: {user}")
        print(f"Profile Picture URL: {profile_pic_url}")
        print(f"Total Submissions: {total_submissions}")
        print(f"Approved Count: {approved_count}")
        print(f"Pending Count: {pending_count}")
        print(f"Rejected Count: {rejected_count}")
        print(f"Average Rating: {avg_rating}")

        return jsonify({
            "user": {
                "name": user.get("username", "Unknown User"),
                "profile_pic": profile_pic_url,
            },
            "total_submissions": total_submissions,
            "approved_count": approved_count,
            "pending_count": pending_count,
            "rejected_count": rejected_count,
            "avg_rating": avg_rating,
            "pending_videos": pending_videos,
            "approved_videos": approved_videos,
            "rejected_videos": rejected_videos,
        })

    except Exception as e:
        print(f"🔴 API Error: {traceback.format_exc()}")  # Debug log
        return jsonify({"error": "Internal Server Error"}), 500


@app.route('/add_gesture', methods=['GET', 'POST'])
def add_gesture():
    user_id = session.get('user_id')  # Retrieve user ID from the session
    if not user_id:  # If no user is logged in, redirect to login
        flash("Please log in to add a gesture.", "danger")
        return redirect(url_for('login'))

    # Ensure the pending_gestures collection exists
    if "pending_gestures" not in db.list_collection_names():
        db.create_collection("pending_gestures")

    # Create indexes for the pending_gestures collection
    pending_gestures_collection = db["pending_gestures"]
    pending_gestures_collection.create_index([("user_id", 1)])
    pending_gestures_collection.create_index([("status", 1)])
    pending_gestures_collection.create_index([("created_at", -1)])

    if request.method == 'POST':
        try:
            # Extract form data
            gesture_name = request.form.get('name')
            gesture_dialect = request.form.get('dialect')
            gesture_video = request.files.get('video')  # File upload

            # Debugging: Print form data
            print(f"Gesture Name: {gesture_name}")
            print(f"Gesture Dialect: {gesture_dialect}")
            print(f"Video File: {gesture_video.filename if gesture_video else 'No file uploaded'}")

            # Validate form data
            if not gesture_name or not gesture_dialect or not gesture_video:
                flash("All fields are required!", "danger")
                return redirect(url_for('add_gesture'))

            # Store the video in GridFS
            filename = secure_filename(gesture_video.filename)
            video_file_id = fs.put(
                gesture_video,
                filename=filename,
                content_type=gesture_video.content_type  # Ensure the content type is set
            )
            print(f"Video uploaded to GridFS. File ID: {video_file_id}")  # Debug log

            # Create a new gesture document
            new_gesture = {
                "name": gesture_name,
                "dialect": gesture_dialect,
                "video_file_id": video_file_id,
                "status": "pending",  # Set status as "pending"
                "user_id": user_id,  # Associate gesture with the logged-in user
                "created_at": datetime.now()  # Correct usage of datetime.now()
            }

            # Insert the gesture into the database
            pending_gestures_collection.insert_one(new_gesture)

            # Increment the pending_count in the user collection
            users_collection = db["users"]  # Assuming your user collection is named "users"
            users_collection.update_one(
                {"_id": user_id},  # Find the user by their ID
                {"$inc": {"pending_count": 1}}  # Increment the pending_count by 1
            )

            print("Gesture added successfully! It is now pending review.", "success")
            return redirect(url_for('dashboard'))  # Redirect to the contributor dashboard after adding the gesture

        except Exception as e:
            # Debugging: Print error
            print(f"Error adding gesture: {e}")
            flash("An error occurred while adding the gesture. Please try again.", "danger")
            return redirect(url_for('add_gesture'))

    # Render the form for GET requests
    return render_template('add_gesture.html')


    
@app.route('/contributor/profile', methods=['GET', 'POST'])
@login_required  # Use the appropriate login decorator for contributors
def contributor_profile():
    # Get the contributor's ID from the session
    contributor_id = session.get('user_id')

    if not contributor_id:
        flash("You must be logged in to access the profile.", "danger")
        return redirect(url_for('ogin'))

    # Fetch contributor details from MongoDB
    contributor = users_collection.find_one({"_id": ObjectId(contributor_id)})

    if not contributor:
        flash("Profile not found.", "danger")
        return redirect(url_for('contributor_dashboard'))

    if request.method == 'POST':
        # Get updated profile data from form
        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        location = request.form.get("location")
        linkedin = request.form.get("linkedin")
        twitter = request.form.get("twitter")
        instagram = request.form.get("instagram")

        # Handle profile picture upload
        profile_picture = request.files.get("profile_picture")
        profile_picture_id = contributor.get("profile_picture_id")  # Default to existing picture ID

        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture from GridFS if it exists
            if profile_picture_id:
                fs.delete(ObjectId(profile_picture_id))

            # Save the new profile picture to GridFS
            profile_picture_id = fs.put(
                profile_picture,
                filename=secure_filename(profile_picture.filename),
                content_type=profile_picture.content_type  # Set content_type
            )

        # Update contributor profile in MongoDB
        users_collection.update_one(
            {"_id": ObjectId(contributor_id)},
            {"$set": {
                "full_name": full_name,
                "username": username,
                "email": email,
                "phone": phone,
                "location": location,
                "linkedin": linkedin,
                "twitter": twitter,
                "instagram": instagram,
                "profile_picture_id": profile_picture_id
            }}
        )
        flash("Profile updated successfully!", "success")
        return redirect(url_for('contributor_profile'))

    # Fetch the profile picture URL for rendering
    profile_picture_url = None
    if contributor.get("profile_picture_id"):
        profile_picture_file = fs.get(ObjectId(contributor["profile_picture_id"]))
        profile_picture_url = f"/contributor/profile/picture/{contributor['profile_picture_id']}"

    return render_template('contributor_profile.html', contributor=contributor, profile_picture_url=profile_picture_url)

@app.route('/contributor/profile/picture/<file_id>')
def contributor_profile_picture(file_id):
    # Serve the profile picture from GridFS
    file = fs.get(ObjectId(file_id))
    return file.read(), 200, {'Content-Type': file.content_type}


##########################################################################################################


##########################################################################################################


##########################################################################################################


##########################################################################################################


##########################################################################################################


##########################################################################################################

'''
# Editor data
editors = [
    {
        "username": "Bushra Shahbaz",
        "email": "bsdsf21m020@pucit.edu.pk",
        "password": "bushra"  # Plain text password
    },
    {
        "username": "Aliha Hamid",
        "email": "bsdsf21m001@pucit.edu.pk",
        "password": "aliha"  # Plain text password
    }
]

# Hash passwords and insert editors
for editor in editors:
    # Hash the password
    hashed_password = generate_password_hash(editor["password"], method='pbkdf2:sha256')
    
    # Replace the plain text password with the hashed password
    editor["password"] = hashed_password

    # Insert the editor into the collection
    editors_collection.insert_one(editor)

print("Editors added successfully!")
'''




@app.route('/editor')
def editor_landing():
    return render_template('editor_landing.html')



@app.route('/editor/login', methods=['GET', 'POST'])
def editor_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('editor_login'))

        # Find the editor in the editors collection
        editor = editors_collection.find_one({"email": email})

        # Check if the editor exists and the password is correct
        if editor and check_password_hash(editor["password"], password):
            session.permanent = True
            session['editor_id'] = str(editor["_id"])  # Store editor ID in session
            flash("Editor login successful!", "success")
            return redirect(url_for('editor_dashboard'))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for('editor_login'))

    return render_template('editor_login.html')  # Create a new template for editor login






from functools import wraps

def editor_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'editor_id' not in session:
            flash("You need to log in as an editor to access this page!", "warning")
            return redirect(url_for('editor_login'))
        return f(*args, **kwargs)
    return decorated_function





@app.route('/editor/dashboard')
@editor_login_required
def editor_dashboard():
    # Get the editor's ID from the session
    editor_id = session.get('editor_id')

    # Fetch the editor's name
    editor = editors_collection.find_one({"_id": ObjectId(editor_id)})
    editor_name = editor.get("username", "Editor")

    # Fetch gesture statistics
    pending_count = pending_gestures_collection.count_documents({})
    approved_count = approved_gestures_collection.count_documents({"approved_by": editor_id})
    rejected_count = rejected_gestures_collection.count_documents({"rejected_by": editor_id})

    return render_template('editor_dashboard.html',
                          editor_name=editor_name,
                          pending_count=pending_count,
                          approved_count=approved_count,
                          rejected_count=rejected_count)



@app.route('/review_gestures')
@editor_login_required
def review_gestures():
    # Fetch the first pending gesture
    gesture = pending_gestures_collection.find_one()

    if gesture:
        # Add video URL to the gesture
        if "video_file_id" in gesture:
            gesture["video_url"] = url_for('stream_video', video_id=gesture["video_file_id"], _external=True)

        # Fetch the contributor's name from the users collection
        user = users_collection.find_one({"_id": ObjectId(gesture["user_id"])})
        gesture["contributor_name"] = user.get("username", "Unknown User") if user else "Unknown User"

    return render_template('review_gestures.html', gesture=gesture)




@app.route('/submit_review/<gesture_id>', methods=['POST'])
@editor_login_required
def submit_review(gesture_id):
    # Get the editor's ID from the session
    editor_id = session.get('editor_id')
    print(f"Editor ID: {editor_id}")  # Debugging

    # Get form data
    shape = request.form.get('shape')
    location = request.form.get('location')
    orientation = request.form.get('orientation')
    movement = request.form.get('movement')
    scale = request.form.get('scale')
    comments = request.form.get('comments')
    category = request.form.get('category')  # <-- Check if category is received
    decision = request.form.get('decision')

    print(f"Form Data Received: Shape={shape}, Location={location}, Orientation={orientation}, "
          f"Movement={movement}, Scale={scale}, Category={category}, Comments={comments}, Decision={decision}")

    # Fetch the gesture from the pending collection
    gesture = pending_gestures_collection.find_one({"_id": ObjectId(gesture_id)})

    if gesture:
        print(f"Gesture Found: {gesture}")  # Debugging
        
        # Add review data including category
        gesture["review_data"] = {
            "shape": shape,
            "location": location,
            "orientation": orientation,
            "movement": movement,
            "scale": scale,
            "category": category,  # <-- Store category in review_data
            "comments": comments
        }

        print(f"Updated Gesture Data: {gesture}")  # Debugging

        # Move to appropriate collection based on decision
        if decision == "accept":
            gesture["approved_by"] = editor_id
            approved_gestures_collection.insert_one(gesture)
            print("Gesture moved to Approved Collection")  # Debugging
        elif decision == "reject":
            gesture["rejected_by"] = editor_id
            rejected_gestures_collection.insert_one(gesture)
            print("Gesture moved to Rejected Collection")  # Debugging
        elif decision == "pending":
            pending_gestures_collection.update_one({"_id": ObjectId(gesture_id)}, {"$set": gesture})
            print("Gesture updated in Pending Collection")  # Debugging

        # Remove the gesture from the pending collection
        pending_gestures_collection.delete_one({"_id": ObjectId(gesture_id)})
        print("Gesture removed from Pending Collection")  # Debugging

        flash("Review submitted successfully!", "success")
    else:
        print("Gesture not found!")  # Debugging
        flash("Gesture not found!", "danger")

    return redirect(url_for('review_gestures'))









# Allowed file extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS





@app.route('/editor/profile', methods=['GET', 'POST'])
@editor_login_required
def editor_profile():
    # Get the editor's ID from the session
    editor_id = session.get('editor_id')

    if not editor_id:
        flash("You must be logged in to access the profile.", "danger")
        return redirect(url_for('editor_login'))

    # Fetch editor details from MongoDB
    editor = editors_collection.find_one({"_id": ObjectId(editor_id)})

    if not editor:
        flash("Profile not found.", "danger")
        return redirect(url_for('editor_dashboard'))

    if request.method == 'POST':
        # Get updated profile data from form
        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        location = request.form.get("location")
        linkedin = request.form.get("linkedin")
        twitter = request.form.get("twitter")
        instagram = request.form.get("instagram")

        # Handle profile picture upload
        profile_picture = request.files.get("profile_picture")
        profile_picture_id = editor.get("profile_picture_id")  # Default to existing picture ID

        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture from GridFS if it exists
            if profile_picture_id:
                fs.delete(ObjectId(profile_picture_id))

            # Save the new profile picture to GridFS
            profile_picture_id = fs.put(profile_picture, filename=secure_filename(profile_picture.filename))

        # Update editor profile in MongoDB
        editors_collection.update_one(
            {"_id": ObjectId(editor_id)},
            {"$set": {
                "full_name": full_name,
                "username": username,
                "email": email,
                "phone": phone,
                "location": location,
                "linkedin": linkedin,
                "twitter": twitter,
                "instagram": instagram,
                "profile_picture_id": profile_picture_id
            }}
        )
        flash("Profile updated successfully!", "success")
        return redirect(url_for('editor_profile'))

    # Fetch the profile picture URL for rendering
    profile_picture_url = None
    if editor.get("profile_picture_id"):
        profile_picture_file = fs.get(ObjectId(editor["profile_picture_id"]))
        profile_picture_url = f"/editor/profile/picture/{editor['profile_picture_id']}"

    return render_template('editor_profile.html', editor=editor, profile_picture_url=profile_picture_url)

@app.route('/editor/profile/picture/<file_id>')
def editor_profile_picture(file_id):
    # Serve the profile picture from GridFS
    file = fs.get(ObjectId(file_id))
    return file.read(), 200, {'Content-Type': file.content_type}























@app.route('/editor/logout')
def editor_logout():
    session.pop('editor_id', None)  # Remove editor_id from session
    flash("Logged out successfully!", "info")
    return redirect(url_for('editor_login'))












if __name__ == "__main__":
    app.run(debug=True)
