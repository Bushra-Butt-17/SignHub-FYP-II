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
from flask import Flask, request, session, redirect, url_for, render_template, flash, Response, abort
# Load environment variables

from flask import Flask
from flask_mail import Mail  # Add this import
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
revision_gestures_collection = db["revision_gestures"]
# Define the editors collection
editors_collection = db["editors"]
# MongoDB collection for SiGML Generators
sigml_generators_collection = db["sigml_generators"]
video_generators_collection = db["video_generators"]
# MongoDB collection for SiGML files
sigml_files_collection = db["sigml_files"]
# Rest of your code remains the same...
sigml_required_gestures_collection = db['sigml_required_gestures'] 
sigml_updated_gestures_collection =db['sigml_updated_gestures'] # Add this line
final_collection = db['final_gesture_collection']
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

    # Calculate average rating from approved gestures
    # Calculate average rating from approved gestures
    # Calculate average rating from approved gestures
    avg_rating = 0
    if approved_gestures:  # Check if there are any approved gestures
        total_rating = 0
        valid_gestures = 0  # Counter for gestures with valid review_data and scale

        for gesture in approved_gestures:
            if "review_data" in gesture and "scale" in gesture["review_data"]:
                # Cap scale at 10 to ensure it doesn't exceed the maximum
                scale = min(int(gesture["review_data"]["scale"]), 10)
                print(scale)
                # Convert scale (out of 10) to 5-star rating
                rating = (scale / 10) * 5
                total_rating += rating
                valid_gestures += 1  # Increment valid gestures counter
            else:
                print(f"Missing review_data or scale for gesture: {gesture.get('name', 'Unknown')}")

        # Calculate average rating if there are valid gestures
        if valid_gestures > 0:
            avg_rating = total_rating / valid_gestures
            # Cap the average rating at 5.0 (in case of rounding errors)
            avg_rating = min(avg_rating, 5.0)
        else:
            print("No valid gestures with review_data and scale found.")
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

        # Calculate average rating from approved gestures
        avg_rating = 0
        if approved_videos:
            total_rating = 0
            for video in approved_videos:
                if "review_data" in video and "scale" in video["review_data"]:
                    scale = int(video["review_data"]["scale"])
                    # Convert scale (out of 8) to 5-star rating
                    rating = (scale / 10) * 5
                    total_rating += rating
            avg_rating = total_rating / approved_count

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
            "avg_rating": round(avg_rating, 1),
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
@login_required
def contributor_profile():
    # Get the contributor's ID from the session
    contributor_id = session.get('user_id')

    if not contributor_id:
        flash("You must be logged in to access the profile.", "danger")
        return redirect(url_for('login'))

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

        print(f"[DEBUG] Received profile picture: {profile_picture}")
        if profile_picture and allowed_file(profile_picture.filename):
            print(f"[DEBUG] Valid profile picture received: {profile_picture.filename}")

            try:
                # Delete old profile picture from GridFS if it exists
                if profile_picture_id:
                    print(f"[DEBUG] Deleting old profile picture ID: {profile_picture_id}")
                    fs.delete(ObjectId(profile_picture_id))

                # Save the new profile picture to GridFS
                profile_picture_id = fs.put(
                    profile_picture,
                    filename=secure_filename(profile_picture.filename),
                    content_type=profile_picture.content_type
                )
                print(f"[DEBUG] New profile picture saved with ID: {profile_picture_id}")

            except Exception as e:
                print(f"[ERROR] Failed to update profile picture: {e}")
                flash("Error updating profile picture.", "danger")
        print(f"[DEBUG] Full Name: {full_name}")
        print(f"[DEBUG] Username: {username}")
        print(f"[DEBUG] Email: {email}")
        print(f"[DEBUG] Phone: {phone}")
        print(f"[DEBUG] Location: {location}")
        print(f"[DEBUG] LinkedIn: {linkedin}")
        print(f"[DEBUG] Twitter: {twitter}")
        print(f"[DEBUG] Instagram: {instagram}")
        print(f"[DEBUG] Profile Picture ID: {profile_picture_id}")
        # Update contributor profile in MongoDB
        try:
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
            print(f"[DEBUG] Profile updated successfully with picture ID: {profile_picture_id}")
            flash("Profile updated successfully!", "success")
        except Exception as e:
            print(f"[ERROR] Failed to update profile in MongoDB: {e}")
            flash("Error updating profile.", "danger")

        return redirect(url_for('contributor_profile'))

    # Fetch the profile picture URL for rendering
    profile_picture_url = None
    if contributor.get("profile_picture_id"):
        profile_picture_file = fs.get(ObjectId(contributor["profile_picture_id"]))
        profile_picture_url = f"/contributor/profile/picture/{contributor['profile_picture_id']}"
        print(f"[DEBUG] Profile picture URL generated: {profile_picture_url}")

    return render_template('contributor_profile.html', contributor=contributor, profile_picture_url=profile_picture_url)


@app.route('/contributor/profile/picture/<picture_id>')
def serve_profile_picture(picture_id):
    try:
        # Fetch the image file from GridFS
        image_file = fs.get(ObjectId(picture_id))
        # Return the image with the correct content type
        return Response(image_file.read(), content_type=image_file.content_type)
    except Exception as e:
        print(f"[ERROR] Failed to serve profile picture: {e}")
        # Return a 404 error if the image is not found
        abort(404)




@app.route('/contributor/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    contributor_id = session.get('user_id')
    if not contributor_id:
        flash("You must be logged in to change your password.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Fetch contributor from the database
        contributor = users_collection.find_one({"_id": ObjectId(contributor_id)})

        if not contributor or not check_password_hash(contributor['password'], current_password):
            flash("Incorrect current password.", "danger")
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for('change_password'))

        # Update password securely
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {"_id": ObjectId(contributor_id)},
            {"$set": {"password": hashed_password}}
        )

        flash("Password changed successfully!", "success")
        return redirect(url_for('contributor_profile'))

    return render_template('change_password.html')





from flask import render_template, request, session, redirect, url_for
from datetime import datetime
from bson.objectid import ObjectId

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        return str(value)  # Fallback to string representation if not datetime
    except Exception as e:
        return str(value)


from flask import render_template, request, session, redirect, url_for, jsonify
from datetime import datetime
from bson.objectid import ObjectId

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        return str(value)  # Fallback to string representation if not datetime
    except Exception as e:
        print(f"Error formatting date: {e}")
        return str(value)

@app.route('/contributor_reviews')
@login_required
def contributor_reviews():
    user_id = session.get('user_id')

    # Fetch accepted and rejected reviews
    accepted_reviews = list(approved_gestures_collection.find({"user_id": user_id}))
    rejected_reviews = list(rejected_gestures_collection.find({"user_id": user_id}))

    # Add video URL processing function
    def add_video_url(reviews):
        for review in reviews:
            if "video_file_id" in review:
                try:
                    # Get video file from GridFS
                    video_file = fs.get(ObjectId(review["video_file_id"]))
                    # Generate streaming URL
                    review["video_url"] = url_for(
                        'stream_video', 
                        video_id=review["video_file_id"],
                        _external=True
                    )
                except Exception as e:
                    print(f"Error fetching video for review {review['_id']}: {e}")
                    review["video_url"] = None
        return reviews

    # Process both review lists
    accepted_reviews = add_video_url(accepted_reviews)
    rejected_reviews = add_video_url(rejected_reviews)

    # Combine reviews and sort by creation date
    try:
        all_reviews = sorted(
            accepted_reviews + rejected_reviews, 
            key=lambda x: x['created_at'], 
            reverse=True
        )
    except Exception as e:
        print(f"Error sorting reviews: {e}")
        return jsonify({"error": str(e)}), 500

    # Pagination setup
    page = int(request.args.get('page', 1))
    per_page = 4
    total_reviews = len(all_reviews)
    paginated_reviews = all_reviews[(page - 1) * per_page:page * per_page]
    total_pages = (total_reviews + per_page - 1) // per_page

    return render_template(
        'contributor_reviews.html',
        reviews=paginated_reviews,
        page=page,
        total_pages=total_pages
    )

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS







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

'''# Editor routes


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
    editor_id = session.get('editor_id')
    
    # Get form data
    shape = request.form.get('shape')
    location = request.form.get('location')
    orientation = request.form.get('orientation')
    movement = request.form.get('movement')
    scale = request.form.get('scale')
    comments = request.form.get('comments')
    category = request.form.get('category')
    decision = request.form.get('decision')

    # Fetch the gesture
    gesture = pending_gestures_collection.find_one({"_id": ObjectId(gesture_id)})

    if gesture:
        # Update status based on decision
        if decision == "accept":
            new_status = "approved"
        elif decision == "reject":
            new_status = "rejected"
        else:  # pending
            new_status = "revision"

        # Add review data with updated status
        gesture["review_data"] = {
            "shape": shape,
            "location": location,
            "orientation": orientation,
            "movement": movement,
            "scale": scale,
            "category": category,
            "comments": comments
        }
        gesture["status"] = new_status  # Update the status

        # Move to appropriate collection based on decision
        if decision == "accept":
            # Move to the "sigml_required_gestures" collection for SiGML processing
            gesture["approved_by"] = editor_id
            approved_gestures_collection.insert_one(gesture)
            sigml_required_gestures_collection.insert_one(gesture)
        elif decision == "reject":
            # Move to the "rejected_gestures" collection
            gesture["rejected_by"] = editor_id
            rejected_gestures_collection.insert_one(gesture)
        elif decision == "revision":
            # Move to the "revision_gestures" collection
            gesture["edited_by"] = editor_id
            revision_gestures_collection.insert_one(gesture)

        # Remove from pending collection unless keeping as pending
        if decision != "pending":
            pending_gestures_collection.delete_one({"_id": ObjectId(gesture_id)})

        flash("Review submitted successfully!", "success")
    else:
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









from flask import render_template, request, redirect, url_for, flash
from bson import ObjectId
from datetime import datetime

@app.route('/review-updated-gestures', methods=['GET', 'POST'])
def review_updated_gestures():
    if request.method == 'POST':
        gesture_id = request.form.get('gesture_id')
        decision = request.form.get('decision')
        category = request.form.get('category')
        comment = request.form.get('comment', '')

        gesture = sigml_updated_gestures_collection.find_one({"_id": ObjectId(gesture_id)})
        if not gesture:
            flash("Gesture not found.")
            return redirect(url_for('review_updated_gestures'))

        # Handle acceptance of the gesture
        if decision == 'accept':
            # Update the status of the gesture in the updated collection
            sigml_updated_gestures_collection.update_one(
                {"_id": ObjectId(gesture_id)},
                {"$set": {"status": "finalized", "category": category}}
            )

            # Fetch contributor details
            contributor = users_collection.find_one({"_id": ObjectId(gesture.get("contributor_id"))})
            contributor_name = contributor.get("username", "Unknown") if contributor else "Unknown"

            # Insert finalized gesture into the final collection
            final_collection.insert_one({
                "source_id": gesture["_id"],
                "name": gesture["name"],
                "category": category,
                "contributor_name": contributor_name,
                "gesture_video_id": gesture.get("video_file_id"),
                "avatar_video_id": gesture.get("avatar_video_id"),
                "created_at": datetime.utcnow()
            })

        # Handle revision of the gesture
        elif decision == 'revise':
            sigml_required_gestures_collection.insert_one({
                "original_id": gesture["_id"],
                "name": gesture["name"],
                "category": category,
                "comment": comment,
                "requested_by": "admin",  # Use current_user if applicable
                "created_at": datetime.utcnow()
            })
            # Delete the gesture from the updated collection
            sigml_updated_gestures_collection.delete_one({"_id": ObjectId(gesture_id)})

        return redirect(url_for('review_updated_gestures'))

    # GET one updated gesture
    gesture = sigml_updated_gestures_collection.find_one({"status": "updated"})
    if not gesture:
        return render_template('no_gestures.html')  # Save the above as no_gestures.html

    # Prepare video URLs for the gesture
    gesture_video_url = None
    avatar_video_url = None

    if "video_file_id" in gesture and gesture["video_file_id"]:
        gesture_video_url = url_for('stream_video', video_id=gesture["video_file_id"], _external=True)

    # Only add avatar video URL if avatar_video_id exists
    if "avatar_video_id" in gesture and gesture["avatar_video_id"]:
        avatar_video_url = url_for('stream_video', video_id=gesture["avatar_video_id"], _external=True)

    # Add URLs to the gesture object
    gesture["gesture_video_url"] = gesture_video_url
    gesture["avatar_video_url"] = avatar_video_url if avatar_video_url else None

    # Fetch the contributor's full name
    contributor = users_collection.find_one({"_id": ObjectId(gesture.get("contributor_id"))})
    gesture['contributor_name'] = contributor.get("full_name", "Unknown") if contributor else "Unknown"
    print(gesture)
    # Render the template
    return render_template("review_updated.html", gesture=gesture)





from flask import request, render_template
from bson.objectid import ObjectId

@app.route('/final-review-dashboard')
def final_review_dashboard():
    gestures = list(final_collection.find())
    
    for gesture in gestures:
        contributor = users_collection.find_one({"full_name": gesture.get("contributor_name")})
        gesture["contributor_email"] = contributor.get("email") if contributor else "N/A"
        gesture["created_at_str"] = gesture["created_at"].strftime("%Y-%m-%d %H:%M:%S") if "created_at" in gesture else "N/A"

    return render_template("final_review_dashboard.html", gestures=gestures)



@app.route('/review-final-gesture/<gesture_id>')
def review_single_gesture(gesture_id):
    gesture = final_collection.find_one({"_id": ObjectId(gesture_id)})
    if not gesture:
        flash("Gesture not found.")
        return redirect(url_for('final_review_dashboard'))

    # Prepare video URLs if available
    gesture_video_url = None
    avatar_video_url = None

    if gesture.get("gesture_video_id"):
        gesture_video_url = url_for('stream_video', video_id=str(gesture["gesture_video_id"]), _external=True)

    if gesture.get("avatar_video_id"):
        avatar_video_url = url_for('stream_video', video_id=str(gesture["avatar_video_id"]), _external=True)

    return render_template("review_single_gesture.html", gesture=gesture,
                           gesture_video_url=gesture_video_url,
                           avatar_video_url=avatar_video_url)











































############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################





from datetime import datetime
from werkzeug.security import generate_password_hash
'''
# Insert one initial SiGML Generator record
initial_generator = {
    "username": "Ahsan Salman Yousaf",
    "password": generate_password_hash("ahsan"),
    "email": "bsdsf21m021@pucit.edu.pk",
    "created_at": datetime.now()
}

# Insert the record into the collection
sigml_generators_collection.insert_one(initial_generator)  # Use insert_one for a single record
print("1 initial SiGML Generator record inserted.")

'''


@app.route('/sigml_generator/login', methods=['GET', 'POST'])
def sigml_generator_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('sigml_generator_login'))

        # Find the SiGML Generator in the sigml_generators collection
        generator = sigml_generators_collection.find_one({"email": email})

        # Check if the generator exists and the password is correct
        if generator and check_password_hash(generator["password"], password):
            session.permanent = True
            session['sigml_generator_id'] = str(generator["_id"])  # Store generator ID in session
            flash("Login successful!", "success")
            return redirect(url_for('sigml_generator_dashboard'))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for('sigml_generator_login'))

    return render_template('sigml_generator_login.html')



from functools import wraps

def sigml_generator_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'sigml_generator_id' not in session:
            flash("You need to log in as a SiGML Generator to access this page!", "warning")
            return redirect(url_for('sigml_generator_login'))
        return f(*args, **kwargs)
    return decorated_function





@app.route('/sigml_generator/profile', methods=['GET', 'POST'])
@sigml_generator_login_required
def sigml_generator_profile():
    # Get the SiGML Generator's ID from the session
    generator_id = session.get('sigml_generator_id')

    if not generator_id:
        flash("You must be logged in to access the profile.", "danger")
        return redirect(url_for('sigml_generator_login'))

    # Fetch SiGML Generator details from MongoDB
    generator = sigml_generators_collection.find_one({"_id": ObjectId(generator_id)})

    if not generator:
        flash("Profile not found.", "danger")
        return redirect(url_for('sigml_generator_dashboard'))

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
        profile_picture_id = generator.get("profile_picture_id")  # Default to existing picture ID

        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture from GridFS if it exists
            if profile_picture_id:
                fs.delete(ObjectId(profile_picture_id))

            # Save the new profile picture to GridFS
            profile_picture_id = fs.put(
                profile_picture,
                filename=secure_filename(profile_picture.filename),
                content_type=profile_picture.content_type
            )

        # Update SiGML Generator profile in MongoDB
        sigml_generators_collection.update_one(
            {"_id": ObjectId(generator_id)},
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
        return redirect(url_for('sigml_generator_profile'))

    # Fetch the profile picture URL for rendering
    profile_picture_url = None
    if generator.get("profile_picture_id"):
        profile_picture_file = fs.get(ObjectId(generator["profile_picture_id"]))
        profile_picture_url = f"/sigml_generator/profile/picture/{generator['profile_picture_id']}"

    return render_template('sigml_generator_profile.html', generator=generator, profile_picture_url=profile_picture_url)



@app.route('/sigml_generator/profile/picture/<file_id>')
def sigml_generator_profile_picture(file_id):
    # Serve the profile picture from GridFS
    file = fs.get(ObjectId(file_id))
    return file.read(), 200, {'Content-Type': file.content_type}





@app.route('/sigml_generator/dashboard')
@sigml_generator_login_required
def sigml_generator_dashboard():
    # Get the SiGML Generator's ID from the session
    generator_id = session.get('sigml_generator_id')

    # Fetch the SiGML Generator's details
    generator = sigml_generators_collection.find_one({"_id": ObjectId(generator_id)})
    generator_name = generator.get("username", "SiGML Generator")

    # Fetch gestures requiring SiGML processing
    sigml_required_gestures = list(sigml_required_gestures_collection.find())
    print(f"Fetched {len(sigml_required_gestures)} gestures requiring SiGML processing")  # Debug print

    # Fetch processed SiGML files for the specific SiGML Generator
    processed_gestures_count = sigml_updated_gestures_collection.count_documents({
        "sigml_generated_by": generator_id  # Filter by the current SiGML Generator's ID
    })
    print(f"Fetched {processed_gestures_count} processed gestures for SiGML Generator: {generator_id}")  # Debug print

    # Calculate counts
    total_pending_processing = len(sigml_required_gestures)
    total_processed = processed_gestures_count  # Use the count from sigml_updated_gestures

    # Fetch contributor and editor names for gestures requiring SiGML processing
    for gesture in sigml_required_gestures:
        # Fetch contributor name
        contributor = users_collection.find_one({"_id": ObjectId(gesture["user_id"])})
        gesture["contributor_name"] = contributor.get("username", "Unknown Contributor") if contributor else "Unknown Contributor"

        # Fetch editor name (if applicable)
        if "approved_by" in gesture:
            editor = editors_collection.find_one({"_id": ObjectId(gesture["approved_by"])})
            gesture["editor_name"] = editor.get("username", "Unknown Editor") if editor else "Unknown Editor"
        else:
            gesture["editor_name"] = "Not Yet Approved"

    return render_template('sigml_generator_dashboard.html',
                          generator_name=generator_name,
                          total_pending_processing=total_pending_processing,
                          total_processed=total_processed,
                          sigml_required_gestures=sigml_required_gestures)






from werkzeug.utils import secure_filename

# Add this function to validate video types
def is_valid_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp4', 'avi', 'mov', 'mkv'}

@app.route('/process_gesture/<gesture_id>', methods=['GET', 'POST'])
@sigml_generator_login_required
def process_gesture(gesture_id):
    print(f"Fetching gesture with ID: {gesture_id}")
    gesture = sigml_required_gestures_collection.find_one({"_id": ObjectId(gesture_id)})
    print(f"Gesture found: {gesture}")

    if not gesture:
        flash("Gesture not found!", "danger")
        return redirect(url_for('sigml_generator_dashboard'))

    if request.method == 'POST':
        print("POST request received")
        sigml_file = request.files.get('sigml_file')
        video_file = request.files.get('video_file')  # Gesture video file
        avatar_video_file = request.files.get('avatar_video_file')  # Avatar video file

        print(f"SiGML file received: {sigml_file}")
        print(f"Video file received: {video_file}")
        print(f"Avatar video file received: {avatar_video_file}")

        if sigml_file:
            print(f"File name: {sigml_file.filename}")
            if is_valid_sigml_file(sigml_file.filename):
                print("SiGML file is valid")
                try:
                    # ✅ Save SiGML to GridFS
                    sigml_file_id = fs.put(
                        sigml_file,
                        filename=secure_filename(sigml_file.filename),
                        content_type=sigml_file.content_type
                    )
                    print(f"SiGML file saved to GridFS with ID: {sigml_file_id}")

                    # ✅ Save the gesture video to GridFS (if valid)
                    video_file_id = None
                    if video_file and is_valid_video_file(video_file.filename):
                        video_file_id = fs.put(
                            video_file,
                            filename=secure_filename(video_file.filename),
                            content_type=video_file.content_type
                        )
                        print(f"Gesture video file saved to GridFS with ID: {video_file_id}")
                    else:
                        print("Invalid or no gesture video uploaded")

                    # ✅ Save the avatar video to GridFS (if valid)
                    avatar_video_id = None
                    if avatar_video_file and is_valid_video_file(avatar_video_file.filename):
                        avatar_video_id = fs.put(
                            avatar_video_file,
                            filename=secure_filename(avatar_video_file.filename),
                            content_type=avatar_video_file.content_type
                        )
                        print(f"Avatar video file saved to GridFS with ID: {avatar_video_id}")
                    else:
                        print("Invalid or no avatar video uploaded")

                    sigml_generator_id = session.get('sigml_generator_id')
                    print(f"SiGML Generator ID: {sigml_generator_id}")

                    # ✅ Updated gesture object with both gesture and avatar videos
                    updated_gesture = {
                        "gesture_id": gesture_id,
                        "name": gesture.get("name"),
                        "dialect": gesture.get("dialect"),
                        "video_file_id": gesture.get("video_file_id"),  # Keep existing gesture video
                        "avatar_video_id": avatar_video_id,  # New avatar video ID
                        "category": gesture.get("review_data", {}).get("category"),
                        "contributor_id": gesture.get("user_id"),
                        "editor_id": gesture.get("approved_by"),
                        "sigml_file_id": sigml_file_id,
                        "sigml_generated_by": sigml_generator_id,
                        "created_at": datetime.now(),
                        "status": "updated"
                    }
                    print(f"Updated gesture document: {updated_gesture}")

                    sigml_updated_gestures_collection.insert_one(updated_gesture)
                    print("Gesture inserted into sigml_updated_gestures_collection")

                    sigml_required_gestures_collection.delete_one({"_id": ObjectId(gesture_id)})
                    print("Gesture deleted from sigml_required_gestures collection")

                    flash("SiGML, Gesture Video, and Avatar Video uploaded successfully!", "success")
                    return redirect(url_for('sigml_generator_dashboard'))
                except Exception as e:
                    print(f"Error during processing: {e}")
                    flash("An error occurred while processing the gesture. Please try again.", "danger")
            else:
                print("Invalid SiGML file")
                flash("Invalid file. Please upload a valid SiGML file.", "danger")
        else:
            print("No file uploaded")
            flash("No file uploaded. Please upload a valid SiGML file.", "danger")

    if "video_file_id" in gesture:
        gesture["video_url"] = url_for('stream_video', video_id=gesture["video_file_id"], _external=True)
        print(f"Gesture Video URL: {gesture['video_url']}")

    if "avatar_video_id" in gesture:
        gesture["avatar_video_url"] = url_for('stream_video', video_id=gesture["avatar_video_id"], _external=True)
        print(f"Avatar Video URL: {gesture['avatar_video_url']}")

    return render_template('process_gesture.html', gesture=gesture)



@app.route('/start_generating')
@sigml_generator_login_required
def start_generating():
    # Fetch the next gesture requiring SiGML processing
    next_gesture = sigml_required_gestures_collection.find_one({})

    if next_gesture:
        print(f"Next gesture found: {next_gesture['_id']}")  # Debug: Print the next gesture ID
        return redirect(url_for('process_gesture', gesture_id=next_gesture['_id']))
    else:
        flash("No gestures available for processing!", "info")
        return redirect(url_for('sigml_generator_dashboard'))
    





@app.route('/processed_gestures')
@sigml_generator_login_required
def processed_gestures():
    # Get the SiGML Generator's ID from the session
    generator_id = session.get('sigml_generator_id')

    # Fetch processed gestures for the specific SiGML Generator
    processed_gestures = list(sigml_updated_gestures_collection.find({
        "sigml_generated_by": generator_id  # Filter by the current SiGML Generator's ID
    }))
    print(f"Fetched {len(processed_gestures)} processed gestures for SiGML Generator: {generator_id}")  # Debug print

    # Fetch additional details for each processed gesture
    for gesture in processed_gestures:
        # Fetch contributor name
        contributor = users_collection.find_one({"_id": ObjectId(gesture["contributor_id"])})
        gesture["contributor_name"] = contributor.get("username", "Unknown Contributor") if contributor else "Unknown Contributor"

        # Fetch editor name (if applicable)
        if "editor_id" in gesture:
            editor = editors_collection.find_one({"_id": ObjectId(gesture["editor_id"])})
            gesture["editor_name"] = editor.get("username", "Unknown Editor") if editor else "Unknown Editor"
        else:
            gesture["editor_name"] = "Not Available"

    return render_template('processed_gestures.html', processed_gestures=processed_gestures)





@app.route('/view_gesture/<gesture_id>')
@sigml_generator_login_required
def view_gesture(gesture_id):
    # Fetch the processed gesture
    gesture = sigml_updated_gestures_collection.find_one({"gesture_id": gesture_id})

    if not gesture:
        flash("Gesture not found!", "danger")
        return redirect(url_for('processed_gestures'))

    # Fetch additional details (contributor, editor, etc.)
    contributor = users_collection.find_one({"_id": ObjectId(gesture["contributor_id"])})

    gesture["contributor_name"] = contributor.get("username", "Unknown Contributor") if contributor else "Unknown Contributor"

    if "editor_id" in gesture:
        editor = editors_collection.find_one({"_id": ObjectId(gesture["editor_id"])})

        gesture["editor_name"] = editor.get("username", "Unknown Editor") if editor else "Unknown Editor"
    else:
        gesture["editor_name"] = "Not Available"

    # Fetch video file URL for gesture and avatar videos
    gesture_video_url = None
    avatar_video_url = None

    if "video_file_id" in gesture:
        # Fetch the video URL for the original gesture video
        gesture_video_url = url_for('stream_video', video_id=gesture["video_file_id"], _external=True)
        #print("hi")

    if "avatar_video_id" in gesture:
        # Fetch the video URL for the avatar video
        avatar_video_url = url_for('stream_video', video_id=gesture["avatar_video_id"], _external=True)

    # Add URLs to the gesture object
    gesture["gesture_video_url"] = gesture_video_url
    gesture["avatar_video_url"] = avatar_video_url

    # Fetch and decode the SiGML file
    sigml_text = ""
    if "sigml_file_id" in gesture:
        try:
            sigml_file = fs.get(ObjectId(gesture["sigml_file_id"]))
            sigml_text = sigml_file.read().decode('utf-8')  # Decode the binary content to text
        except Exception as e:
            print(f"Error fetching SiGML file: {e}")
            flash("Failed to load SiGML file.", "danger")

    print(gesture)

    return render_template('view_gesture.html', gesture=gesture, sigml_text=sigml_text)




def is_valid_sigml_file(filename):
    # Check if the file has a valid .sigml extension
    allowed_extensions = {'sigml'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions




@app.route('/stream_sigml/<file_id>')
def stream_sigml(file_id):
    try:
        # Fetch the SiGML file from GridFS
        sigml_file = fs.get(ObjectId(file_id))
        return sigml_file.read(), 200, {'Content-Type': sigml_file.content_type}
    except Exception as e:
        return "SiGML file not found", 404



@app.route('/sigml_generator/logout')
def sigml_generator_logout():
    session.pop('sigml_generator_id', None)  # Remove sigml_generator_id from session
    flash("Logged out successfully!", "info")
    return redirect(url_for('sigml_generator_login'))


######################################################################33333



from flask import Flask, render_template, request, jsonify, send_file
import os
import subprocess
from datetime import datetime


# Directory to store generated SiGML files
SIGML_DIR = "sigml"

# Ensure the SiGML directory exists
os.makedirs(SIGML_DIR, exist_ok=True)

# Generate SiGML file from HamNoSys input
def generate_sigml(word, hamnosys):
    try:
        sigml_path = os.path.join(SIGML_DIR, f"{word}.sigml")
        
        # Call the HamNoSys2SiGML script using subprocess
        command = ["python", "HamNoSys2SiGML.py", hamnosys]
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Error generating SiGML: {result.stderr}")

        # Remove the first line if it starts with "<?xml"
        sigml_content = result.stdout
        if sigml_content.startswith("<?xml"):
            sigml_content = "\n".join(sigml_content.split("\n")[1:])

        # Save the processed output to the SiGML file
        with open(sigml_path, "w", encoding="utf-8") as f:
            f.write(sigml_content)

        return sigml_path, sigml_content
    except Exception as e:
        print(f"Error generating SiGML: {e}")
        return None, str(e)

# Playground Page
@app.route('/hamnosys2sigml', methods=['GET'])
@sigml_generator_login_required
def hamnosys2sigml():
    """
    Renders the HamNoSys2SiGML Tool page where users can input HamNoSys notation and generate SiGML.
    """
    return render_template('hamnosys2sigml.html')

# SiGML Generation API
@app.route('/hamnosys2sigml/generate', methods=['POST'])
@sigml_generator_login_required
def generate_sigml_api():
    """
    Accepts HamNoSys input, generates SiGML, and returns the result for display and download.
    """
    try:
        # Get input from the form
        word = request.form.get("word")
        hamnosys = request.form.get("hamnosys")

        # Validate input
        if not word or not hamnosys:
            return jsonify({"error": "Both word and HamNoSys are required"}), 400

        # Generate SiGML
        sigml_path, sigml_content = generate_sigml(word, hamnosys)
        if not sigml_path:
            return jsonify({"error": "Failed to generate SiGML"}), 500

        # Create a downloadable file with the word's name
        download_filename = f"{word}.sigml"  # Save as wordname.sigml
        download_path = os.path.join(SIGML_DIR, download_filename)

        # Save the SiGML file for download
        with open(download_path, "w", encoding="utf-8") as f:
            f.write(sigml_content)

        # Return the result for display and download
        return jsonify({
            "success": True,
            "word": word,
            "sigml_content": sigml_content,
            "download_url": f"/hamnosys2sigml/download/{download_filename}"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# SiGML File Download API
@app.route('/hamnosys2sigml/download/<filename>', methods=['GET'])
@sigml_generator_login_required
def download_sigml(filename):
    """
    Serves the generated SiGML file for download.
    """
    try:
        download_path = os.path.join(SIGML_DIR, filename)
        return send_file(download_path, as_attachment=True, download_name=filename)  # Set download name
    except Exception as e:
        return jsonify({"error": str(e)}), 404




############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################

############################################################################################################






@app.route("/welcome")
def welcome():
    return render_template("welcome.html")




























from flask import Flask, request, render_template, redirect, url_for
from flask_pymongo import PyMongo
import gridfs
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SelectField
from wtforms.validators import DataRequired
from pymongo import MongoClient
import os


dictionary_collection = db["dictionary"]


# List of categories
categories = [
    ('ABC - One-Handed', 'ABC - One-Handed'),
    ('ABC - Two-Handed', 'ABC - Two-Handed'),
    ('Adjectives', 'Adjectives'),
    ('Adverbs', 'Adverbs'),
    ('Airport', 'Airport'),
    ('Alphabet - Urdu', 'Alphabet - Urdu'),
    ('Appliances', 'Appliances'),
    ('Around The House', 'Around The House'),
    ('Arts', 'Arts'),
    ('Automobile', 'Automobile'),
    ('Banking', 'Banking'),
    ('Bathroom', 'Bathroom'),
    ('Beach', 'Beach'),
    ('Beauty', 'Beauty'),
    ('Bedroom', 'Bedroom'),
    ('Birds', 'Birds'),
    ('Body Anatomy', 'Body Anatomy'),
    ('Brand Names', 'Brand Names'),
    ('Buildings & Places', 'Buildings & Places'),
    ('Burger King', 'Burger King'),
    ('Calendar & Time', 'Calendar & Time'),
    ('Carpentry', 'Carpentry'),
    ('Classroom', 'Classroom'),
    ('Cleaning Products', 'Cleaning Products'),
    ('Clothes & Accessories', 'Clothes & Accessories'),
    ('Colors', 'Colors'),
    ('Computer', 'Computer'),
    ('Construction', 'Construction'),
    ('Countries & Continents', 'Countries & Continents'),
    ('Death & Funerals', 'Death & Funerals'),
    ('Drinks', 'Drinks'),
    ('Education', 'Education'),
    ('Family & Marriage', 'Family & Marriage'),
    ('Famous People', 'Famous People'),
    ('Farming & Agriculture', 'Farming & Agriculture'),
    ('Flowers, Plants & Trees', 'Flowers, Plants & Trees'),
    ('Food - General', 'Food - General'),
    ('Food Dishes', 'Food Dishes'),
    ('Fruits', 'Fruits'),
    ('Geography', 'Geography'),
    ('Government', 'Government'),
    ('Grammar', 'Grammar'),
    ('Health & Medical Care', 'Health & Medical Care'),
    ('Holidays & Celebrations', 'Holidays & Celebrations'),
    ('Hospitality', 'Hospitality'),
    ('Hygiene', 'Hygiene'),
    ('Insects, Spiders & Reptiles', 'Insects, Spiders & Reptiles'),
    ('Islamic Signs', 'Islamic Signs'),
    ('Jewelry', 'Jewelry'),
    ('KFC', 'KFC'),
    ('Kitchen', 'Kitchen'),
    ('Law & Order', 'Law & Order'),
    ('Life Skills Training', 'Life Skills Training'),
    ('Living Room', 'Living Room'),
    ('Mammals', 'Mammals'),
    ('Marine Life', 'Marine Life'),
    ('Mathematics', 'Mathematics'),
    ('Media', 'Media'),
    ('Military', 'Military'),
    ('Music & Dance', 'Music & Dance'),
    ('Nouns - General', 'Nouns - General'),
    ('Numbers', 'Numbers'),
    ('Office', 'Office'),
    ('Pakistan Places', 'Pakistan Places'),
    ('Prepositions', 'Prepositions'),
    ('Professions', 'Professions'),
    ('Pronouns', 'Pronouns'),
    ('Science', 'Science'),
    ('Sentences', 'Sentences'),
    ('Sewing', 'Sewing'),
    ('Space', 'Space'),
    ('Spices', 'Spices'),
    ('Sports & Games', 'Sports & Games'),
    ('Textile', 'Textile'),
    ('Transport', 'Transport'),
    ('Vegetables', 'Vegetables'),
    ('Verbs', 'Verbs'),
    ('Vocational - General', 'Vocational - General'),
    ('Weather', 'Weather')
]

# Form to submit gestures
class GestureForm(FlaskForm):
    contributor_name = StringField('Contributor Name', validators=[DataRequired()])
    name= StringField('Contributor Name', validators=[DataRequired()])
    avatar_video = FileField('Avatar Video', validators=[DataRequired()])
    category = SelectField('Category', choices=categories, validators=[DataRequired()])


@app.route('/submit', methods=['GET', 'POST'])
def submit_gesture():
    form = GestureForm()

    if form.validate_on_submit():
        # Get form data
        contributor_name = form.contributor_name.data
        name=form.name.data
        category = form.category.data
        avatar_video = form.avatar_video.data
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Store the avatar video in GridFS
        video_filename = avatar_video.filename
        video_data = avatar_video.read()
        video_id = fs.put(video_data, filename=video_filename)

        # Save gesture details (without the video file) to the dictionary collection
        gesture_data = {
            'contributor_name': contributor_name,
            'name':name,
            'avatar_video_id': video_id,  # Store the GridFS file ID for reference
            'category': category,
            'created_at': created_at
        }

        # Insert the gesture data into the dictionary collection
        dictionary_collection.insert_one(gesture_data)

        # Redirect after success
        

    return render_template('submit_gesture.html', form=form)








































# Add these imports at the top of your app.py
import logging
from flask import jsonify, request
from bson.json_util import dumps

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Add these endpoints to your Flask app:

@app.route('/api/gestures/all', methods=['GET'])
def get_all_gestures():
    """Endpoint to get all gestures"""
    try:
        # Get all gestures from the database
        gestures = list(dictionary_collection.find(
            {},
            {"_id": 0, "contributor_name": 1, "name": 1, "category": 1, "created_at": 1, "image_url": 1, "video_url": 1}
        ))
        return jsonify({
            'success': True,
            'gestures': gestures
        })
    except Exception as e:
        logger.error(f"Error fetching all gestures: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Fix your existing categories endpoint:
@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Endpoint to get all categories"""
    logger.debug("Fetching all categories")
    try:
        # Get unique categories from the database
        db_categories = dictionary_collection.distinct("category")
        return jsonify({
            'success': True,
            'categories': db_categories
        })
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500









@app.route('/api/gestures/category/<category>', methods=['GET'])
def get_gestures_by_category(category):
    """Endpoint to get gestures by category"""
    logger.debug(f"Fetching gestures for category: {category}")
    try:
        gestures = list(dictionary_collection.find(
            {"category": category},
            {"_id": 0, "contributor_name": 1, "name": 1, "category": 1, "created_at": 1}
        ))
        print(f"Gestures for Category '{category}': {gestures}")  # Debugging line
        return jsonify({'success': True, 'gestures': gestures})
    except Exception as e:
        logger.error(f"Error fetching gestures for category {category}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/gestures/search', methods=['GET'])
def search_gestures():
    """Endpoint to search gestures by name"""
    search_term = request.args.get('q', '')
    logger.debug(f"Searching gestures with term: {search_term}")
    try:
        gestures = list(dictionary_collection.find(
            {"name": {"$regex": search_term, "$options": "i"}},
            {"_id": 0, "contributor_name": 1, "name": 1, "category": 1, "created_at": 1}
        ).limit(20))
        print(f"Search Results for '{search_term}': {gestures}")  # Debugging line
        return jsonify({'success': True, 'gestures': gestures})
    except Exception as e:
        logger.error(f"Error searching gestures: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Frontend Routes
@app.route('/browse')
def browse_gestures():
    """Frontend page for browsing gestures"""
    return render_template('browse_gestures.html')





from flask import render_template, request
from urllib.parse import unquote

@app.route('/gesture')
def gesture_details():
    """Route to show gesture details page"""
    gesture_name = request.args.get('name')
    if not gesture_name:
        return render_template('gesture_details.html', error="No gesture specified")
    
    try:
        # Get gesture details from database
        gesture = dictionary_collection.find_one(
            {"name": unquote(gesture_name)},
            {"_id": 0}
        )
        
        if not gesture:
            return render_template('gesture_details.html', error="Gesture not found")
            
        # Add video URL if video_file_id exists
        if "avatar_video_id" in gesture:
            gesture["video_url"] = url_for('stream_video', 
                                         video_id=gesture["avatar_video_id"], 
                                         _external=True)
        
        return render_template('gesture_details.html', gesture=gesture)
        
    except Exception as e:
        return render_template('gesture_details.html', error=f"Error loading gesture: {str(e)}")




# Add custom filter to format dates
@app.template_filter('format_date')
def format_date_filter(value, format="%b %d, %Y"):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return value
    if isinstance(value, datetime):
        return value.strftime(format)
    return value





if __name__ == '__main__':
    app.run(debug=True)  # Ensure the app is running in debug mode


















