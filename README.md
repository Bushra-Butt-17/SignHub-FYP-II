# SignHub API Documentation 📄


Welcome to the **SignHub API**! This API allows users to interact with a platform for managing sign language gestures, including user authentication, gesture submissions, and profile management. Below is a detailed explanation of each endpoint! 🎉

---

## Table of Contents 📑
1. [Home 🏠](#home-)
2. [Signup ✍️](#signup-)
3. [Login 🔑](#login-)
4. [Dashboard 📊](#dashboard-)
5. [Stream Video 📹](#stream-video-)
6. [Profile Picture 🖼️](#profile-picture-)
7. [Logout 🚪](#logout-)
8. [Add Gesture ✨](#add-gesture-)
9. [API Dashboard 📈](#api-dashboard-)

---

## Home 🏠
**Endpoint:** `/`  
**Method:** `GET`  
**Description:**  
This is the landing page of the application. It renders the `home.html` template, providing users with an introduction to the platform.  
**Response:**  
- Renders the `home.html` template.

---

## Signup ✍️
**Endpoint:** `/signup`  
**Methods:** `GET`, `POST`  
**Description:**  
Allows new users to create an account. On a `POST` request, it validates the input fields (username, email, password, and confirm password) and creates a new user in the database.  
**Request Body (POST):**  
- `username`: The desired username.
- `email`: The user's email address.
- `password`: The user's password.
- `confirm_password`: Confirmation of the password.  
**Response:**  
- On success: Redirects to the login page with a success message.
- On failure: Redirects back to the signup page with an error message.

---

## Login 🔑
**Endpoint:** `/login`  
**Methods:** `GET`, `POST`  
**Description:**  
Allows existing users to log in. On a `POST` request, it validates the email and password, and if correct, creates a session for the user.  
**Request Body (POST):**  
- `email`: The user's email address.
- `password`: The user's password.  
**Response:**  
- On success: Redirects to the dashboard with a success message.
- On failure: Redirects back to the login page with an error message.

---

## Dashboard 📊
**Endpoint:** `/dashboard`  
**Methods:** `GET`, `POST`  
**Description:**  
The user's dashboard, where they can view their profile, upload a profile picture, and see their gesture submissions (pending, approved, and rejected).  
**Request Body (POST):**  
- `profile_pic`: A file upload for the user's profile picture.  
**Response:**  
- Renders the `dashboard.html` template with user data, gesture statistics, and video URLs.

---

## Stream Video 📹
**Endpoint:** `/stream_video/<video_id>`  
**Method:** `GET`  
**Description:**  
Streams a video file from GridFS using the provided `video_id`.  
**Parameters:**  
- `video_id`: The ID of the video to stream.  
**Response:**  
- Streams the video file with the appropriate MIME type (`video/mp4`).

---

## Profile Picture 🖼️
**Endpoint:** `/profile_pic/<user_id>`  
**Method:** `GET`  
**Description:**  
Retrieves and serves the profile picture for a user. If no profile picture is found, it serves a default image.  
**Parameters:**  
- `user_id`: The ID of the user whose profile picture is being requested.  
**Response:**  
- Serves the profile picture or a default image if none is found.

---

## Logout 🚪
**Endpoint:** `/logout`  
**Method:** `GET`  
**Description:**  
Logs the user out by clearing their session.  
**Response:**  
- Redirects to the login page with a success message.

---

## Add Gesture ✨
**Endpoint:** `/add_gesture`  
**Methods:** `GET`, `POST`  
**Description:**  
Allows users to submit a new gesture for review. On a `POST` request, it validates the input fields (name, dialect, and video file) and stores the gesture in the `pending_gestures` collection.  
**Request Body (POST):**  
- `name`: The name of the gesture.
- `dialect`: The dialect associated with the gesture.
- `video`: A video file demonstrating the gesture.  
**Response:**  
- On success: Redirects to the dashboard with a success message.
- On failure: Redirects back to the add gesture page with an error message.

---

## API Dashboard 📈
**Endpoint:** `/api/dashboard`  
**Method:** `GET`  
**Description:**  
Provides a JSON representation of the user's dashboard data, including profile information, gesture statistics, and video details.  
**Response:**  
- Returns a JSON object containing:
  - User details (name, profile picture URL).
  - Gesture statistics (total submissions, approved, pending, rejected).
  - Video details (pending, approved, rejected videos).

---

## Running the Application 🚀
To run the application, use the following command:
```bash
python app.py
```
The application will be served on `http://0.0.0.0:5000`.

---

## Dependencies 📦
- Flask
- Flask-CORS
- Flask-JWT-Extended
- PyMongo
- GridFS
- Waitress
- python-dotenv

---

## Environment Variables 🔧
- `SECRET_KEY`: Secret key for Flask session management.
- `JWT_SECRET_KEY`: Secret key for JWT token generation.
- `MONGODB_URI`: MongoDB connection URI.

---

## License 📜
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
![](https://github.com/user-attachments/assets/a0fd75d7-1606-41c0-895b-5f8eb79b8235)

Enjoy using **SignHub**! If you have any questions or issues, feel free to reach out. 😊
