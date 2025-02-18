# Chalkboard Project Overview

This Flask application provides a robust backend for handling user authentication, course management, and avatar updates using Google Cloud Datastore and Storage. It features JWT-based authentication, integrating with Auth0 for secure user verification, and supports CRUD operations on user and course entities.

## Prerequisites

- Python 3.8 or higher
- Flask
- Google Cloud SDK
- Authlib
- Requests
- Python-dotenv
- python-jose

## Installation

### Clone the repository:

```bash
git clone <repository-url>
cd <repository-folder>
```
### Set up a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Install dependencies:
```
pip install -r requirements.txt
Set up environment variables:
Create a .env file in the root directory of the project and populate it with the necessary environment variables:
```
```
SECRET_KEY=your_secret_key
CLIENT_ID=your_auth0_client_id
CLIENT_SECRET=your_auth0_client_secret
DOMAIN=your_auth0_domain
BUCKET_NAME=your_gcs_bucket_name
APP_HOST=localhost
APP_PORT=5000
APP_URL=http://localhost:5000
```

### Configure Google Cloud credentials:
Ensure that your Google Cloud credentials are set up properly and that the application has access to Datastore and Storage.

### Running the Application
To start the server, run:

```
python app.py
This will start the Flask server on http://localhost:5000 by default, as specified in your environment variables.
```
### Usage
The application supports various endpoints for managing users, courses, and avatars:

### User Authentication and Management:

`/users/login` for user authentication.
`/users for` fetching all users or a specific user.
`/users/<user_id>/avatar` for handling user avatars.
### Course Management:

`/courses` to create or retrieve courses.
`/courses/<course_id>` to update, retrieve, or delete specific courses.
### Example Requests
Here are a few examples of how to interact with the API:

### Logging in a user:
```
curl -X POST http://localhost:5000/users/login -H "Content-Type: application/json" -d '{"username":"testuser", "password":"password"}'
```
### Getting a user's avatar:
```
curl http://localhost:5000/users/1/avatar
```
### Creating a course:
```
curl -X POST http://localhost:5000/courses -H "Content-Type: application/json" -d '{"subject":"Math", "number":"101", "title":"Algebra", "term":"Fall 2023", "instructor_id":"1"}'
```
### Contributing
Contributions are welcome. Please fork the repository and submit pull requests to the main branch.
