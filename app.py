from flask import Flask, request, jsonify, session, render_template, redirect, url_for, make_response
import re
import datetime
from functools import wraps
from datetime import timedelta
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = '449flaskproject'
app.config['SESSION_COOKIE_NAME'] = 'inventory_app_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

# In-memory data to store inventory
inventory = {}

# In-memory data to store users
users = {}

# Helper function to find item by item_id
def find_item(user, item_id):
    user_inventory = inventory.get(user)
    for item in user_inventory:
        if item['id'] == item_id:
            return item
    return None

def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# Helper function to check if the request has a valid JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# User registration endpoint
@app.route('/register', methods=['POST'])
def register():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400

    username = request.json['username']
    password = request.json['password']
    # role = request.json.get('role', 'user')  # default to 'user'
    
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    
    if not isinstance(username, str):
        return jsonify({'error': 'Username must be a string'}), 400

    if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({'error': 'Password must contain a special character and be at least 8 characters long.'}), 400

    users[username] = password

    return jsonify({'message': 'User has been successfully registered'}), 201


# User login endpoint and get a JWT token
@app.route('/login', methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400

    username = request.json['username']
    password = request.json['password']

    if users.get(username) != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = jwt.encode(
            {'username': username, 'exp': datetime.datetime.now(datetime.timezone.utc) + timedelta(minutes=30)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    session['user'] = username # Store user session
    response = jsonify({'message': 'Login sucessful', 'token': token})
    response.set_cookie('username', username, httponly=True, max_age=1800)

    return response, 200


# User logout endpoint and clears session and removes cookies
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    response = jsonify({'message': 'Logout successful'})
    response.set_cookie('username', '', expires=0)  # Clear session cookie
    return response, 200


# Middleware
@app.before_request
def require_login():
    allowed_routes = ['login', 'register']  # Routes that don't require authentication
    if request.endpoint not in allowed_routes and 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in to view this resource.'}), 401


# Get all items in inventory (logged in only)
@app.route('/inventory', methods=['GET'])
@token_required
def get_items(current_user):
    return jsonify(inventory.get(current_user))


# Get a single item by item_id (logged in only)
@app.route('/inventory/<int:item_id>', methods=['GET'])
@token_required
def get_item(current_user, item_id):
    item = find_item(current_user, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    return jsonify(item)


# Create a new item (logged in only)
@app.route('/inventory', methods=['POST'])
@token_required
def create_item(current_user):
    required_fields = ['name', 'description', 'quantity', 'price']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Required fields are: name (string), description (string), quantity (int), price (float)'}), 400

    if not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity']):
        return jsonify({'error': 'Price must be zero or a positive integer'}), 400
    if not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400
    
    # Handle first time item creation by a user
    if current_user not in inventory:
        inventory[current_user] = []

    user_inventory = inventory[current_user]
    item_id = max(item['id'] for item in user_inventory) + 1 if user_inventory else 1

    item = {
        'id': item_id,
        'name': request.json['name'],
        'description': request.json['description'],
        'quantity': request.json['quantity'],
        'price': request.json['price']
    }

    user_inventory.append(item)
    return jsonify(item), 201


# Update an item (logged in only)
@app.route('/inventory/<int:item_id>', methods=['PUT'])
@token_required
def update_item(current_user, item_id):
    item = find_item(current_user, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    
    if not request.json:
        return jsonify({'error': 'Request body must be in JSON format'}), 400
    
    if 'name' in request.json and not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if 'description' in request.json and not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if 'quantity' in request.json and (not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity'])):
        return jsonify({'error': 'Price must be zero or a positive integer'}), 400
    if 'price' in request.json and not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400

    item.update(request.json)
    return jsonify(item)


# Delete an item by item_id (logged in only)
@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@token_required
def delete_item(current_user, item_id):
    item = find_item(current_user, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    inventory[current_user].remove(item)
    return jsonify({'message': 'Item successfully deleted'}), 200


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)