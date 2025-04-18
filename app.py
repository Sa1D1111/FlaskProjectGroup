from flask import Flask, request, jsonify, session
import re
import datetime
from functools import wraps
from datetime import timedelta
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = '449flaskproject' # Usually hidden in a .env
app.config['SESSION_COOKIE_NAME'] = 'inventory_app_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

inventory = {}

users = {}


# Helper function to find item by item_id
def find_item(user, item_id):
    user_inventory = inventory.get(user, [])
    for item in user_inventory:
        if item['id'] == item_id:
            return item
    return None


# Email validation
def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)


# Date validation
def validate_date(date):
    if not re.match(r'^(0[1-9]|1[0-2])/([0][1-9]|[12][0-9]|3[01])/(\d{4})$', date):
        return False
    return True


# Role validation
def is_valid_role(role):
    return role == "user" or role == "admin"


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
        
        # current_user is user name after decoding as the first argument, followed by the rest of the route parameters
        return f(current_user, *args, **kwargs)
    
    return decorated


# User/Admin registration endpoint
@app.route('/register', methods=['POST'])
def register():
    if not request.json or 'username' not in request.json or 'password' not in request.json or 'email' not in request.json or 'role' not in request.json:
        return jsonify({'error': 'Username, password, email, and role are required'}), 400

    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    role = request.json['role']
    
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    if not isinstance(username, str):
        return jsonify({'error': 'Username must be a string'}), 400
    if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({'error': 'Password must contain a special character (e.g. !@#$%^&*(),.?\":{}|<>)and be at least 8 characters long.'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'Email is not in format user@email.com'}), 400
    if not is_valid_role(role):
        return jsonify({'error': 'User is missing role (user or admin)'}), 400

    users[username] = {
        'password': password,
        'email': email,
        'role': role
    }

    return jsonify({'message': 'User has been successfully registered'}), 201


# User/Admin login endpoint and get a JWT token
@app.route('/login', methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400

    username = request.json['username']
    password = request.json['password']

    user = users.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = jwt.encode(
            {'username': username, 'exp': datetime.datetime.now(datetime.timezone.utc) + timedelta(minutes=30)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    
    session['user'] = username # Store user session
    response = jsonify({'message': 'Login sucessful', 'token': token})
    response.set_cookie('username', username, httponly=True, max_age=3600)

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


# User Routes

# Get all items in inventory (logged in only)
@app.route('/inventory', methods=['GET'])
@token_required
def get_items(current_user):
    # Only grab items belonging to the current_user
    return jsonify(inventory.get(current_user, []))


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
    required_fields = ['name', 'description', 'quantity', 'price', 'brand', 'condition', 'last updated']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Required fields are: name (string), description (string), quantity (int), price (float), condition (new or used), last updated (MM/DD/YYYY)'}), 400

    if not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if not isinstance(request.json['brand'], str):
        return jsonify({'error': 'Brand must be a string'}), 400
    if not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity']):
        return jsonify({'error': 'Quantity must be zero or a positive integer'}), 400
    if not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400
    if not isinstance(request.json['condition'], str):
        return jsonify({'error': 'Condition must be a string (either new or used)'}), 400
    if not validate_date(request.json['last updated']):
        return jsonify({'error': 'Date must be in format MM/DD/YYYY'}), 400
    
    # Handle first time item creation by a user
    # Creates an inventory specific to current_user
    if current_user not in inventory:
        inventory[current_user] = []

    user_inventory = inventory[current_user]
    item_id = max(item['id'] for item in user_inventory) + 1 if user_inventory else 1

    item = {
        'id': item_id,
        'name': request.json['name'],
        'brand': request.json['brand'],
        'description': request.json['description'],
        'quantity': request.json['quantity'],
        'price': request.json['price'],
        'condition': request.json['condition'],
        'last updated': request.json['last updated']
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
    
    required_fields = ['name', 'description', 'quantity', 'price', 'brand', 'condition', 'last updated']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Required fields are: name (string), description (string), quantity (int), price (float), condition (new or used), last updated (MM/DD/YYYY)'}), 400
    
    if 'name' in request.json and not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if 'brand' in request.json and not isinstance(request.json['brand'], str):
        return jsonify({'error': 'Brand must be a string'}), 400
    if 'description' in request.json and not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if 'quantity' in request.json and (not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity'])):
        return jsonify({'error': 'Quantity must be zero or a positive integer'}), 400
    if 'price' in request.json and not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400
    if 'condition' in request.json and not isinstance(request.json['condition'], str):
        return jsonify({'error': 'Condition must be a string (either new or used)'}), 400
    if 'last updated' in request.json and not validate_date(request.json['last updated']):
        return jsonify({'error': 'Date must be in format MM/DD/YYYY'}), 400

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


# Admin Routes

# Helper function to check if admin
def admin_role_check(new_user):
    user = users.get(new_user)
    return user['role'] == 'admin'


# Get all items in inventory (logged in only)
@app.route('/admin/inventory/', methods=['GET'])
@token_required
def admin_get_all_inventory(current_user):
    # Grab all items belonging to the current_user
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401
    return jsonify(inventory)


# Get all items for a single user
@app.route('/admin/inventory/<string:username>', methods=['GET'])
@token_required
def admin_get_user_inventory(current_user, username):
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401
    
    user_inventory = inventory.get(username, [])
    if user_inventory is None:
        return jsonify({'error': 'Items not found'}), 404
    return jsonify(user_inventory)


# Get a single item by username and item_id (logged in only)
@app.route('/admin/inventory/<string:username>/<int:item_id>', methods=['GET'])
@token_required
def admin_get_user_item(current_user, username, item_id):
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401
    
    item = find_item(username, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    return jsonify(item)


# Create a new item for a user (logged in only)
@app.route('/admin/inventory/<string:username>', methods=['POST'])
@token_required
def admin_create_item(current_user, username):
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401
    
    required_fields = ['name', 'description', 'quantity', 'price', 'brand', 'condition', 'last updated']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Required fields are: name (string), description (string), quantity (int), price (float), condition (new or used), last updated (MM/DD/YYYY)'}), 400

    if not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if not isinstance(request.json['brand'], str):
        return jsonify({'error': 'Brand must be a string'}), 400
    if not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity']):
        return jsonify({'error': 'Quantity must be zero or a positive integer'}), 400
    if not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400
    if not isinstance(request.json['condition'], str):
        return jsonify({'error': 'Condition must be a string (either new or used)'}), 400
    if not validate_date(request.json['last updated']):
        return jsonify({'error': 'Date must be in format MM/DD/YYYY'}), 400
    
    # Handle first time item creation by a user
    # Creates an inventory specific to current_user
    if username not in inventory:
        inventory[username] = []

    user_inventory = inventory[username]
    item_id = max(item['id'] for item in user_inventory) + 1 if user_inventory else 1

    item = {
        'id': item_id,
        'name': request.json['name'],
        'brand': request.json['brand'],
        'description': request.json['description'],
        'quantity': request.json['quantity'],
        'price': request.json['price'],
        'condition': request.json['condition'],
        'last updated': request.json['last updated']
    }

    user_inventory.append(item)
    return jsonify(item), 201


# Update an item for a user (logged in only)
@app.route('/admin/inventory/<string:username>/<int:item_id>', methods=['PUT'])
@token_required
def admin_update_item(current_user, username, item_id):
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401

    item = find_item(username, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    
    required_fields = ['name', 'description', 'quantity', 'price', 'brand', 'condition', 'last updated']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Required fields are: name (string), description (string), quantity (int), price (float), condition (new or used), last updated (MM/DD/YYYY)'}), 400
    
    if 'name' in request.json and not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if 'brand' in request.json and not isinstance(request.json['brand'], str):
        return jsonify({'error': 'Brand must be a string'}), 400
    if 'description' in request.json and not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if 'quantity' in request.json and (not isinstance(request.json['quantity'], int) or not (0 <= request.json['quantity'])):
        return jsonify({'error': 'Quantity must be zero or a positive integer'}), 400
    if 'price' in request.json and not isinstance(request.json['price'], float):
        return jsonify({'error': 'Price must be a floating point number'}), 400
    if 'condition' in request.json and not isinstance(request.json['condition'], str):
        return jsonify({'error': 'Condition must be a string (either new or used)'}), 400
    if 'last updated' in request.json and not validate_date(request.json['last updated']):
        return jsonify({'error': 'Date must be in format MM/DD/YYYY'}), 400

    item.update(request.json)
    return jsonify(item)


# Delete an item by item_id (logged in only)
@app.route('/admin/inventory/<string:username>/<int:item_id>', methods=['DELETE'])
@token_required
def admin_delete_item(current_user, username, item_id):
    if not admin_role_check(current_user):
        return jsonify({'error': 'Insufficient permissions. Requires admin role.'}), 401
    
    item = find_item(username, item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    inventory[username].remove(item)
    return jsonify({'message': 'Item successfully deleted'}), 200


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)