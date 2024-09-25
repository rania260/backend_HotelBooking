import hashlib
import datetime
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
from bson.objectid import ObjectId
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = '82ee86b1bfd0e997cb0319c3fcdcc0ac2d8ad47e'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)

client = MongoClient("mongodb+srv://raniarezgui4:4marns3zJLRUI0fw@cluster0.iyxtn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["mydatabase"]
users_collection = db["users"]
# Define the hotels collection
hotels_collection = db["hotels"]

@app.route('/')
def hello_world():
	return 'Hello, World!'

#Register
@app.route("/register", methods=["POST"])
def register():
    new_user = request.get_json()  # récupérer les données JSON
    new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest()  # encrypter le mot de passe
    new_user["role"] = "user"  # ajouter le rôle par défaut

    # Vérifier si l'email ou le nom d'utilisateur existe déjà
    if users_collection.find_one({"email": new_user["email"]}) or users_collection.find_one({"username": new_user["username"]}):
        return jsonify({'msg': 'Username or email already exists'}), 409
    
    # Si non, insérer le nouvel utilisateur
    users_collection.insert_one(new_user)
    return jsonify({'msg': 'User created successfully'}), 201



# login
# @app.route("/login", methods=["POST"])
# def login():
#     login_details = request.get_json()  # récupérer les données JSON
#     user_from_db = users_collection.find_one({'email': login_details['email']})  # rechercher l'utilisateur via l'email

#     if user_from_db:
#         encrypted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
#         if encrypted_password == user_from_db['password']:
#             access_token = create_access_token(identity={'email': user_from_db['email'], 'role': user_from_db['role']})  # créer le token JWT avec le rôle
#             return jsonify(access_token=access_token), 200

#     return jsonify({'msg': 'The email or password is incorrect'}), 401
# login route
@app.route("/login", methods=["POST"])
def login():
    login_details = request.get_json()  # récupérer les données JSON
    user_from_db = users_collection.find_one({'email': login_details['email']})  # rechercher l'utilisateur via l'email

    if user_from_db:
        encrypted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
        if encrypted_password == user_from_db['password']:
            access_token = create_access_token(identity={'email': user_from_db['email'], 'role': user_from_db['role']})  # créer le token JWT avec le rôle
            return jsonify(access_token=access_token, role=user_from_db['role']), 200

    return jsonify({'msg': 'The email or password is incorrect'}), 401

#logout users
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'msg': 'Logout successful'})
    response.delete_cookie('access_token')  # Optional: if you're using cookies to store the token
    return response



# # Route to get all users (admin-only functionality)
# @app.route("/getallusers", methods=["GET"])
# @jwt_required()
# def get_all_users():
#     current_user = get_jwt_identity()  # Get the current user's identity
    
#     # Ensure that only admins can access this route
#     if current_user['role'] != 'admin':
#         return jsonify({'msg': 'Access denied. Admins only.'}), 403
    
#     users = users_collection.find({}, {"_id": 0, "password": 0})  # Get all users excluding '_id' and 'password'
#     users_list = list(users)  # Convert the cursor to a list
    
#     return jsonify({'users': users_list}), 200
@app.route("/getallusers", methods=["GET"])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    users = users_collection.find({}, {'_id': 1, 'username': 1, 'email': 1, 'role': 1})  # Sélectionner uniquement les champs nécessaires
    user_list = []
    for user in users:
        user_list.append({
            '_id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        })

    return jsonify({'users': user_list}), 200
# Route pour obtenir un utilisateur par ID
@app.route("/getallusers/<user_id>", methods=["GET"])
@jwt_required()
def get_user_by_id(user_id):
    current_user = get_jwt_identity()
    # Vérifier si l'utilisateur est un admin
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    # Récupérer l'utilisateur par ID
    try:
        obj_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": obj_id}, {"_id": 0, "password": 0})  # Exclude password field
        if user:
            return jsonify(user), 200
        else:
            return jsonify({'msg': 'User not found'}), 404
    except Exception as e:
        return jsonify({'msg': str(e)}), 400

#add

@app.route("/adduser", methods=["POST"])
@jwt_required()
def add_user():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    data = request.json
    username = data.get('username')
    email = data.get('email')
    role = data.get('role')
    password = data.get('password')

    if not all([username, email, role, password]):
        return jsonify({'msg': 'Missing required fields'}), 400

    hashed_password = generate_password_hash(password)  # Hash the password before saving

    new_user = {
        'username': username,
        'email': email,
        'role': role,
        'password': hashed_password
    }

    try:
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User added successfully'}), 201
    except Exception as e:
        return jsonify({'msg': 'Failed to add user', 'error': str(e)}), 500

# @app.route("/adduser", methods=["POST"])
# @jwt_required()
# def add_user():
#     current_user = get_jwt_identity()
#     if current_user['role'] != 'admin':
#         return jsonify({'msg': 'Access denied'}), 403

#     user_data = request.get_json()
    
#     # Ensure required fields are present
#     if 'username' not in user_data or 'email' not in user_data or 'role' not in user_data:
#         return jsonify({'msg': 'Missing required fields'}), 400

#     # Add user to the database
#     try:
#         result = users_collection.insert_one(user_data)
#         return jsonify({'msg': 'User added successfully', 'user_id': str(result.inserted_id)}), 201
#     except Exception as e:
#         return jsonify({'msg': str(e)}), 400

#delete
# @app.route("/getallusers/delete/<user_id>", methods=["DELETE"])
# @jwt_required()
# def delete_user(user_id):
#     current_user = get_jwt_identity()
#     if current_user['role'] != 'admin':
#         return jsonify({'msg': 'Access denied'}), 403

#     # Validate the user_id
#     try:
#         obj_id = ObjectId(user_id)
#     except Exception as e:
#         return jsonify({'msg': 'Invalid user ID'}), 400

#     result = users_collection.delete_one({"_id": obj_id})

#     if result.deleted_count == 1:
#         return jsonify({'msg': 'User deleted successfully'}), 200
#     else:
#         return jsonify({'msg': 'User not found'}), 404


@app.route("/getallusers/delete/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()

    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    # Vérification : l'ID est-il déjà un ObjectId ? 
    try:
        obj_id = ObjectId(user_id)  # On essaie de le convertir en ObjectId
    except Exception as e:
        return jsonify({'msg': 'Invalid user ID', 'error': str(e)}), 400

    # Tentative de suppression de l'utilisateur
    result = users_collection.delete_one({"_id": obj_id})

    if result.deleted_count == 1:
        return jsonify({'msg': 'User deleted successfully'}), 200
    else:
        return jsonify({'msg': 'User not found'}), 404



# Route pour mettre à jour un utilisateur par ID
@app.route("/getallusers/update/<user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user = get_jwt_identity()
    # Vérifier si l'utilisateur est un admin
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    # Récupérer les nouvelles données à mettre à jour
    updated_data = request.get_json()

    # Mettre à jour l'utilisateur
    try:
        result = users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": updated_data}
        )

        if result.modified_count == 1:
            return jsonify({'msg': 'User updated successfully'}), 200
        else:
            return jsonify({'msg': 'User not found or no changes made'}), 404
    except Exception as e:
        return jsonify({'msg': str(e)}), 400

# GESTION HOTEL
@app.route("/create/hotel", methods=["POST"])
@jwt_required()
def add_hotel():
    #return jsonify({'msg': 'Route is working!'}), 200
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    hotel_data = request.get_json()
    required_fields = ['title', 'city', 'address', 'price', 'photo', 'description', 'reviews']

    if not all(field in hotel_data for field in required_fields):
        return jsonify({'msg': 'Missing fields'}), 400

    result = hotels_collection.insert_one(hotel_data)
    return jsonify({'msg': 'Hotel added successfully', 'hotel_id': str(result.inserted_id)}), 201


@app.route("/hotels", methods=["GET"])
@jwt_required()
def get_all_hotels():
    current_user = get_jwt_identity()
    hotels_cursor = hotels_collection.find({}, {
        "_id": 1, "title": 1, "city": 1, "address": 1, "price": 1, "description": 1, "photo": 1, "reviews": 1
    })  # Added "reviews": 1 to include reviews

    hotels_list = []
    for hotel in hotels_cursor:
        hotels_list.append({
            "_id": str(hotel["_id"]),
            "title": hotel["title"],
            "city": hotel["city"],
            "address": hotel.get("address", ""),
            "price": hotel["price"],
            "description": hotel.get("description", ""),
            "photo": hotel.get("photo", ""),
            "reviews": hotel.get("reviews", [])  # Include reviews here
        })

    return jsonify({'hotels': hotels_list}), 200



#update hotel
@app.route("/hotels/update/<hotel_id>", methods=["PUT"])
@jwt_required()
def update_hotel(hotel_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    updated_data = request.get_json()
    result = hotels_collection.update_one({"_id": ObjectId(hotel_id)}, {"$set": updated_data})

    if result.modified_count == 1:
        return jsonify({'msg': 'Hotel updated successfully'}), 200
    else:
        return jsonify({'msg': 'Hotel not found or no changes made'}), 404
#delete hotel 
@app.route("/hotels/delete/<hotel_id>", methods=["DELETE"])
@jwt_required()
def delete_hotel(hotel_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403

    result = hotels_collection.delete_one({"_id": ObjectId(hotel_id)})

    if result.deleted_count == 1:
        return jsonify({'msg': 'Hotel deleted successfully'}), 200
    else:
        return jsonify({'msg': 'Hotel not found'}), 404

#gethotelbyid
# @app.route("/hotels/<hotel_id>", methods=["GET"])
# @jwt_required()
# def get_hotel_by_id(hotel_id):
#     current_user = get_jwt_identity()
#     if current_user['role'] != 'admin':
#         return jsonify({'msg': 'Access denied'}), 403

#     hotel = hotels_collection.find_one({"_id": ObjectId(hotel_id)}, {
#         "_id": 1, "title": 1, "city": 1, "address": 1, "price": 1, "description": 1, "photo": 1, "reviews": 1
#     })

#     if hotel:
#         return jsonify({
#             "_id": str(hotel["_id"]),
#             "title": hotel["title"],
#             "city": hotel["city"],
#             "address": hotel.get("address", ""),
#             "price": hotel["price"],
#             "description": hotel.get("description", ""),
#             "photo": hotel.get("photo", ""),
#             "reviews": hotel.get("reviews", [])
#         }), 200
#     else:
#         return jsonify({'msg': 'Hotel not found'}), 404
#gethotelbyid
@app.route("/hotels/<hotel_id>", methods=["GET"])
@jwt_required()
def get_hotel(hotel_id):
    current_user = get_jwt_identity()
    # Logique pour récupérer les détails de l'hôtel
    hotel = hotels_collection.find_one({"_id": ObjectId(hotel_id)})
    if hotel:
        return jsonify({
            "_id": str(hotel["_id"]),
            "title": hotel["title"],
            "city": hotel["city"],
            "address": hotel.get("address", ""),
            "price": hotel["price"],
            "description": hotel.get("description", ""),
            "photo": hotel.get("photo", ""),
            "reviews": hotel.get("reviews", [])
        }), 200
    return jsonify({"message": "Hôtel non trouvé"}), 404



if __name__ == '__main__':
    app.run(debug=True)