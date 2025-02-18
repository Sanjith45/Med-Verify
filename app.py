from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
import qrcode  # Import the qrcode module
import base64  # To encode the QR code to base64
from io import BytesIO  # To handle the in-memory image for the QR code

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this in production
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["auth_app"]

# Using different collections for different roles
users_collection = db["users"]
manufacturers_collection = db["manufacturer"]
distributors_collection = db["distributor"]
products_collection = db["products"]
orders_collection = db["orders"]
transactions_collection = db["transactions"]  # New Collection for Transactions

@app.route("/")
def home():
    return render_template("home.html")

# Manufacturer login route
@app.route("/manufacturer/login", methods=["GET", "POST"])
def manufacturer_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = manufacturers_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["role"] = "Manufacturer"
            session["username"] = username
            flash(f"Welcome, {username}! You are logged in as Manufacturer.", "success")
            return redirect(url_for("manufacturer_dashboard"))
        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for("manufacturer_login"))
    
    return render_template("manufacturer_login.html")

# Manufacturer signup route
@app.route("/manufacturer/signup", methods=["GET", "POST"])
def manufacturer_signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        user_data = {
            "role": "Manufacturer",
            "username": username,
            "password": hashed_password,
            "company_name": request.form.get("company_name"),
            "manufacturer_name": request.form.get("manufacturer_name")
        }

        if manufacturers_collection.find_one({"username": username}):
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for("manufacturer_signup"))

        manufacturers_collection.insert_one(user_data)
        flash("Manufacturer signup successful! Please log in.", "success")
        return redirect(url_for("manufacturer_login"))
    
    return render_template("manufacturer_signup.html")

# Distributor login route
@app.route("/distributor/login", methods=["GET", "POST"])
def distributor_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = distributors_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["role"] = "Distributor"
            session["username"] = username
            flash(f"Welcome, {username}! You are logged in as Distributor.", "success")
            return redirect(url_for("distributor_dashboard"))
        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for("distributor_login"))
    
    return render_template("distributor_login.html")

# Distributor signup route
@app.route("/distributor/signup", methods=["GET", "POST"])
def distributor_signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        user_data = {
            "role": "Distributor",
            "username": username,
            "password": hashed_password,
            "company_name": request.form.get("company_name"),
            "distributor_name": request.form.get("distributor_name")
        }

        if distributors_collection.find_one({"username": username}):
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for("distributor_signup"))

        distributors_collection.insert_one(user_data)
        flash("Distributor signup successful! Please log in.", "success")
        return redirect(url_for("distributor_login"))
    
    return render_template("distributor_signup.html")

# User login route
@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["role"] = "User"
            session["username"] = username
            flash(f"Welcome, {username}! You are logged in as User.", "success")
            return redirect(url_for("user_dashboard"))
        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for("user_login"))
    
    return render_template("user_login.html")

# User signup route
@app.route("/user/signup", methods=["GET", "POST"])
def user_signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        user_data = {
            "role": "User",
            "username": username,
            "password": hashed_password,
            "name": request.form.get("name"),
            "email": request.form.get("email")
        }

        if users_collection.find_one({"username": username}):
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for("user_signup"))

        users_collection.insert_one(user_data)
        flash("User signup successful! Please log in.", "success")
        return redirect(url_for("user_login"))
    
    return render_template("user_signup.html")

# Manufacturer Dashboard
@app.route("/manufacturer_dashboard", methods=["GET", "POST"])
def manufacturer_dashboard():
    if "username" not in session or session.get("role") != "Manufacturer":
        flash("You must log in as a Manufacturer to access this dashboard.", "error")
        return redirect(url_for("home"))
    
    username = session["username"]

    # Add Product
    if request.method == "POST":
        product_name = request.form["product_name"]
        quantity = int(request.form["quantity"])
        weight = request.form["weight"]

        # Generate QR Code
        qr_data = f"{product_name},{quantity},{weight},{username}"  # Data for the QR code
        qr = qrcode.make(qr_data)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")  # Base64 encoding for storing in DB

        # Insert product with QR Code into the database
        products_collection.insert_one({
            "name": product_name,
            "quantity": quantity,
            "weight": weight,
            "manufacturer": username,
            "qr_code": qr_code_base64  # Save the QR code base64 string
        })
        flash("Product added successfully!", "success")
        return redirect(url_for("manufacturer_dashboard"))

    # Fetch Manufacturer's Products, Pending Orders, and Transaction History
    products = list(products_collection.find({"manufacturer": username}))
    orders = list(orders_collection.find({"manufacturer": username, "status": "Pending"}))
    transactions = list(transactions_collection.find({"manufacturer": username}))

    return render_template("manufacturer_dashboard.html", products=products, orders=orders, transactions=transactions)

@app.route("/distributor_dashboard")
def distributor_dashboard():
    if "username" not in session or session["role"] != "Distributor":
        flash("You must log in as a Distributor to access this dashboard.", "error")
        return redirect(url_for("home"))

    username = session["username"]

    # Fetch all available products (excluding accepted orders)
    products = list(products_collection.find())

    filtered_products = []
    for product in products:
        existing_order = orders_collection.find_one({
            "product_name": product["name"],
            "distributor": username
        })
        if not existing_order or existing_order["status"] == "Rejected":
            product["status"] = "Available"
            filtered_products.append(product)

    # Fetch Distributor's Accepted Orders
    purchases = list(orders_collection.find({"distributor": username, "status": "Accepted"}))

    return render_template("distributor_dashboard.html", products=filtered_products, purchases=purchases)

# User dashboard
@app.route("/user_dashboard")
def user_dashboard():
    if "username" not in session or session.get("role") != "User":
        flash("You must log in as a User to access this dashboard.", "error")
        return redirect(url_for("home"))
    
    username = session["username"]
    user = users_collection.find_one({"username": username})
    return render_template("user_dashboard.html", profile=user)

# Manufacturer profile route
@app.route("/manufacturer_profile/<name>")
def manufacturer_profile(name):
    manufacturer = manufacturers_collection.find_one({"username": name})
    if manufacturer:
        return render_template("manufacturer_profile.html", manufacturer=manufacturer)
    flash("Manufacturer not found.", "error")
    return redirect(url_for("distributor_dashboard"))

# Place Order (Distributor)
@app.route("/place_order", methods=["POST"])
def place_order():
    if "username" not in session or session.get("role") != "Distributor":
        flash("You must log in as a Distributor to place orders.", "error")
        return redirect(url_for("home"))

    distributor = session["username"]
    product_id = request.form["product_id"]
    product = products_collection.find_one({"_id": ObjectId(product_id)})

    if product:
        order = {
            "product_name": product["name"],
            "manufacturer": product["manufacturer"],
            "distributor": distributor,
            "status": "Pending",
        }
        orders_collection.insert_one(order)
        flash("Order placed successfully!", "success")

    return redirect(url_for("distributor_dashboard"))

# Accept/Reject Order (Manufacturer)
@app.route("/update_order_status", methods=["POST"])
def update_order_status():
    order_id = request.form["order_id"]
    new_status = request.form["status"]

    order = orders_collection.find_one({"_id": ObjectId(order_id)})
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("manufacturer_dashboard"))

    orders_collection.update_one(
        {"_id": ObjectId(order_id)},
        {"$set": {"status": new_status}}
    )

    # If accepted, move order to transaction history
    if new_status == "Accepted":
        transactions_collection.insert_one(order)

    flash(f"Order status updated to {new_status}.", "success")
    return redirect(url_for("manufacturer_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
