from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from flask_bcrypt import Bcrypt

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

# Manufacturer dashboard
@app.route("/manufacturer_dashboard", methods=["GET", "POST"])
def manufacturer_dashboard():
    if "username" not in session or session.get("role") != "Manufacturer":
        flash("You must log in as a Manufacturer to access this dashboard.", "error")
        return redirect(url_for("home"))
    
    username = session["username"]
    
    # Add product to database
    if request.method == "POST":
        product_name = request.form["product_name"]
        quantity = int(request.form["quantity"])
        weight = request.form["weight"]
        
        products_collection.insert_one({
            "name": product_name,
            "quantity": quantity,
            "weight": weight,
            "manufacturer": username
        })
        flash("Product added successfully!", "success")
        return redirect(url_for("manufacturer_dashboard"))

    # Fetch all products for the manufacturer
    products = products_collection.find({"manufacturer": username})
    return render_template("manufacturer_dashboard.html", products=products)

# Distributor dashboard
@app.route("/distributor_dashboard")
def distributor_dashboard():
    if "username" not in session or session.get("role") != "Distributor":
        flash("You must log in as a Distributor to access this dashboard.", "error")
        return redirect(url_for("home"))
    
    products = products_collection.find()
    return render_template("distributor_dashboard.html", products=products)

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

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
