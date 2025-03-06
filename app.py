from flask import Flask, render_template, request, redirect, url_for, session, flash
from web3 import Web3
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
import qrcode
import base64
from io import BytesIO
import json
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["auth_app"]

users_collection = db["users"]
manufacturers_collection = db["manufacturers"]
distributors_collection = db["distributors"]
products_collection = db["products"]
orders_collection = db["orders"]
transactions_collection = db["transactions"]

# Ethereum Blockchain Connection
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))
web3.eth.default_account = web3.eth.accounts[0]

# Smart Contract ABI and Address
contract_address = "0xd9145CCE52D386f254917e481eB44e9943F39138"
contract_abi =  [
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": True,
          "internalType": "uint256",
          "name": "id",
          "type": "uint256"
        },
        {
          "indexed": True,
          "internalType": "address",
          "name": "manufacturer",
          "type": "address"
        },
        {
          "indexed": True,
          "internalType": "address",
          "name": "distributor",
          "type": "address"
        }
      ],
      "name": "ProductAccepted",
      "type": "event"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": True,
          "internalType": "uint256",
          "name": "id",
          "type": "uint256"
        },
        {
          "indexed": True,
          "internalType": "address",
          "name": "distributor",
          "type": "address"
        }
      ],
      "name": "ProductRequested",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "productCounter",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "products",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "id",
          "type": "uint256"
        },
        {
          "internalType": "string",
          "name": "name",
          "type": "string"
        },
        {
          "internalType": "address",
          "name": "manufacturer",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "distributor",
          "type": "address"
        },
        {
          "internalType": "bool",
          "name": "isAccepted",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_name",
          "type": "string"
        }
      ],
      "name": "requestProduct",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_productId",
          "type": "uint256"
        }
      ],
      "name": "acceptRequest",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]  # Add your compiled contract ABI here
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    if "username" not in session or session.get("role") != "Manufacturer":
        flash("Unauthorized access.", "error")
        return redirect(url_for("home"))

    order_id = request.form["order_id"]
    order = orders_collection.find_one({"_id": ObjectId(order_id)})
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("manufacturer_dashboard"))

    product_id = order["product_id"]  # Assuming products have an ID
    try:
        tx_hash = contract.functions.acceptRequest(int(product_id)).transact({'from': web3.eth.default_account})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt.status == 1:  # Check if transaction was successful
            transactions_collection.insert_one({
                "product_name": order["product_name"],
                "manufacturer": order["manufacturer"],
                "distributor": order["distributor"],
                "status": "Accepted",
                "timestamp": str(time.time()),
                "tx_hash": tx_hash.hex()
            })
            flash("Transaction recorded successfully on Ethereum blockchain!", "success")
        else:
            flash("Blockchain transaction failed!", "error")
    except Exception as e:
        flash(f"Blockchain transaction error: {str(e)}", "error")

    return redirect(url_for("manufacturer_dashboard"))

@app.route("/blockchain", methods=["GET"])
def get_blockchain():
    return "Ethereum blockchain transactions stored via smart contract.", 200


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

    if request.method == "POST":
        product_name = request.form["product_name"]
        quantity = int(request.form["quantity"])
        weight = request.form["weight"]
        
        # Store the product in the database first to get the _id
        product_id = products_collection.insert_one({
            "name": product_name,
            "quantity": quantity,
            "weight": weight,
            "manufacturer": username
        }).inserted_id

        # Create QR Code Data
        qr_data = {
            "product_name": product_name,
            "quantity": quantity,
            "weight": weight,
            "manufacturer": username,
            "handoff_date": None,  # This will be updated when the transaction is confirmed
            "tx_hash": None,  # This will be updated later
            "product_id": str(product_id)
        }

        # Generate QR Code
        qr_json = json.dumps(qr_data)  # Convert dictionary to JSON string
        qr = qrcode.make(qr_json)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        # Update the product with the generated QR code
        products_collection.update_one(
            {"_id": product_id}, 
            {"$set": {"qr_code": qr_code_base64}}
        )

        flash("Product added successfully with a QR code!", "success")
        return redirect(url_for("manufacturer_dashboard"))

    products = list(products_collection.find({"manufacturer": username}))
    orders = list(orders_collection.find({"manufacturer": username}))
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
        orders_collection.insert_one(order)  # ✅ Store in orders_collection, not transactions_collection
        flash("Order placed successfully!", "success")


    return redirect(url_for("distributor_dashboard"))

# Accept/Reject Order (Manufacturer)
@app.route("/view_transactions", methods=["GET"])
def view_transactions():
    latest_block = web3.eth.block_number
    blockchain_transactions = []

    # Fetch last 10 blocks
    for i in range(latest_block, max(latest_block - 10, 0), -1):
        block = web3.eth.get_block(i, full_transactions=True)
        for tx in block.transactions:
            blockchain_transactions.append({
                "hash": tx.hash.hex(),
                "from": tx["from"],
                "to": tx["to"],
                "value": web3.from_wei(tx["value"], "ether"),
                "block": tx["blockNumber"],
            })

    # Fetch transactions from MongoDB
    db_transactions = list(transactions_collection.find())

    # Merge MongoDB transactions with blockchain transactions
    merged_transactions = []
    for db_tx in db_transactions:
        tx_hash = db_tx.get("tx_hash", "Not on Blockchain")
        eth_tx = next((tx for tx in blockchain_transactions if tx["hash"] == tx_hash), None) if tx_hash != "Not on Blockchain" else None

        merged_transactions.append({
            "hash": tx_hash,
            "manufacturer": db_tx["manufacturer"],
            "distributor": db_tx["distributor"],
            "product_name": db_tx["product_name"],
            "status": db_tx["status"],
            "value": eth_tx["value"] if eth_tx else "N/A",
            "block": eth_tx["block"] if eth_tx else "N/A",
        })



    return render_template("blockchain_transactions.html", transactions=merged_transactions)

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

    if new_status == "Accepted":
        try:
            product = products_collection.find_one({"name": order["product_name"], "manufacturer": order["manufacturer"]})
            if not product:
                flash("Product not found in database.", "error")
                return redirect(url_for("manufacturer_dashboard"))

            product_id = str(product["_id"])
            int_product_id = int(product_id[:8], 16)

            tx_hash = contract.functions.acceptRequest(int_product_id).transact({'from': web3.eth.default_account})
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.status == 1:  
                order.pop("_id", None)
                order["tx_hash"] = tx_hash.hex()
                order["status"] = "Accepted"
                order["handoff_date"] = time.strftime("%Y-%m-%d %H:%M:%S")

                transactions_collection.insert_one(order)

                # Update QR Code with transaction details
                qr_data = {
                    "product_name": order["product_name"],
                    "quantity": product["quantity"],
                    "weight": product["weight"],
                    "manufacturer": product["manufacturer"],
                    "distributor": order["distributor"],
                    "handoff_date": order["handoff_date"],
                    "tx_hash": tx_hash.hex(),
                    "product_id": product_id
                }

                qr_json = json.dumps(qr_data)
                qr = qrcode.make(qr_json)
                buffered = BytesIO()
                qr.save(buffered, format="PNG")
                qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

                products_collection.update_one(
                    {"_id": product["_id"]},
                    {"$set": {"qr_code": qr_code_base64}}
                )

                flash("Transaction recorded and QR updated!", "success")
            else:
                flash("Blockchain transaction failed!", "error")
        except Exception as e:
            flash(f"Blockchain transaction error: {str(e)}", "error")

    flash(f"Order status updated to {new_status}.", "success")
    return redirect(url_for("manufacturer_dashboard"))

from bson.errors import InvalidId

@app.route("/scan_qr/<product_id>", methods=["GET"])
def scan_qr(product_id):
    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})
    except InvalidId:
        return "Invalid Product ID", 400  # Return a Bad Request error

    if not product:
        return "Product not found", 404

    return render_template("qr_details.html", product=product)

if __name__ == "__main__":
    app.run(debug=True)

