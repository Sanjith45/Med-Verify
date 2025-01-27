from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["auth_app"]

# Function to print the collection names
def print_collection_names():
    # Get the collection names from the database
    collections = db.list_collection_names()
    print("Collections in the 'auth_app' database:")
    for collection in collections:
        print(collection)

if __name__ == "__main__":
    # Print collection names
    print_collection_names()
