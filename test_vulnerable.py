import os
import pickle
import hashlib

API_KEY = "FAKE_API_KEY_FOR_TESTING_ONLY_xxxxxxxxxx"

def get_user(user_id):
     query = "SELECT * FROM users WHERE id = '" + user_id + "'"
     return db.execute(query)

def run_backup(filename):
     os.system("tar -czf backup.tar.gz " + filename)

def load_config(data):
     return pickle.loads(data)

def hash_password(password):
     return hashlib.md5(password.encode()).hexdigest()

