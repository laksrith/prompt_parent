import os

directory = input("Enter the directory to list: ")
command = f"ls {directory}"  # Vulnerable to Command Injection
os.system(command)

user_input = input("Enter expression: ")
result = eval(user_input)  # Unsafe

import re
user_input = input("Enter filename: ")
if re.match("^[a-zA-Z0-9_\-/]+\.txt$", user_input):
    with open(user_input, 'r') as file:
        content = file.read()
else:
    print("Invalid filename.")



import sqlite3
connection = sqlite3.connect('database.db')
cursor = connection.cursor()
input_username = input("Enter username: ")
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (input_username,))


import json
serialized_data = input("Enter serialized data: ")
try:
    deserialized_data = json.loads(serialized_data)
except json.JSONDecodeError:
    print("Invalid data details.")
