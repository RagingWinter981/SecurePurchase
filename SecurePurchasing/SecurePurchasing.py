
import os
from flask import Flask, render_template, request, url_for, redirect, jsonify, make_response
import pypyodbc as odbc
import secrets
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from functools import wraps
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import random
import array
from datetime import datetime


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection configuration
DRIVER_NAME = 'SQL SERVER'
DATABASE_NAME = 'SecurePurchase'


# Kylee Connection String
# SERVER_NAME = 'LAPTOP-TT3C4QN9\SQLEXPRESS'
# connection_string = f"""
#   DRIVER={{{DRIVER_NAME}}};
#   SERVER={SERVER_NAME};
#   DATABASE={DATABASE_NAME};
#   Trust_Connection=yes;
#    uid=Kylee;
#   pwd=1234;
# """

# Albert Connection String
SERVER_NAME = 'ARIESPC'
connection_string = f"""
    DRIVER={{{DRIVER_NAME}}};
    SERVER={SERVER_NAME};
    DATABASE={DATABASE_NAME};
    Trust_Connection=yes;
     uid=Aeris;
    pwd=1234;
"""

# JJ's Connection String
#SERVER_NAME = 'LAPTOP-JP2PAISQ'
# connection_string = f"""
#     DRIVER={{{DRIVER_NAME}}};
#     SERVER={SERVER_NAME};
#     DATABASE={DATABASE_NAME};
#     Trust_Connection=yes;
#      uid=;
#     pwd=;
# """


#connecting to the DB
def connect_to_database():
    conn = odbc.connect(connection_string)
    return conn

# User class implementing UserMixin
class User(UserMixin):
    def __init__(self, user_id, role=None): #Using login session
        self.id = user_id
        self.role = role

    def has_role(self, role):    #Using Role
        return self.role == role

# Function to encrypt data AES-128 using cryptography
def encrypt_data(data):
    key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
    iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to decrypt data AES-128 using cryptography
def decrypt_data(ciphertext):
    key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
    iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

# Function to check user credentials
def check_credentials(username, password, userID):
    conn = connect_to_database()
    cursor = conn.cursor()

    query = f"SELECT * FROM LoginInfo WHERE Username = ? AND Password = ? AND UserID = ?"
    cursor.execute(query, (username, password, userID ))
    user_id = cursor.fetchone()
    conn.close()
    return user_id

def check_role(userID):
    conn = connect_to_database()
    cursor = conn.cursor()

    query = f"Select EmployeeType From Employees Where UserId = ?"
    cursor.execute(query, (userID, ))
    user_role = cursor.fetchone()
    conn.close()
    return user_role

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    User_type = check_role(user_id)

    if User_type:
        UserType = User_type[0]
        return User(user_id, role=UserType)
    

#Role required
def role_required(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            roles = role if isinstance(role, list) else [role]
            print(f"Required roles: {roles}")
            print(f"User role: {current_user.role}")
            
            # Check if user has at least one of the required roles
            if not any(current_user.has_role(r) for r in roles):
                return make_response({"msg": "Access forbidden: insufficient role"}, 403)
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/')
def login():
    return render_template('Login.html')

@app.route('/login_form', methods=['POST'])
def login_form():
   
    username = request.form.get('Username')
    password = request.form.get('password')
    ID = request.form.get('ID')

    user_info = check_credentials(username, password, ID)
    user_type = check_role(ID)
    if user_info and user_type:
        userID = user_info[0]
        userType = user_type[0]
        print(f"User role: {userType}")

        user = User(userID, role=userType)  # Initialize User with role
        login_user(user)

        if userType == "Employee":
             return redirect(url_for('employee'))
        elif ( userType == "Manager"):
            return redirect(url_for('manager'))
        elif (userType == "FinancialApprover"):
            return redirect(url_for('purchasingDept'))
        else:
            return render_template('purchasingDept.html', info='An error has occured')
        
    else:
        return render_template('Login.html', info='Invalid User or Password')


# Route to get the current user's ID
@app.route('/current_user_id')
def get_current_user_id():
    if current_user.is_authenticated:
        return f"Current user ID: {current_user.id}"
    else:
        return "No user logged in"


@app.route('/employee', methods=['GET', 'POST'])
@role_required(['Employee', 'Manager', 'FinancialApprover'])
@login_required
def employee():
    if request.method == 'POST':
        item = request.form.get('Item')
        price = request.form.get('Price')
        quantity = request.form.get('Quantity')
        requestID = random.randint(1000, 9999)
        employeeTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"Print Quantity", quantity, "Print Price", price)
        try:
            with odbc.connect(connection_string) as conn:
                cursor = conn.cursor()

                # Fetch the employee name using the current user's ID
                employee_query = "SELECT Employee, Manager FROM Employees WHERE UserId = ?"
                cursor.execute(employee_query, (current_user.id,))
                rows = cursor.fetchall()

                row = rows[0]

                # Extract the employee name and manager name from the row tuple
                employee = row[0]
                manager = row[1]

                # Encrypts each value using AES-128
                encrypt_item = encrypt_data(item)
                encrypt_price = encrypt_data(str(price))
                encrpt_quantity = encrypt_data(str(quantity))
                encrypt_requestID = encrypt_data(str(requestID))
                encrypt_employeeTimeRequest = encrypt_data(str(employeeTimeRequest))

                # Changes the value to hex to put into the database
                input_item = binascii.hexlify(encrypt_item).decode()
                input_price = binascii.hexlify(encrypt_price).decode()
                input_quantity = binascii.hexlify(encrpt_quantity).decode()
                input_requestID = binascii.hexlify(encrypt_requestID).decode()
                input_employeeTimeRequest = binascii.hexlify(encrypt_employeeTimeRequest).decode()

                query1 = (f"INSERT INTO Request (ReEmployee, Item, price, quantity, RequestID, employeeTimeRequest, managerName) VALUES (?, ?, ?, ?, ?, ?, ?)")
                cursor.execute(query1, (employee, input_item, input_price, input_quantity, input_requestID, input_employeeTimeRequest, manager))
                

                # Decrypt to verify
                decrypted_item = decrypt_data(binascii.unhexlify(input_item))
                decrypted_price = decrypt_data(binascii.unhexlify(input_price))
                decrypted_quantity = decrypt_data(binascii.unhexlify(input_quantity))
                decrypted_requestID = decrypt_data(binascii.unhexlify(input_requestID))
                decrypted_employeeTimeRequest = decrypt_data(binascii.unhexlify(input_employeeTimeRequest))

                print("Decrypted Item:", decrypted_item, "Decrypt Price: ", decrypted_price, "Decrypt Quantity: ", decrypted_quantity, "Decrypt, Request ID: ", decrypted_requestID, "Time Requested: ", decrypted_employeeTimeRequest)

                print(f"Executing query: {query1} with parameters: {(employee, input_item, input_price, input_quantity, input_requestID, input_employeeTimeRequest, manager)}")

                conn.commit()
                
                return redirect(url_for('employee'))

        except Exception as e:
            print(f"Error: {e}")
   
    return render_template('Employee.html')

@app.route('/manager')
@role_required('Manager')
@login_required
def manager():

    conn = connect_to_database()
    cursor = conn.cursor()
    RetrieveQuery = (f"SELECT ReEmployee, Item, price, quantity, RequestID, employeeTimeRequest FROM Request")
    cursor.execute(RetrieveQuery, ())
    ManagerInfo = cursor.fetchall()
    conn.close()

    encrypted_columns = [1, 2, 3, 4, 5]

    # Decrypt specific columns in the retrieved data
    decrypted_manager_info = []
    for row in ManagerInfo:
        decrypted_row = list(row)  # Convert tuple to list for modification
        
        # Only decrypt specified columns
        for col_index in encrypted_columns:
            if col_index < len(row):
                try:
                    # Convert hex string to bytes and decrypt
                    encrypted_bytes = binascii.unhexlify(str(row[col_index]))
                    decrypted_value = decrypt_data(encrypted_bytes)
                    decrypted_row[col_index] = decrypted_value
                except (binascii.Error, Exception) as e:
                    print(f"Decryption error for column {col_index}: {e}")
                    # Keep original value if decryption fails
                    continue

        decrypted_manager_info.append(tuple(decrypted_row))

    return render_template('Manager.html', ManagerInfo=decrypted_manager_info)

@app.route('/edit/<int:id>')
@login_required
@role_required('Manager')
def approve_item(id):

    managerTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = connect_to_database()
    cursor = conn.cursor()
    employee_query = "SELECT Employee, Manager FROM Employees WHERE UserId = ?"
    cursor.execute(employee_query, (current_user.id,))
    rows = cursor.fetchall()
    managerName = rows[0]


    conn = connect_to_database()
    cursor = conn.cursor()
    query = f"UPDATE Request SET managerName = ?, managerTimeStamp = ?, managerApprove = 'Approved' WHERE RequestID = ?"
    cursor.execute(query, (managerName,managerTimeRequest , id ))
    conn.close()
    
    return f'Approving item {id}'


# @app.route('/approve_item/<int:id>', methods=['POST'])
# @login_required
# @role_required('Manager')
# def approve_item(id):
#     if request.method == 'POST':
#         managerTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

#         # conn = connect_to_database()
#         # cursor = conn.cursor()
#         # employee_query = "SELECT Employee, Manager FROM Employees WHERE UserId = ?"
#         # cursor.execute(employee_query, (current_user.id,))
#         # rows = cursor.fetchone()
#         # managerName = rows[0]


#         # conn = connect_to_database()
#         # cursor = conn.cursor()
#         # query = "UPDATE Request SET managerName = ?, managerTimeStamp = ?, managerApprove = 'Approved' WHERE RequestID = ?"
#         # cursor.execute(query, (managerName,managerTimeRequest , id ))
#         # conn.commit()
#         # conn.close()
    
#     return redirect('/manager')

# @app.route('/deny_item/<int:id>', methods=['POST'])
# @login_required
# @role_required('Manager')
# def deny_item(id):
#     if request.method == 'POST':
#         managerTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

#         # conn = connect_to_database()
#         # cursor = conn.cursor()
#         # employee_query = "SELECT Employee, Manager FROM Employees WHERE UserId = ?"
#         # cursor.execute(employee_query, (current_user.id,))
#         # rows = cursor.fetchone()
#         # managerName = rows[0]


#         # conn = connect_to_database()
#         # cursor = conn.cursor()
#         # query = "UPDATE Request SET managerName = ?, managerTimeStamp = ?, managerApprove = 'Deny' WHERE RequestID = ?"
#         # cursor.execute(query, (managerName,managerTimeRequest , id ))
#         # conn.commit()
#         # conn.close()
    
#     return redirect('/manager')


@app.route('/purchasingDept')
@role_required('FinancialApprover')
def purchasingDept():
    return render_template('PurchasingDept.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    app.run(debug=True)
    








# # User class implementing UserMixin
# class User(UserMixin):
#     def __init__(self, user_id):
#         self.id = user_id

# # Function to check user credentials
# def check_credentials(username, password, ssn):
#     conn = connect_to_database()
#     cursor = conn.cursor()

#     encrypted_ssn = encrypt_data(ssn)
#     hex_encrypted_ssn = binascii.hexlify(encrypted_ssn).decode()

#     query = f"SELECT * FROM UserInfo WHERE fName = ? AND lName = ? AND ssn = ?"
#     cursor.execute(query, (username, password, hex_encrypted_ssn ))
#     user_id = cursor.fetchone()
#     conn.close()
#     return user_id

# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = "login"

# @login_manager.user_loader
# def load_user(user_id):
#     return User(user_id)

# def generate_validationNum():
#     #using secrets to generate 10 random pin
#     return ''.join(secrets.choice('0123456789') for _ in range(10))

# def decrypt_data(ciphertext):
#     key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
#     iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
#     unpadder = padding.PKCS7(128).unpadder()
#     unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
#     return unpadded_data.decode()

#     # Function to encrypt data
# def encrypt_data(data):
#     key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
#     iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     encryptor = cipher.encryptor()
#     padder = padding.PKCS7(128).padder()
#     padded_data = padder.update(data.encode()) + padder.finalize()
#     ciphertext = encryptor.update(padded_data) + encryptor.finalize()
#     return ciphertext

# @app.route('/')
# def login():
#     return render_template('login.html')

# @app.route('/login_form', methods=['POST'])
# def login_form():
# #    username = request.form.get('firstName')
# #    password = request.form.get('lastName')
# #    ssn = request.form.get('SSN')

#  #   user_id = check_credentials(username, password, ssn)
#   #  if user_id:
#    #     user = User(user_id)
#     #    login_user(user)
#      #   return redirect(url_for('home'))
#   #  else:
#    #     return render_template('login.html', info='Invalid User or Password')
#     username = request.form.get('firstName')
#     password = request.form.get('lastName')
#     ssn = request.form.get('SSN')

#     user_info = check_credentials(username, password, ssn)
#     if user_info:
#         user_id = user_info[0]  # Get the fifth item from the tuple (index starts from 0)
#         user = User(user_id)
#         login_user(user)
#         return redirect(url_for('home'))
#     else:
#         return render_template('login.html', info='Invalid User or Password')

# # Route to get the current user's ID
# @app.route('/current_user_id')
# def get_current_user_id():
#     if current_user.is_authenticated:
#         return f"Current user ID: {current_user.id}"
#     else:
#         return "No user logged in"

# @app.route('/home')
# @login_required
# def home():
#     return render_template('home.html')

# @app.route('/CLA')
# @login_required
# def CLA():
#     return render_template('CLApage.html')

# @app.route("/setCert", methods=["POST"])
# def setCert():
#     if request.method == "POST":
#         #save cert num to the database
#         validationNum = generate_validationNum()
#         encrypted_validation_number = encrypt_data(validationNum)

#         hex_encrypted_validation_number = binascii.hexlify(encrypted_validation_number).decode()

#         conn = connect_to_database()
#         cursor = conn.cursor()
#         query1 = f"Select verificationNumber FROM UserInfo WHERE verificationNumber = ?"
#         cursor.execute(query1, (hex_encrypted_validation_number, ))
#         numRow= len(cursor.fetchall())
#         print("Numbebr of valid num: ", numRow)
#         conn.commit() 
#         conn.close()

#         if(numRow == 0):

#             # Get the current user's details
#             user_id = current_user.id

#             conn = connect_to_database()
#             cursor = conn.cursor()
#             query1 = f"UPDATE UserInfo SET verificationNumber = ? WHERE ID = ? AND verificationNumber IS NULL"
#             cursor.execute(query1, (hex_encrypted_validation_number, str(user_id)))
#             print(user_id)
#             conn.commit() 
#             conn.close()

            
#             user_id = current_user.id
            
#             conn = connect_to_database()
#             cursor = conn.cursor()
#             getValid = f"Select verificationNumber FROM UserInfo WHERE ID = ? "
#             cursor.execute(getValid, (str(user_id),))
#             validationNum = cursor.fetchone()
#             conn.commit() 
#             conn.close()
#         else:
#             setCert()

#                     # Extract the encrypted validation number from the row
#         database_encrypted_validation_number = binascii.unhexlify(validationNum[0])

#         # Decrypt the validation number for display
#         decrypted_validation_number = decrypt_data(database_encrypted_validation_number)
             
#         return render_template('CLApage.html', validationNum=decrypted_validation_number)
#     else:
#         return render_template('CLApage.html')
    
# #JJ additions
# # to validate the votes before putting them into the CTF
# def validate_vote(validationNumber):
#     # Connect to the CLA database
#     connCLA = connect_to_database()
#     cursorCLA = connCLA.cursor()

#     # Query to check if the validationNumber exists in the UserInfo table
#     query = "SELECT COUNT(*) FROM UserInfo WHERE verificationNumber = ?"
#     cursorCLA.execute(query, (validationNumber,))

#     # Fetch the result to see if the validationNumber is present
#     result = cursorCLA.fetchone()
#     is_valid = result[0] > 0  # True if count is greater than 0, otherwise False

#     # Cleanup CLA database connections
#     cursorCLA.close()
#     connCLA.close()

#     # Return whether the validationNumber was found
#     return is_valid

# #the following function will be used to check if there's a duplicate for a vote in the CTF
# # if there's  a duplicate then the function returns 1 and the vote shouldn't be validated
# # Else it returns 0 and the vote should be validated
# def checkForDup(validationNum):
#     # Connect to the database
#     connCTF = connect_to_CTF_database()
#     cursorCTF = connCTF.cursor()

#     # Prepare the SQL query to check if the validation number is already in the Info table
#     query = "SELECT COUNT(*) FROM Info WHERE ValidationNum = ?"

#     # Execute the SQL query with parameter substitution to prevent SQL Injection
#     cursorCTF.execute(query, (validationNum,))

#     # Fetch the result
#     result = cursorCTF.fetchone()

#     # first element is the count obtained from the query
#     if result[0] > 0:
#         isValid = "False"  # Validation number exists in the database
#     else:
#         isValid = "True"  # Validation number does not exist in the database
   
#     cursorCTF.close()
#     connCTF.close()

#     return isValid
  
# def check_that_Everyone_Has_Voted():
#     connCTF = connect_to_CTF_database()
#     cursorCTF = connCTF.cursor()

#     connCLA = connect_to_database()
#     cursorCLA = connCLA.cursor()

#     # Query to check for any NULL or empty verification numbers in UserInfo
#     checkQuery = """
#     SELECT COUNT(*) FROM UserInfo 
#     WHERE verificationNumber IS NULL OR verificationNumber = ''
#     """
#     cursorCLA.execute(checkQuery)
    
#     # If the count is greater than 0, return False immediately
#     if cursorCLA.fetchone()[0] > 0:
#         cursorCLA.close()
#         connCLA.close()
#         cursorCTF.close()
#         connCTF.close()
#         return False
#     else:
#         #query to get all verificationNumbers from UserInfo
#         claQuery = "SELECT verificationNumber FROM UserInfo"
#         cursorCLA.execute(claQuery)

#         #loading results into an entire array
#         existingVerificationNumbers = {row[0] for row in cursorCLA.fetchall()}

#         # Fetch all validated numbers from CTF where IsValidated is true
#         cursorCTF.execute("SELECT ValidationNum FROM Info WHERE IsValidated = 'True'")
#         #loading all valid votes from table and just getting the verification number
#         voteValidationNumbers = {row[0] for row in cursorCTF.fetchall()}

#         #checking if all numbers of the CLA are in the CTF
#         EveryoneVoted = existingVerificationNumbers.issubset(voteValidationNumbers)

#         return EveryoneVoted

# def check_if_votes_have_been_tallied():
#     connCTF = connect_to_CTF_database()
#     cursorCTF = connCTF.cursor()

#     #Querying to see if any Tally is greater than 0
#     #Meaning that someone messed with the database
#     query = "SELECT COUNT(*) FROM Candidates WHERE Tally > 0"

#     cursorCTF.execute(query)
#     results = cursorCTF.fetchone()

#     if results[0] > 0:
#         return "True"
#     else:
#         return "False"

# @app.route('/showResults', methods=["POST"])
# def tabulateFinalResults():
#     areVotesTallied = check_if_votes_have_been_tallied()
#     hasEveryoneVoted = check_that_Everyone_Has_Voted()

#     if(areVotesTallied == "False"):
#         if(hasEveryoneVoted == True):
#             connCTF = connect_to_CTF_database()
#             cursorCTF = connCTF.cursor()

#             # Query to get valid votes and calculate total per candidate
#             vote_query = """
#                 SELECT Vote, COUNT(*) as VoteCount
#                 FROM Info
#                 WHERE isValidated = 'True'
#                 GROUP BY Vote
#             """
#             cursorCTF.execute(vote_query)
#             votes = cursorCTF.fetchall()
        
#             # Update candidates' tallies directly
#             update_query = """
#                 UPDATE Candidates
#                 SET Tally = ?
#                 WHERE ID = ?
#             """
#             # Prepare data for update
#             updates = [(vote[1], vote[0]) for vote in votes]
#             cursorCTF.executemany(update_query, updates)
#             connCTF.commit()

#             # Fetch updated candidate tallies
#             fetchTalliesQuery = "SELECT CandidateName, Tally FROM Candidates ORDER BY ID"
#             cursorCTF.execute(fetchTalliesQuery)
#             results = cursorCTF.fetchall()

#             # Fetch voter IDs and their voted candidates
#             voters_query = """
#                 SELECT i.IdentNum, c.CandidateName
#                 FROM Info i
#                 JOIN Candidates c ON i.Vote = c.ID
#                 WHERE i.isValidated = 'True'
#                 ORDER BY c.CandidateName
#             """
#             cursorCTF.execute(voters_query)
#             encrypted_voter_info = cursorCTF.fetchall()

#             # Decrypt voter IdentNums
#             # for voter in encrypted_voter_info: 
#             #     encrypted_IdentNum = binascii.unhexlify(voter[0])

#             voter_info = [(decrypt_data(binascii.unhexlify(voter[0])), voter[1]) for voter in encrypted_voter_info]

#             # Building the HTML output
#             output = "<h1>Vote Tally for Candidates</h1><table border='1'><tr><th>Candidate Name</th><th>Vote Tally</th></tr>"
#             for result in results:
#                 output += f"<tr><td>{result[0]}</td><td>{result[1]}</td></tr>"
#             output += "</table>"

#             output += "<h2>Voter Details</h2><table border='1'><tr><th>Identification Number</th><th>Voted for</th></tr>"
#             for voter in voter_info:
#                 output += f"<tr><td>{voter[0]}</td><td>{voter[1]}</td></tr>"
#             output += "</table>"
#             return output
#         else:
#             output = "<h1>Not everyone has voted please wait</h1>"
#         return output
#     elif (areVotesTallied == "True"):
#          # Fetch updated candidate tallies
#             fetchTalliesQuery = "SELECT CandidateName, Tally FROM Candidates ORDER BY ID"
#             connCTF = connect_to_CTF_database()
#             cursorCTF = connCTF.cursor()
#             cursorCTF.execute(fetchTalliesQuery)
#             results = cursorCTF.fetchall()

#             # Fetch voter IDs and their voted candidates
#             voters_query = """
#                 SELECT i.IdentNum, c.CandidateName
#                 FROM Info i
#                 JOIN Candidates c ON i.Vote = c.ID
#                 WHERE i.isValidated = 'True'
#                 ORDER BY c.CandidateName
#             """
#             cursorCTF.execute(voters_query)
#             encrypted_voter_info = cursorCTF.fetchall()

#             # Decrypt voter IdentNums
#             # for voter in encrypted_voter_info: 
#             #     encrypted_IdentNum = binascii.unhexlify(voter[0])

#             voter_info = [(decrypt_data(binascii.unhexlify(voter[0])), voter[1]) for voter in encrypted_voter_info]

#             # Building the HTML output
#             output = "<h1>Vote Tally for Candidates</h1><table border='1'><tr><th>Candidate Name</th><th>Vote Tally</th></tr>"
#             for result in results:
#                 output += f"<tr><td>{result[0]}</td><td>{result[1]}</td></tr>"
#             output += "</table>"

#             output += "<h2>Voter Details</h2><table border='1'><tr><th>Identification Number</th><th>Voted for</th></tr>"
#             for voter in voter_info:
#                 output += f"<tr><td>{voter[0]}</td><td>{voter[1]}</td></tr>"
#             output += "</table>"
#             return output
        
# @app.route('/CTF')
# @login_required
# def CTF():
#     return render_template('CTFpage.html')

# @app.route("/setPIN", methods=["POST"])
# def setPIN():
#     dupVote = "False"
#     validVote = "False"
#     isValidVerNum = False
#     if request.method == "POST":
#         userRandPIN = request.form["randomPIN"]
#         userValidnum = request.form["validNum"]
#         userVote= request.form["vote"]
        

#         encrypted_Identification_number = encrypt_data(userRandPIN)
#         encrypted_Verification_number = encrypt_data(userValidnum)
#         encrypted_Vote = encrypt_data(userVote)

#         hex_encrypted_Identification_number = binascii.hexlify(encrypted_Identification_number).decode()
#         hex_encrypted_Verification_number = binascii.hexlify(encrypted_Verification_number).decode()
#         hex_encrypted_Vote = binascii.hexlify(encrypted_Vote).decode()

#         # Get the current user's details
#         user_id = current_user.id

#         conn = connect_to_CTF_database()
#         cursor = conn.cursor()
#         query1 = f"SELECT * From Info Where IdentNum = ?"
#         cursor.execute(query1, (hex_encrypted_Identification_number, ))
#         NumOfRow = len(cursor.fetchall())
#         print("Number of IdentNum Rows: ",NumOfRow)
#         conn.commit() 
#         conn.close()
#         if(NumOfRow == 0):
#             #now checking if there's a duplicate verification number
#             isValidVerNum = validate_vote(hex_encrypted_Verification_number)
#             dupVote = checkForDup(hex_encrypted_Verification_number)
#             if((isValidVerNum == True) and (dupVote == "True") ):
#                 validVote = "True"

#             conn = connect_to_CTF_database()
#             cursor = conn.cursor()
#             query1 = f"INSERT INTO Info(IdentNum, ValidationNum, Vote, isValidated) VALUES (? , ?, ?, ?)"
#             cursor.execute(query1, (hex_encrypted_Identification_number, hex_encrypted_Verification_number, hex_encrypted_Vote, validVote))
#             NumOfRow=cursor.rowcount
            
#             print(user_id)
#             conn.commit()
#             conn.close()
#         else:

#             conn = connect_to_CTF_database()
#             cursor = conn.cursor()
#             CheckVote = f"SELECT * From Info Where IdentNum = ? AND ValidationNum = ?"
#             cursor.execute(CheckVote, (hex_encrypted_Identification_number, hex_encrypted_Verification_number))
#             NumOfRow = len(cursor.fetchall())
#             conn.commit()
#             print("Number of rows for Ident And Valid: ",NumOfRow)
#             conn.close()
#             if(NumOfRow > 0):
#                 print("Already Voted")

#             else:
#                 print("Idenification Number has already been choosen.")


        
#         #updating PIN where SSN is already set
#         #convertingrandomPIN just in case
#         return render_template('CTFpage.html', userRandPIN=userRandPIN)
#     else:
#         return render_template('CTFpage.html')
    
# @app.route("/logout")
# def logout():
#     logout_user()
#     return redirect('/')

