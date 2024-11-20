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
import smtplib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#using for RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as paddingRSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import base64

sender = "juanjoguti2020@gmail.com"

app_password = 'vndnghrvqredwkim'

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

# # Albert Connection String
# SERVER_NAME = 'ARIESPC'
# connection_string = f"""
#     DRIVER={{{DRIVER_NAME}}};
#     SERVER={SERVER_NAME};
#     DATABASE={DATABASE_NAME};
#     Trust_Connection=yes;
#      uid=Aeris;
#     pwd=1234;
# """

# JJ's Connection String
SERVER_NAME = 'LAPTOP-JP2PAISQ'
connection_string = f"""
    DRIVER={{{DRIVER_NAME}}};
    SERVER={SERVER_NAME};
    DATABASE={DATABASE_NAME};
    Trust_Connection=yes;
     uid=;
    pwd=;
"""


def send_email(subject, body, sender, recipients, password):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
       smtp_server.login(sender, password)
       smtp_server.sendmail(sender, recipients, msg.as_string())
    print("Message sent!")

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
    Enc_type = check_role(user_id)

    # Decrypt User_type
    User_type = decrypt_data(binascii.unhexlify(Enc_type[0]))

    if User_type:
        UserType = User_type
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

    encrypted_username = encrypt_data(str(username))
    encrypted_password = encrypt_data(str(password))
    encrypted_ID = encrypt_data(str(ID))

    # convert to hex using hexify and decode
    hex_username = binascii.hexlify(encrypted_username).decode()
    hex_password = binascii.hexlify(encrypted_password).decode()
    hex_ID = binascii.hexlify(encrypted_ID).decode()

    user_info = check_credentials(hex_username, hex_password, hex_ID)
    user_type = check_role(hex_ID)

    if user_info and user_type:
        userID = user_info[0]
        encrypted_userType = user_type[0]

        userType = decrypt_data(binascii.unhexlify(encrypted_userType))
        print("UserType: ", userType)

        user = User(userID, role=userType)  
        login_user(user)

        print("Test again: ", userType)

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


#submitting req for both emp and mgr - remember a mgr aproval goes to financial dpt
@app.route('/employee', methods=['GET', 'POST'])
@role_required(['Employee', 'Manager', 'FinancialApprover'])
@login_required
#add signature here for employee
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

                # Extract the employee name and manager name from the row tuple
                employee = rows[0][0]
                manager = rows[0][1]

                employeeDecrypted = decrypt_data( binascii.unhexlify(rows[0][0]) )

                # retrieving manager email and then crafting email to be sent for them
                emailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
                cursor.execute(emailQuery,(manager,))
                rows = cursor.fetchall()

                #must test in Albert's machine
                mgrEmail = decrypt_data( binascii.unhexlify(rows[0][0]) )

                #craft email
                eSubject = f"Incoming Order Request for approval ID: {requestID}"
                body = (
                    f"Employee: {employeeDecrypted} with ID: {decrypt_data(binascii.unhexlify(current_user.id))}, has requested the following:"
                    f"\n Item: {item}" 
                    f"\n Price: {str(price)} \n "
                    f"Quantity: {quantity} \n " 
                    f"time requested: {employeeTimeRequest} \n "
                    f"Please log into the application to review."    
                )
                recipient = mgrEmail

                #sending email
                send_email(eSubject,body, sender, recipient, app_password)

                #sending email to employee
                # retrieving emp email and then crafting email to be sent for them
                emailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
                cursor.execute(emailQuery,(employee,))
                rows = cursor.fetchall()

                empEmail = decrypt_data(binascii.unhexlify(rows[0][0]))

                #craft email
                eSubject = f"Order ID: {requestID} has been submitted for approval"
                body = (
                    f"Employee: {employeeDecrypted} with ID: {decrypt_data(binascii.unhexlify(current_user.id))}, has requested the following:"
                    f"\n Item: {item}" 
                    f"\n Price: {str(price)} \n "
                    f"Quantity: {quantity} \n " 
                    f"time requested: {employeeTimeRequest} \n "
                    f"Please log into the application to review."    
                )
                recipient = empEmail

                #sending email
                send_email(eSubject,body, sender, recipient, app_password)



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

                #signing the request
                reqSignature = employeeDecrypted + item + str(price) + str(quantity) + str(employeeTimeRequest)

                messageToSign = reqSignature.encode('UTF-8')

                #fetching Private key to sign
                retrieveQuery = "SELECT PrivateKey FROM Employees WHERE Employee = ?"
                cursor.execute(retrieveQuery, (employee, ))
                rows = cursor.fetchall()

                rtrPrvKey = rows [0][0]
                #retrieving private key
                prvBytes = base64.b64decode(rtrPrvKey)
                recprvBytes = serialization.load_pem_private_key(
                              prvBytes,
                              password=None,
                              backend=default_backend()
                              )
                #getting signature
                signature = recprvBytes.sign(
                            messageToSign,
                            paddingRSA.PSS(
                                mgf=paddingRSA.MGF1(hashes.SHA256()),
                                salt_length=paddingRSA.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())
                #encoding to base 64 to add to DB
                signatureBase64 = base64.b64encode(signature).decode('UTF-8')


                #
                query1 = (f"INSERT INTO Request (ReEmployee, Item, price, quantity, RequestID, employeeTimeRequest, managerName, employeeSignature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                cursor.execute(query1, (employee, input_item, input_price, input_quantity, input_requestID, input_employeeTimeRequest, manager, signatureBase64))
                

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

@app.route('/managerSubmit', methods=['GET', 'POST'])
@role_required(['Manager'])
@login_required
#add signature in here for employee lol on mgr type
def managerSubmit():
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

                empNameDec = decrypt_data( binascii.unhexlify(rows[0][0]) )

                #extracting emails
                # retrieving emp email and then crafting email to be sent for them
                emailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
                cursor.execute(emailQuery,(employee,))
                rows = cursor.fetchall()

                empEmail = decrypt_data(binascii.unhexlify(rows[0][0]))

                #craft email
                eSubject = f"Order ID: {requestID} has been submitted for approval from finance department"
                body = (
                    f"Employee: {empNameDec} with ID: {decrypt_data(binascii.unhexlify(current_user.id))}, has requested the following:"
                    f"\n Item: {item}" 
                    f"\n Price: {str(price)} \n "
                    f"Quantity: {quantity} \n " 
                    f"time requested: {employeeTimeRequest} \n "
                    f"Please log into the application to review."    
                )
                recipient = empEmail

                #sending email
                send_email(eSubject,body, sender, recipient, app_password)


                # retrieving manager email and then crafting email to be sent for them
                emailQuery = "SELECT Email FROM Employees WHERE EmployeeType = 'c7e617bbe021a2bf2bf1c2b7613bd0aa620c4741028bd01e8d6718037f83dd28'"
                cursor.execute(emailQuery)
                rows = cursor.fetchall()
                

                #must test in Albert's machine
                finEmail = decrypt_data( binascii.unhexlify(rows[0][0]) )

                #craft email
                eSubject = f"Incoming Manager Order Request for approval ID: {requestID}"
                body = (
                    f"Employee ID: {current_user.id}, has requested the following:"
                    f"\n Item: {item}" 
                    f"\n Price: {str(price)} \n "
                    f"Quantity: {quantity} \n " 
                    f"time requested: {employeeTimeRequest} \n "
                    f"Please log into the application to review."    
                )
                recipient = [finEmail]

                #sending email
                send_email(eSubject,body, sender, recipient, app_password)
                #email part stop

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

                #signing the request
                reqSignature = empNameDec + item + str(price) + str(quantity) + str(employeeTimeRequest)

                messageToSign = reqSignature.encode('UTF-8')

                #fetching Private key to sign
                retrieveQuery = "SELECT PrivateKey FROM Employees WHERE Employee = ?"
                cursor.execute(retrieveQuery, (employee, ))
                rows = cursor.fetchall()

                rtrPrvKey = rows [0][0]
                #retrieving private key
                prvBytes = base64.b64decode(rtrPrvKey)
                recprvBytes = serialization.load_pem_private_key(
                              prvBytes,
                              password=None,
                              backend=default_backend()
                              )
                #getting signature
                signature = recprvBytes.sign(
                            messageToSign,
                            paddingRSA.PSS(
                                mgf=paddingRSA.MGF1(hashes.SHA256()),
                                salt_length=paddingRSA.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())
                #encoding to base 64 to add to DB
                signatureBase64 = base64.b64encode(signature).decode('UTF-8')

                query1 = (f"INSERT INTO Request (ReEmployee, Item, price, quantity, RequestID, employeeTimeRequest, managerName, employeeSignature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                cursor.execute(query1, (employee, input_item, input_price, input_quantity, input_requestID, input_employeeTimeRequest, manager, signatureBase64))
                

                # Decrypt to verify
                decrypted_item = decrypt_data(binascii.unhexlify(input_item))
                decrypted_price = decrypt_data(binascii.unhexlify(input_price))
                decrypted_quantity = decrypt_data(binascii.unhexlify(input_quantity))
                decrypted_requestID = decrypt_data(binascii.unhexlify(input_requestID))
                decrypted_employeeTimeRequest = decrypt_data(binascii.unhexlify(input_employeeTimeRequest))

                print("Decrypted Item:", decrypted_item, "Decrypt Price: ", decrypted_price, "Decrypt Quantity: ", decrypted_quantity, "Decrypt, Request ID: ", decrypted_requestID, "Time Requested: ", decrypted_employeeTimeRequest)

                print(f"Executing query: {query1} with parameters: {(employee, input_item, input_price, input_quantity, input_requestID, input_employeeTimeRequest, manager)}")

                conn.commit()
                
                return redirect(url_for('managerSubmit'))

        except Exception as e:
            print(f"Error: {e}")
   
    return render_template('managerSubmit.html')


@app.route('/manager')
@role_required('Manager')
@login_required
def manager():

    conn = connect_to_database()
    cursor = conn.cursor()
    RetrieveQuery = (f"SELECT ReEmployee, Item, price, quantity, employeeTimeRequest, RequestID FROM Request WHERE managerApprove IS NULL AND ReEmployee IN (Select Employee From Employees where UserId = ? OR Employee in (Select e.Employee From Employees as e, Employees as s Where s.Employee = e.Manager AND s.UserId = ?))")
    cursor.execute(RetrieveQuery, (current_user.id, current_user.id))
    ManagerInfo = cursor.fetchall()
    conn.close()

    encrypted_columns = [0, 1, 2, 3, 4, 5]

    # Decrypt specific columns in the retrieved data
    decrypted_manager_info = []
    for row in ManagerInfo:
        decrypted_row = list(row)  # Convert tuple to list for modification
        
        # Only decrypt specified columns
        for col_index in encrypted_columns:
            if col_index < len(row):
                # Convert hex string to bytes and decrypt
                encrypted_bytes = binascii.unhexlify(str(row[col_index]))
                decrypted_value = decrypt_data(encrypted_bytes)
                decrypted_row[col_index] = decrypted_value

        decrypted_manager_info.append(tuple(decrypted_row))


    conn = connect_to_database()
    cursor = conn.cursor()
    RetrieveResultQuery = (f"SELECT ReEmployee, Item, price, quantity, employeeTimeRequest, RequestID, managerApprove, managerTimeStamp FROM Request WHERE managerApprove IS NOT NULL AND ReEmployee IN (Select Employee From Employees where UserId = ? OR Employee in (Select e.Employee From Employees as e, Employees as s Where s.Employee = e.Manager AND s.UserId = ?))")
    cursor.execute(RetrieveResultQuery, (current_user.id, current_user.id))
    ManagerResult = cursor.fetchall()
    conn.close()

    encrypted_columns = [0, 1, 2, 3, 4, 5, 6, 7]

    # Decrypt specific columns in the retrieved data
    decrypted_manager_result = []
    for row in ManagerResult:
        decrypted_row = list(row)  # Convert tuple to list for modification
        
        # Only decrypt specified columns
        for col_index in encrypted_columns:
            if col_index < len(row):
                # Convert hex string to bytes and decrypt
                encrypted_bytes = binascii.unhexlify(str(row[col_index]))
                decrypted_value = decrypt_data(encrypted_bytes)
                decrypted_row[col_index] = decrypted_value

        decrypted_manager_result.append(tuple(decrypted_row))

    return render_template('Manager.html', ManagerInfo=decrypted_manager_info, ManagerResult= decrypted_manager_result)

#JJ has to mess with this one and the deny one to send emails for when managers approve or deny lol
#add signature in here for mgr only tho
@app.route('/approve_item/<string:id>', methods=['POST'])
@login_required
@role_required('Manager')
def approve_item(id):
    if request.method == 'POST':
        managerTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        encrypt_ID = encrypt_data(id)
        hex_ID = binascii.hexlify(encrypt_ID).decode()
        encrypt_managerTimeRequest = encrypt_data(str(managerTimeRequest))
        hex_managerTimeRequest = binascii.hexlify(encrypt_managerTimeRequest).decode()

        conn = connect_to_database()
        cursor = conn.cursor()

        employee_query = "SELECT Employee, PrivateKey FROM Employees WHERE UserId = ?"
        cursor.execute(employee_query, (current_user.id,))
        rows = cursor.fetchall()
        managerName = rows[0][0]

        rtrPrvKey = rows[0][1]
        #retrieving private key
        prvBytes = base64.b64decode(rtrPrvKey)
        recprvBytes = serialization.load_pem_private_key(
                              prvBytes,
                              password=None,
                              backend=default_backend()
                              )
        
        req_query = "SELECT ReEmployee, Item, price, employeeTimeRequest, quantity FROM Request WHERE RequestID = ?"
        cursor.execute(req_query, (hex_ID,))
        rows = cursor.fetchall()

        reqEmpName = rows[0][0]
        item = rows[0][1]
        price = rows[0][2]
        employeeTimeRequest = rows[0][3]
        quantity = rows[0][4]

        decEmpName = decrypt_data(binascii.unhexlify(reqEmpName))
        itemDec = decrypt_data(binascii.unhexlify(item))
        priceDec = decrypt_data(binascii.unhexlify(price))
        timeDec = decrypt_data(binascii.unhexlify(employeeTimeRequest))
        quantityDec = decrypt_data(binascii.unhexlify(quantity))

        #signing the request
        reqSignature = decEmpName + itemDec + priceDec + quantityDec + timeDec

        messageToSign = reqSignature.encode('UTF-8')

        #getting signature
        signature = recprvBytes.sign(
                            messageToSign,
                            paddingRSA.PSS(
                                mgf=paddingRSA.MGF1(hashes.SHA256()),
                                salt_length=paddingRSA.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())
                #encoding to base 64 to add to DB
        signatureBase64 = base64.b64encode(signature).decode('UTF-8')


        encrypt_managerName = encrypt_data(managerName)
        hex_managerName = binascii.hexlify(encrypt_managerName).decode()
        print(current_user.id)
        print(managerName)

        encrypt_Approve = encrypt_data("Approved")
        hex_approve = binascii.hexlify(encrypt_Approve).decode()        
        
        #inserting extra info with signature
        query = "UPDATE Request SET managerTimeStamp = ?, managerApprove = ?, managerSignature = ? WHERE RequestID = ?"
        cursor.execute(query, (hex_managerTimeRequest, hex_approve, signatureBase64, hex_ID, ))

        #send email in here buddy
        #extracting email
        # emailing fin dept
        emailQuery = "SELECT Email FROM Employees WHERE EmployeeType = 'c7e617bbe021a2bf2bf1c2b7613bd0aa620c4741028bd01e8d6718037f83dd28'"
        cursor.execute(emailQuery)
        rows = cursor.fetchall()

        #must test in Albert's machine
        finEmail = decrypt_data( binascii.unhexlify(rows[0][0]) )

        ReqQuery = "SELECT ReEmployee, item, price, employeeTimeRequest, quantity FROM Request WHERE RequestID = ?"
        cursor.execute(ReqQuery, (hex_ID, ))
        rows = cursor.fetchall()

         # albert's style
        EmployeeName = rows[0][0]
        item = rows[0][1]
        price = rows[0][2]
        empSubmitTime = rows[0][3]
        quantity = rows[0][4]
        #decrypted tell me if Im retarded
        empNameDec = decrypt_data(binascii.unhexlify(EmployeeName))
        itemDec = decrypt_data(binascii.unhexlify(item))
        priceDec = decrypt_data(binascii.unhexlify(price))
        empSubmitTimeDec = decrypt_data(binascii.unhexlify(empSubmitTime))
        quantityDec = decrypt_data(binascii.unhexlify(quantity))

        #craft email to fin
        eSubject = f"Order: {id} has been approved by a manager"
        body = (
        f"\nManager: {decrypt_data(binascii.unhexlify(managerName))} "
        f"\nTime approved: {managerTimeRequest}"
        f"\nItem: {itemDec}" 
        f"\n Price: {priceDec} \n "
        f"Quantity: {quantityDec} \n " 
        f"time requested: {empSubmitTimeDec} \n "
        f"Employee that requested it: {empNameDec} \n"
        f"Please log into the application to review."    
        )
        recipient = finEmail

        #sending email
        send_email(eSubject,body, sender, recipient, app_password)

        empEmailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
        cursor.execute(empEmailQuery, (EmployeeName, ))
        rows = cursor.fetchall()

        #albert
        empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))

        eSubject = f" Your Order: {id} has been approved by a manager"
        body = (
        f"\nManager: {decrypt_data(binascii.unhexlify(managerName))} "
        f"\nTime approved: {managerTimeRequest}"
        f"\nItem: {itemDec}" 
        f"\n Price: {priceDec} \n "
        f"Quantity: {quantityDec} \n " 
        f"time requested: {empSubmitTimeDec} \n "
        f"Please log into the application to review."    
        )

        recipient = empEmailaddDec

        send_email(eSubject,body, sender, recipient, app_password)

        conn.commit()
        conn.close()
    
    return redirect('/manager')

@app.route('/deny_item/<string:id>', methods=['POST'])
@login_required
@role_required('Manager')
def deny_item(id):
    if request.method == 'POST':
        managerTimeRequest = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        encrypt_ID = encrypt_data(id)
        hex_ID = binascii.hexlify(encrypt_ID).decode()
        encrypt_managerTimeRequest = encrypt_data(str(managerTimeRequest))
        hex_managerTimeRequest = binascii.hexlify(encrypt_managerTimeRequest).decode()

        conn = connect_to_database()
        cursor = conn.cursor()
        employee_query = "SELECT Employee, Manager FROM Employees WHERE UserId = ?"
        cursor.execute(employee_query, (current_user.id,))
        rows = cursor.fetchall()
        managerName = rows[0][0]

        encrypt_managerName = encrypt_data(managerName)
        hex_managerName = binascii.hexlify(encrypt_managerName).decode()
        print(current_user.id)
        print(managerName)

        encrypt_Deny = encrypt_data("Deny")
        hex_Deny = binascii.hexlify(encrypt_Deny).decode() 

        conn = connect_to_database()
        cursor = conn.cursor()
        query = "UPDATE Request SET managerTimeStamp = ?, managerApprove = ? WHERE RequestID = ?"
        cursor.execute(query, (hex_managerTimeRequest, hex_Deny , hex_ID))

        ReqQuery = "SELECT ReEmployee, item, price, employeeTimeRequest, quantity FROM Request WHERE RequestID = ?"
        cursor.execute(ReqQuery, (hex_ID, ))
        rows = cursor.fetchall()

         # albert's style
        EmployeeName = rows[0][0]
        item = rows[0][1]
        price = rows[0][2]
        empSubmitTime = rows[0][3]
        quantity = rows[0][4]
        #decrypted tell me if Im retarded
        empNameDec = decrypt_data(binascii.unhexlify(EmployeeName))
        itemDec = decrypt_data(binascii.unhexlify(item))
        priceDec = decrypt_data(binascii.unhexlify(price))
        empSubmitTimeDec = decrypt_data(binascii.unhexlify(empSubmitTime))
        quantityDec = decrypt_data(binascii.unhexlify(quantity))

        empEmailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
        cursor.execute(empEmailQuery, (EmployeeName, ))
        rows = cursor.fetchone()

        print("\n Email Fetched:\n")
        print(rows)

        #albert
        empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0]))

        eSubject = f" Your Order: {id} has been denied by a manager"
        body = (
        f"Manager: {decrypt_data(binascii.unhexlify(managerName))} "
        f"Time denied: {managerTimeRequest}"
        f"Item: {itemDec}" 
        f"\n Price: {priceDec} \n "
        f"Quantity: {quantityDec} \n " 
        f"time requested: {empSubmitTimeDec} \n "
        f"Please log into the application to review."    
        )

        recipient = empEmailaddDec

        send_email(eSubject,body, sender, recipient, app_password)



        conn.commit()
        conn.close()
    
    return redirect('/manager')


@app.route('/purchasingDept')
@role_required('FinancialApprover')
def purchasingDept():
    conn = connect_to_database()
    cursor = conn.cursor()
    RetrieveQuery = (f"SELECT ReEmployee, Item, price, quantity, employeeTimeRequest, managerName, managerApprove, managerTimeStamp, RequestID FROM Request Where IsPurchased IS NULL AND managerApprove IS NOT NULL")
    cursor.execute(RetrieveQuery, ())
    FinAppInfo = cursor.fetchall()
    conn.close()

    encrypted_columns = [0, 1, 2, 3, 4, 5, 6, 7, 8]

    # Decrypt specific columns in the retrieved data
    decrypted_FinApp_info = []
    for row in FinAppInfo:
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
                    # Keep original value
                    continue

        decrypted_FinApp_info.append(tuple(decrypted_row))


    conn = connect_to_database()
    cursor = conn.cursor()
    RetrieveResultsQuery = (f"SELECT ReEmployee, Item, price, quantity, employeeTimeRequest, managerName, managerApprove, managerTimeStamp, RequestID, IsPurchased FROM Request Where IsPurchased IS NOT NULL")
    cursor.execute(RetrieveResultsQuery, ())
    FinAppResult = cursor.fetchall()
    conn.close()

    encrypted_columns = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    # Decrypt specific columns in the retrieved data
    decrypted_FinApp_Result= []
    for row in FinAppResult:
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
                    # Keep original value
                    continue

        decrypted_FinApp_Result.append(tuple(decrypted_row))

    return render_template('PurchasingDept.html', FinAppInfo=decrypted_FinApp_info, FinAppFinal=decrypted_FinApp_Result)

#email noti in here and the bottom for financial approver
@app.route('/Purchase_item/<string:id>', methods=['POST'])
@login_required
@role_required('FinancialApprover')
def purchase_item(id):
    if request.method == 'POST':

        encrypt_ID = encrypt_data(id)
        hex_ID = binascii.hexlify(encrypt_ID).decode()

        encrypt_Approve = encrypt_data("Purchased")
        hex_approve = binascii.hexlify(encrypt_Approve).decode()        

        conn = connect_to_database()
        cursor = conn.cursor()


        #start of jjs emails

        checkIfMgrQuery ="SELECT managerName FROM Request WHERE RequestID = ?"
        cursor.execute(checkIfMgrQuery,(hex_ID, ))
        rows = cursor.fetchone()
        
        if rows:
            mgrName = rows[0]
            ReqQuery = "SELECT ReEmployee, item, price, employeeTimeRequest, quantity, managerTimeStamp FROM Request WHERE RequestID = ?"
            cursor.execute(ReqQuery, (hex_ID, ))
            rows = cursor.fetchall()

         # albert's style
            EmployeeName = rows[0][0]
            item = rows[0][1]
            price = rows[0][2]
            empSubmitTime = rows[0][3]
            quantity = rows[0][4]
            mgrTimeStamp = rows[0][5]
        #decrypted tell me if Im retarded
            empNameDec = decrypt_data(binascii.unhexlify(EmployeeName))
            itemDec = decrypt_data(binascii.unhexlify(item))
            priceDec = decrypt_data(binascii.unhexlify(price))
            empSubmitTimeDec = decrypt_data(binascii.unhexlify(empSubmitTime))
            quantityDec = decrypt_data(binascii.unhexlify(quantity))
            mgrTimeStampDec = decrypt_data(binascii.unhexlify(mgrTimeStamp))

            #crafting email and retrieving public keys
            empEmailQuery = "SELECT Email, PublicKey FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (EmployeeName, ))
            rows = cursor.fetchall()

        #albert
            empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))
            rtrPubKeyEmp = rows[0][1]

            #crafting email
            empEmailQuery = "SELECT Email, PublicKey FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (mgrName, ))
            rows = cursor.fetchall()

            mgrEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))
            rtrPubKeyMgr = rows[0][1]

            #generating public key objects
            pubBytesEmp = base64.b64decode(rtrPubKeyEmp)
            pubBytesMgr = base64.b64decode(rtrPubKeyMgr)

            recpubBytesEmp = serialization.load_pem_public_key(
            pubBytesEmp,
            backend=default_backend()
            )

            recpubBytesMgr = serialization.load_pem_public_key(
            pubBytesMgr,
            backend=default_backend()
            )

            #pub key objects have been generated now verifying signatures (both must be verified)
            req_query = "SELECT ReEmployee, Item, price, employeeTimeRequest, employeeSignature, managerSignature FROM Request WHERE RequestID = ?"
            cursor.execute(req_query, (hex_ID,))
            rows = cursor.fetchall()

            reqEmpName = rows[0][0]
            item = rows[0][1]
            price = rows[0][2]
            employeeTimeRequest = rows[0][3]
            empSignBase64 = rows[0][4]
            mgrSignBase64 = rows[0][5]

            decEmpName = decrypt_data(binascii.unhexlify(reqEmpName))
            itemDec = decrypt_data(binascii.unhexlify(item))
            priceDec = decrypt_data(binascii.unhexlify(price))
            timeDec = decrypt_data(binascii.unhexlify(employeeTimeRequest))

            empSign= base64.b64decode(empSignBase64)
            mgrSign= base64.b64decode(mgrSignBase64)



            #getting message for signature
            reqSignature = decEmpName + itemDec + priceDec + quantityDec + timeDec

            messageToSign = reqSignature.encode('UTF-8')

            #verifying both signatures: 
            valid_signature_emp = False
            try:
                recpubBytesEmp.verify(
                    empSign,
                    messageToSign,
                    paddingRSA.PSS(
                        mgf=paddingRSA.MGF1(hashes.SHA256()),
                        salt_length=paddingRSA.PSS.MAX_LENGTH
                                ),
                                 hashes.SHA256()
                                )

                valid_signature_emp = True
                print("The employee signature is valid.")
            except Exception as e:
                valid_signature_emp = False
                print(f"An error occurred emp sign invalid: {e}")
            
            valid_signature_mgr = False
            try:
                recpubBytesMgr.verify(
                    mgrSign,
                    messageToSign,
                    paddingRSA.PSS(
                        mgf=paddingRSA.MGF1(hashes.SHA256()),
                        salt_length=paddingRSA.PSS.MAX_LENGTH
                                ),
                                 hashes.SHA256()
                                )

                valid_signature_mgr = True
                print("The manager signature is valid.")
            except Exception as e:
                valid_signature_mgr = False
                print(f"An error occurred mgr sign invalid: {e}")
            


            if( valid_signature_mgr and valid_signature_emp): 
                eSubject = f"Order: {id} has been completely approved"
                body = (
                   f"\nManager: {decrypt_data(binascii.unhexlify(mgrName))} "
                   f"\nManager Time approved: {mgrTimeStampDec}"
                   f"\nEmployee Name: {empNameDec}"
                   f"\nItem: {itemDec}" 
                   f"\n Price: {priceDec} \n "
                   f"Quantity: {quantityDec} \n " 
                   f"time requested: {empSubmitTimeDec} \n "    
                   )
                recipient = [empEmailaddDec, mgrEmailaddDec]
                send_email(eSubject,body, sender, recipient, app_password)

                query = "UPDATE Request SET isPurchased = ? WHERE RequestID = ?"
                cursor.execute(query, (hex_approve , hex_ID))
        else:
            #pub key objects have been generated now verifying signatures (both must be verified)
            req_query = "SELECT ReEmployee, Item, price, employeeTimeRequest, employeeSignature, quantity FROM Request WHERE RequestID = ?"
            cursor.execute(req_query, (hex_ID,))
            rows = cursor.fetchall()

            reqEmpName = rows[0][0]
            item = rows[0][1]
            price = rows[0][2]
            employeeTimeRequest = rows[0][3]
            empSignBase64 = rows[0][4]
            quantity = rows[0][5]

            decEmpName = decrypt_data(binascii.unhexlify(reqEmpName))
            itemDec = decrypt_data(binascii.unhexlify(item))
            priceDec = decrypt_data(binascii.unhexlify(price))
            timeDec = decrypt_data(binascii.unhexlify(employeeTimeRequest))
            quantityDec = decrypt_data(binascii.unhexlify(quantity))

            empSign= base64.b64decode(empSignBase64)

            #crafting email and retrieving public keys
            empEmailQuery = "SELECT Email, PublicKey FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (EmployeeName, ))
            rows = cursor.fetchall()

        #albert
            empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))
            rtrPubKeyEmp = rows[0][1]

            #generating public key object
            pubBytesEmp = base64.b64decode(rtrPubKeyEmp)

            recpubBytesEmp = serialization.load_pem_public_key(
            pubBytesEmp,
            backend=default_backend()
            )

            #getting message for signature
            reqSignature = decEmpName + itemDec + priceDec + quantityDec + timeDec

            messageToSign = reqSignature.encode('UTF-8')

            #verifying both signatures: 
            valid_signature_emp = False
            try:
                recpubBytesEmp.verify(
                    empSign,
                    messageToSign,
                    paddingRSA.PSS(
                        mgf=paddingRSA.MGF1(hashes.SHA256()),
                        salt_length=paddingRSA.PSS.MAX_LENGTH
                                ),
                                 hashes.SHA256()
                                )

                valid_signature_emp = True
                print("The employee signature is valid.")
            except Exception as e:
                valid_signature_emp = False
                print(f"An error occurred emp sign invalid: {e}")
            
            if(valid_signature_emp):
                eSubject = f" Order: {id} has been completely approved"
                body = (
                f"\nItem: {itemDec}" 
                f"\n Price: {priceDec} \n "
                f"\nQuantity: {quantityDec} \n " 
                f"time requested: {empSubmitTimeDec} \n "
                f"Please log into the application to review."    
                )
                recipient = [empEmailaddDec]
                send_email(eSubject,body, sender, recipient, app_password)

                query = "UPDATE Request SET isPurchased = ? WHERE RequestID = ?"
                cursor.execute(query, (hex_approve , hex_ID))


        conn.commit()
        conn.close()
    
    return redirect('/purchasingDept')

@app.route('/decline_item/<string:id>', methods=['POST'])
@login_required
@role_required('FinancialApprover')
def decline_item(id):
    if request.method == 'POST':

        encrypt_ID = encrypt_data(id)
        hex_ID = binascii.hexlify(encrypt_ID).decode()

        encrypt_Deny = encrypt_data("Decline")
        hex_Deny = binascii.hexlify(encrypt_Deny).decode() 

        conn = connect_to_database()
        cursor = conn.cursor()
        query = "UPDATE Request SET isPurchased = ? WHERE RequestID = ?"
        cursor.execute(query, ( hex_Deny , hex_ID))
        cursor.commit()
        

        #start of jjs emails

        checkIfMgrQuery ="SELECT managerName FROM Request WHERE RequestID = ?"
        cursor.execute(checkIfMgrQuery,(hex_ID, ))
        rows = cursor.fetchone()
        
        if rows:
            mgrName = rows[0]
            ReqQuery = "SELECT ReEmployee, item, price, employeeTimeRequest, quantity, managerTimeStamp FROM Request WHERE RequestID = ?"
            cursor.execute(ReqQuery, (hex_ID, ))
            rows = cursor.fetchall()

         # albert's style
            EmployeeName = rows[0][0]
            item = rows[0][1]
            price = rows[0][2]
            empSubmitTime = rows[0][3]
            quantity = rows[0][4]
            mgrTimeStamp = rows[0][5]
        #decrypted tell me if Im retarded
            empNameDec = decrypt_data(binascii.unhexlify(EmployeeName))
            itemDec = decrypt_data(binascii.unhexlify(item))
            priceDec = decrypt_data(binascii.unhexlify(price))
            empSubmitTimeDec = decrypt_data(binascii.unhexlify(empSubmitTime))
            quantityDec = decrypt_data(binascii.unhexlify(quantity))
            mgrTimeStampDec = decrypt_data(binascii.unhexlify(mgrTimeStamp))

            #crafting email
            empEmailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (EmployeeName, ))
            rows = cursor.fetchall()

        #albert
            empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))

            #crafting email
            empEmailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (mgrName, ))
            rows = cursor.fetchall()

            mgrEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))

            eSubject = f"Order: {id} has been denied by financial department"
            body = (
                   f"\nManager: {decrypt_data(binascii.unhexlify(mgrName))} "
                   f"\nManager Time approved: {mgrTimeStampDec}"
                   f"\nEmployee Name: {empNameDec}"
                   f"\nItem: {itemDec}" 
                   f"\n Price: {priceDec} \n "
                   f"Quantity: {quantityDec} \n " 
                   f"time requested: {empSubmitTimeDec} \n "    
                   )
            recipient = [empEmailaddDec, mgrEmailaddDec]
            send_email(eSubject,body, sender, recipient, app_password)
        else:
            ReqQuery = "SELECT ReEmployee, item, price, employeeTimeRequest, quantity FROM Request WHERE RequestID = ?"
            cursor.execute(ReqQuery, (hex_ID, ))
            rows = cursor.fetchall()


         # albert's style
            EmployeeName = rows[0][0]
            item = rows[0][1]
            price = rows[0][2]
            empSubmitTime = rows[0][3]
            quantity = rows[0][4]
        #decrypted tell me if Im retarded
            empNameDec = decrypt_data(binascii.unhexlify(EmployeeName))
            itemDec = decrypt_data(binascii.unhexlify(item))
            priceDec = decrypt_data(binascii.unhexlify(price))
            empSubmitTimeDec = decrypt_data(binascii.unhexlify(empSubmitTime))
            quantityDec = decrypt_data(binascii.unhexlify(quantity))

            empEmailQuery = "SELECT Email FROM Employees WHERE Employee = ?"
            cursor.execute(empEmailQuery, (EmployeeName, ))
            rows = cursor.fetchall()

        #albert
            empEmailaddDec = decrypt_data(binascii.unhexlify(rows[0][0]))

            eSubject = f" Order: {id} has been denied by financial department"
            body = (
            f"Item: {itemDec}" 
            f"\n Price: {priceDec} \n "
            f"Quantity: {quantityDec} \n " 
            f"time requested: {empSubmitTimeDec} \n "
            f"Please log into the application to review."    
            )
            recipient = [empEmailaddDec]
            send_email(eSubject,body, sender, recipient, app_password)

            conn.commit()
            conn.close()

    
    return redirect('/purchasingDept')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    app.run(debug=True)