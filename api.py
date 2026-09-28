from  fastapi import FastAPI, HTTPException, Depends 
from pydantic import BaseModel
from pymongo  import MongoClient
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
from fastapi.middleware.cors import CORSMiddleware

"""
     pip install pymongo    
"""

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Mongo db connection.
MONGO_URL = "mongodb://localhost:27017"
client = MongoClient (MONGO_URL) # -- This is the Mongodb URL as the client...
db =  client["MyDB"] # -- Connect with MyDB database in Mongo.
stuent_collection = db["student"] # -- Connect with student table/collection in the mongodb.
user_collection = db["users"] 

# pip install "passlib[bcrypt]" "python-jose[cryptography]"
# pip uninstall bcrypt
# pip install bcrypt==4.3.0   
# pip install "python-jose[cryptography]"

# JWT Configuration.
# Define the secret key used to create and verify JWT tokens.
SECRET_KEY = "my-secret-key"

# Define the algorithm used for signing and verifying JWT tokens.
ALGORITHM = "HS256"

# Create an OAuth2 scheme that gets the Bearer token from the request.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Create a password context for securely hashing and verifying passwords.
pwd_context = CryptContext(

    # Specify bcrypt as the password hashing algorithm.
    schemes=["bcrypt"],

    # Automatically handle older or deprecated password hashing schemes.
    deprecated="auto"
)


class User(BaseModel):
    username:str
    password:str
    role:str

class StudentCrate (BaseModel):
    rollno : int
    name:str    
    course:str
    
 
class StudentUpdate(BaseModel):
    rollno : int
    name:str    
    course:str
   
   
@app.post("/register")
def register_user (user:User):
    existing_user = user_collection.find_one({"username":user.username})

    if existing_user : 
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = pwd_context.hash (user.password)
    
    user_collection.insert_one({
        "username":user.username, 
        "password":hashed_password,
        "role":user.role
        })
    
    return "User registered successfully..."


# Login operation.
@app.post ("/login")
def login (user:User):
    existing_user = user_collection.find_one ({"username":user.username})
    
    if existing_user is None:
        raise HTTPException(status_code=401, detail="User not found..")
    
    # Check the password.
    if not pwd_context.verify(
        user.password,
        existing_user["password"]
    ):
        raise HTTPException(status_code=401, detail="Invalid password..")
    
    #Create a payload with user name and expiry time of token is 30mins from now.
    pay_load = {
        "sub":user.username,
        "role":existing_user["role"],
        "exp":datetime.utcnow() + timedelta(minutes=30)
    }
    
    token = jwt.encode(
        pay_load,
        SECRET_KEY,
        algorithm=ALGORITHM 
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# Verify token...
# Define a function to verify the JWT token received from the user.
def Verify_Token(token: str = Depends(oauth2_scheme)):

    # Start a try block to handle invalid or expired JWT tokens.
    try:

        # Decode the JWT token using the secret key and specified algorithm.
        payload = jwt.decode(
            token,

            # Use the secret key to verify that the token was created by our application.
            SECRET_KEY,

            # Allow only the specified algorithm to decode and verify the token.
            algorithms=[ALGORITHM]
        )

        # Get the username from the "sub" field of the JWT payload.
        username = payload.get("sub")

        # Get the user's role from the "role" field of the JWT payload.
        role = payload.get("role")

        # Check whether the username is missing from the JWT payload.
        if username is None:

            # Return HTTP 401 if the JWT does not contain a valid username.
            raise HTTPException(status_code=401, detail="Invalid Token")

        # Return the username and role to the calling function.
        return {"username": username, "role": role}

    # Catch errors that occur while decoding or verifying the JWT token.
    except Exception:

        # Return HTTP 401 when the token is invalid or has expired.
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Define a function that accepts the roles allowed to access an API.
def require_role(allowed_roles: list):

    # Create an inner function that will check the logged-in user's role.
    def role_checker(user=Depends(Verify_Token)):

        # Check whether the user's role exists in the list of allowed roles.
        if user["role"] not in allowed_roles:

            # Return HTTP 400 when the user's role is not allowed.
            raise HTTPException(status_code=400, detail="Access denied")

        # Return the authenticated user's username and role.
        return user

    # Return the role-checking function to FastAPI's Depends().
    return role_checker

@app.get("/")
def home():
    return "Student Management Information"

"""
    broser is http://localhost:port/students
    returns all the records of the dictionary.
"""
@app.get("/students")
def get_students(user=Depends(require_role(["Student", "Admin"]))):
    # find({} -> There is no filter, {"_id":0} --> Ignore _id field or dont return this field.)
    students = list (stuent_collection.find({}, {"_id":0}))
    return students


#Fetch the student by student id.
@app.get ("/student/{student_id}")
def get_student_by_id(student_id:int, user=Depends(require_role(["Student", "Admin"]))):
    #                                      Filter roll number by student_id which is passed as argument.
    student =  stuent_collection.find_one({"rollno":student_id}, {"_id":0})
    if student is None:
        raise HTTPException(status_code=404, detail="Student not found")
    
    return student

#insert a record in the dictionary.
@app.post ("/student", status_code=201)
def insert_student (student:StudentCrate, user=Depends(require_role(["Admin"]))):
    # -- model_dump() -- converts normal json data into Python dictionary which will write into the mongodb.
    stuent_collection.insert_one(student.model_dump())
    return "Record inserted successfully"


     
# Updating a record.
@app.put ("/student/{student_id}")
def update_student (student_id:int, student:StudentUpdate, user=Depends(require_role(["Admin"]))):
    result = stuent_collection.update_one({"rollno":student_id}, {"$set":student.model_dump()})
    
    if result.matched_count == 0:
     raise HTTPException(
        status_code=404,
        detail="Student not found"
    )  
    return "Record updated Successfully..."


#For Deleting a record
@app.delete ("/student/{student_id}")
def delete_record (student_id : int, user=Depends(require_role(["Admin"]))):
    result = stuent_collection.delete_one({"rollno":student_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Student id not found in the database...")
    
    return "Student record deleted successfully...."