from fastapi import FastAPI, HTTPException,File, Form ,UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from passlib.context import CryptContext
from passlib.hash import pbkdf2_sha256
from pymongo import MongoClient
from datetime import datetime, date
from dotenv import load_dotenv, find_dotenv
import os,time,re
import uvicorn

load_dotenv(find_dotenv())
password = os.environ.get("MONGODB_PWD")
print(password)
connection_string = f"mongodb+srv://hassan:{password}@cluster0.yfycgja.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(connection_string)
# Check the Database connection
try:
    client.admin.command('ismaster')
    print("Connected to MongoDB successfully")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

db = client.flask_login
collection = db.users

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

IMAGEDIR='pics/'

ALLOWED_EXTENSION = {'png','jpg','jpeg','gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def validate_password(password):
    # Check if the password length is at least 8 characters

    if len(password) < 8 and not any(char.isupper() for char in password) and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password at least 8 character long and must contain one uppercase letter and one special character"

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    # Check if the password contains at least one uppercase letter
    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter."

    # Check if the password contains at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."

    return "Password is valid."

@app.get('/')
async def home():
    return {"message": "Welcome to FastAPI"}

@app.get('/login')
async def login(email: str, password: str):
    users = db.users
    ignored_keys = {'_id': 0, 'created_at': 0, 'updated_at': 0}
    login_user = users.find_one({'email': email}, ignored_keys)
    print(check_password_hash(login_user['password'],password))
    
    if login_user and check_password_hash( login_user['password'],password):
        return JSONResponse(content=login_user, status_code=200)
    else:
        raise HTTPException(status_code=401, detail="Invalid email or password")
        # return JSONResponse(status_code=401, content="Invalid email or password")

@app.post('/signup')
async def register( name:str=Form(...),email:str = Form(...),dob:str = Form(...),password:str=Form(...),profile_pic:str = Form(...)):
    
    dob_datetime = datetime.strptime(dob, '%Y-%m-%d')

    # Read profile pic data (assuming it's an image)
    # profile_pic_content = await profile_pic.read()

    # Print request body data
    print('Name:', name)
    print('Email:', email)
    print('Date of Birth:', dob_datetime)
    print('Password:', password)
    print('Profile Picture:', profile_pic)

    users = db.users
    existing_user = users.find_one({'email': email})
    if existing_user:
        raise HTTPException(status_code=400, detail=f'Oops! This email "{email}" already exists!')

    password_validation_result = validate_password(password)
    if password_validation_result != "Password is valid.":
        raise HTTPException(status_code=400, detail=password_validation_result)

    dob = datetime.strptime(dob, '%Y-%m-%d').date()
    print(dob)
    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if age < 16:
        raise HTTPException(status_code=400, detail=f'Sorry! Your age is {age} years. Age must be 16 or older to register.')
    dob = dob.strftime('%Y-%m-%d') 

    if profile_pic:
        print("Profile Pic : ",profile_pic)
        hash_password = generate_password_hash(password, method='pbkdf2:sha256')
        user_data = {'profile_pic':profile_pic,'email': email, 'name': name, 'dob': dob, 'password': hash_password,'isAdmin': False, 'created_at': datetime.now(), 'updated_at': datetime.now()}
        users.insert_one(user_data)
        print("Data Successfully Upoaded : ",user_data)

        return JSONResponse(status_code=201, content={'message': 'User registered successfully'})
    else:
        raise HTTPException(status_code=400, detail='Profile picture is required')

@app.post('/extension_test')
async def extension_test(name:str = Form(...),text:str = Form(...)):
    name_lower =name.lower()
    print('Lower Case : ',name_lower)
    if name_lower:
        print(f"Hello {name}!")
        print(text)
        return JSONResponse(status_code=200, content={"text" : text,'name':name})
    else:
        return JSONResponse(status_code=400,content={"message":"Name is Required"})



if __name__ == "__main__":
  
    uvicorn.run('main:app', host="0.0.0.0", port=8000,reload=True)

