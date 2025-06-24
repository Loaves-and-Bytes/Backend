import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError
import jwt
from pymongo import MongoClient
from requests import Session
from models import FetchMenuBody, UpdateMenuBody, LoginBody, RegisterBody
from bson import ObjectId
from bson.json_util import dumps
from json import loads
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from dotenv import load_dotenv

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongo_client = MongoClient("mongodb+srv://abeladityaphilipose:A3m1mjTDEPAYwMHb@datastore.dayo1hn.mongodb.net/?retryWrites=true&w=majority&appName=DataStore")

db = mongo_client.get_database("Res_Data")

profile_collection = db.get_collection("Res_profiles")
menu_collection = db.get_collection("Res_menus")

load_dotenv()

def createAccessToken(data):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)

@app.middleware("http")
async def validateToken(request: Request, call_next):
    skip_auth_paths = ['/login','/register', "/docs", "/openapi.json", "/redoc", "/fetchMenu", "/search"]

    for path in skip_auth_paths:
        if request.url.path.startswith(path): return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if token:
        try:
            payload = jwt.decode(jwt=token,algorithms=[ALGORITHM],key=os.getenv("SECRET_KEY"))
            res_id = payload.get('restaurant_id')

            restaurant = profile_collection.find_one({"_id":ObjectId(res_id)})

            if restaurant is None:
                raise HTTPException(status_code=401, detail="Invalid Token")

            request.state.restaurant = restaurant["res_id"]
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or Expired Token")
    else:
        raise HTTPException(status_code=401, detail="Token Missing")
    
    response = await call_next(request)
    return response

@app.post("/login")
def login(body: LoginBody):
    user_res = profile_collection.find_one({"username":body.username})

    if user_res is None or not pwd_context.verify(body.pswd, user_res["pswd"]):
        raise HTTPException(status_code=401, detail='Invalid Credentials')
    
    access_token = createAccessToken(data={'restaurant_id':str(user_res["_id"])})

    response = JSONResponse(status_code=200, content={"token": access_token, "message": "Login Successful"})
    return response

@app.post("/register")
def register(body: RegisterBody):
    check_prof = list(profile_collection.find({"res_name":body.name_of_restaurant}))
    if len(check_prof) !=0:
        return JSONResponse(status_code=400, content={"msg":"A Profile against this restaurant already exists"})
    
    check_username_dup = list(profile_collection.find({"username":body.username}))
    if len(check_username_dup) != 0:
        return JSONResponse(status_code=400, content={"msg":"Username already in use"})

    hashed_pswd = pwd_context.hash(body.pswd)

    try:
        res_menu_id = str(menu_collection.find_one({"name": body.name_of_restaurant})["_id"])
    except Exception as e:
        return JSONResponse(status_code=400, content={"msg":"Incorrect restaurant name provided"})

    profile_collection.insert_one({"res_name":body.name_of_restaurant,"username":body.username,"pswd":hashed_pswd,"res_id":res_menu_id})

    access_token = createAccessToken(data={'restaurant_menu_id':res_menu_id})

    return JSONResponse(status_code=200, content={"token": access_token, "message": "Register Successful"})

@app.post("/fetchMenu")
def fetchMenu(body: FetchMenuBody):
    try:
        data = menu_collection.find_one({"_id":ObjectId(body.res_id)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"msg": "Couldn't fetch menu"})
    
    return JSONResponse(status_code=200, content=loads(dumps(data)))

@app.post("/updateMenu")
def UpdateMenu(body: UpdateMenuBody,request: Request):
    res_id = request.state.restaurant
    try:
        if body.action == "u":
            menu_collection.find_one_and_update({"_id":ObjectId(res_id)},{"$set":body.update_str})
        elif body.action == "a" :
            menu_collection.find_one_and_update({"_id":ObjectId(res_id),},{"$push":body.update_str})
        elif body.action == "d" :
            doc = menu_collection.find_one({"_id":ObjectId(res_id)})
            if len(body.update_str["loc"]) == 1:
                doc["menu"]["sections"].pop(body.update_str["loc"][0])
                l = doc["menu"]["sections"]
                menu_collection.find_one_and_update({"_id":ObjectId(res_id)},{"$set":{"menu.sections":l}})
            elif len(body.update_str["loc"]) > 1:
                doc["menu"]["sections"][body.update_str["loc"][0]]["dishes"].pop(body.update_str["loc"][1])
                l = doc["menu"]["sections"][body.update_str["loc"][0]]["dishes"]
                menu_collection.find_one_and_update({"_id":ObjectId(res_id)},{"$set":{f"menu.sections.{body.update_str['loc'][0]}.dishes":l}}) 
            else:
                return JSONResponse(status_code=400, content={"msg":"Incorrent action flag passed"})   
        else: 
            return JSONResponse(status_code=400, content={"msg":"Incorrent action flag passed"})

    except Exception as e:
        return JSONResponse(status_code=400, content={"msg": "Error carrying out update request"})
    
    return JSONResponse(status_code=200, content="menu update successful")


# ADD AI PART HERE -------------
@app.post("/search")
def search():
    pass
# ---------------