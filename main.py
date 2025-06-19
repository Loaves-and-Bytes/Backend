from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError
import jwt
from pymongo import MongoClient
from requests import Session
from models import FetchMenuBody, UpdateMenuBody
from bson import ObjectId
from bson.json_util import dumps
from json import loads
from datetime import datetime, timedelta, timezone

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

app = FastAPI()

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

def createAccessToken(data):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, "somethingsupercool", algorithm=ALGORITHM)

@app.middleware("http")
async def validateToken(request: Request, call_next):
    skip_auth_paths = ['/login','/register', "/docs", "/openapi.json", "/redoc"]

    for path in skip_auth_paths:
        if request.url.path.startswith(path): return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if token:
        try:
            payload = jwt.decode(token=token)
            user_id = payload.get('user_id')

            restaurant = list(profile_collection.find({"_id":ObjectId(user_id)}))

            if len(restaurant) == 0:
                raise HTTPException(status_code=401, detail="Invalid Token")

            request.state.restaurant = restaurant[0]
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or Expired Token")
    else:
        raise HTTPException(status_code=401, detail="Token Missing")
    
    response = await call_next(request)
    return response

@app.post("/fetchMenu")
def fetchMenu(body: FetchMenuBody):
    try:
        data = menu_collection.find_one({"_id":ObjectId(body.res_id)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"msg": "Couldn't fetch menu"})
    
    return JSONResponse(status_code=200, content=loads(dumps(data)))

@app.post("/updateMenu")
def UpdateMenu(body: UpdateMenuBody):
    try:
        if body.action == "u":
            menu_collection.find_one_and_update({"_id":ObjectId(body.res_id)},{"$set":body.update_str})
        elif body.action == "a" :
            menu_collection.find_one_and_update({"_id":ObjectId(body.res_id),},{"$push":body.update_str})
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