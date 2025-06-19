from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from models import FetchMenuBody, UpdateMenuBody
from bson import ObjectId
from bson.json_util import dumps
from json import loads

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