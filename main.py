import os
import faiss
import jwt
import requests
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError
from pymongo import MongoClient
from requests import Session
from models import FetchMenuBody, UpdateMenuBody, LoginBody, RegisterBody, SearchBody
from bson import ObjectId
from bson.json_util import dumps
from json import loads
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize

load_dotenv()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongo_client = MongoClient(os.getenv("MONGO_CONNECTION_STRING"))
# embed_model = SentenceTransformer('all-mpnet-base-v2', cache_folder='./models/all-mpnet-base-v2')

db = mongo_client.get_database("Res_Data")
profile_collection = db.get_collection("Res_profiles")
menu_collection = db.get_collection("Res_menus")

def createAccessToken(data):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)

def semantic_search(menu_id: str, query_text: str, threshold: float = -1, k: int = 10):
    dish_records = []
    menu_doc = menu_collection.find_one({"_id": ObjectId(menu_id)})

    for section in menu_doc["menu"]["sections"]:
        for dish in section["dishes"]:
            if "embedding" in dish:
                dish_records.append({
                    "name": dish["name"],
                    "description": dish.get("desc", ""),
                    "section": section["name"],
                    "price": dish["price"],
                    "tags": dish.get("tags", []),
                    "embedding": np.array(dish["embedding"], dtype="float32")
                })

    index = faiss.read_index(f"faiss_index_{menu_doc['name']}.index")

    query_vector = np.array(get_embedding_from_mistral([query_text])[0]).astype("float32").reshape(1, -1)
    similarities, indices = index.search(normalize(query_vector, axis=1), k)
    results = []
    for i, sim in zip(indices[0], similarities[0]):
        if sim >= threshold:
            doc = dish_records[i]
            doc.pop('embedding', None)
            results.append(doc)

    return results

def get_embedding_from_mistral(inputs):
    response = requests.post("https://api.mistral.ai/v1/embeddings", 
                             headers={
                                "Authorization": f"Bearer {MISTRAL_API_KEY}",
                                "Content-Type": "application/json"
                             }, 
                             json={
                                "model": "mistral-embed", 
                                "input":inputs 
                             })
    if response.status_code == 200:
        embeddings = [item["embedding"] for item in response.json()["data"]]
        return embeddings
    else:
         raise Exception(f"Error fetching embeddings: {response.status_code} - {response.text}")

def generate_embeddings_for_menu(res_id: str):
    
    try:
        item = menu_collection.find_one({"_id":ObjectId(res_id)})
    except Exception as e:
        return {"message": "Error fetching menu", "error": str(e)}

    updated_sections = []
    try:
        for section in item['menu']['sections']:
            updated_dishes = []
            for dish in section['dishes']:

                if 'embedding' in dish:
                    updated_dishes.append(dish)
                    continue

                text = f"{dish['name']}. {dish['desc']}. Category: {dish['section']}."
                embedding = get_embedding_from_mistral([text])[0]
                dish['embedding'] = embedding.tolist()
                updated_dishes.append(dish)

            section['dishes'] = updated_dishes
            updated_sections.append(section)

        menu_collection.update_one(
            {'_id': ObjectId(res_id)},
            {'$set': {'menu.sections': updated_sections}}
        )
    except Exception as e:
        return {"message": "Error generating embeddings", "error": str(e)}

    return {"message": "Embeddings generated and updated successfully"}

@app.middleware("http")
async def validateToken(request: Request, call_next):
    skip_auth_paths = ['/login','/register', "/docs", "/openapi.json", "/redoc", "/fetchMenu", "/search"]

    if request.method == "OPTIONS":
        return await call_next(request)

    for path in skip_auth_paths:
        if request.url.path.startswith(path): return await call_next(request)

    auth_header = request.headers.get("authorization")
    token = ''
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if token:
        try:
            payload = jwt.decode(jwt=token,algorithms=[ALGORITHM],key=os.getenv("SECRET_KEY"))
            res_id = payload.get('restaurant_id')
            res_menu_id = payload.get("restaurant_menu_id")

            restaurant = profile_collection.find_one({"_id":ObjectId(res_id)})

            if restaurant is None:
                raise HTTPException(status_code=401, detail="Invalid Token")

            request.state.restaurant = res_id
            request.state.restaurant_menu = res_menu_id
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or Expired Token")
    else:
        return JSONResponse(status_code=401, content={"message":"token missing"})
    
    response = await call_next(request)
    return response

@app.post("/login")
def login(body: LoginBody):
    user_res = profile_collection.find_one({"username":body.username})

    if user_res is None or not pwd_context.verify(body.pswd, user_res["pswd"]):
        raise HTTPException(status_code=401, detail='Invalid Credentials')
    
    access_token = createAccessToken(data={'restaurant_id':str(user_res["_id"]),'restaurant_menu_id':user_res['res_id']})

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
def UpdateMenu(body: UpdateMenuBody, request: Request):
    res_id = request.state.restaurant_menu
    try:
        if body.action == "u": #update
            if not list(body.update_str.keys())[0].split(".")[-1] == "name":
                dish = list(body.update_str.values())[0]
                text = f"{dish['name']}. {dish['desc']}."
                dish['embedding'] = get_embedding_from_mistral([text])[0]
                body.update_str = {list(body.update_str.keys())[0]: dish}

            menu_collection.find_one_and_update({"_id":ObjectId(res_id)},{"$set":body.update_str}) #update_str contains the json object of the dish that is updated
            
        elif body.action == "a" : #add
            if "menu.sections" not in list(body.update_str.keys()):
                dish = list(body.update_str.values())[0]
                text = f"{dish['name']}. {dish['desc']}."
                dish['embedding'] = get_embedding_from_mistral([text])[0]
                body.update_str = {list(body.update_str.keys())[0]: dish}
                
            menu_collection.find_one_and_update({"_id":ObjectId(res_id),},{"$push":body.update_str})
            
        elif body.action == "d" : #delete
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
    
    menu_doc = menu_collection.find_one({"_id": ObjectId(res_id)})
    embeddings = []
    for section in menu_doc["menu"]["sections"]:
        for dish in section["dishes"]:
            if "embedding" in dish:
                embeddings.append(np.array(dish["embedding"], dtype="float32"))

    embeddings = normalize(np.array(embeddings), axis=1).astype("float32")
    dim = len(embeddings[0])
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    faiss.write_index(index, f"faiss_index_{menu_doc['name']}.index")

    return JSONResponse(status_code=200, content={"message":"menu update successful"})

@app.get("/fetchDishes")
def fetchDishes(request: Request):
    res_id = request.state.restaurant_menu

    dish_list = []

    try:
        menu = menu_collection.find_one({"_id": ObjectId(res_id)})

        for i in range(len(menu["menu"]["sections"])):
            for j in range(len(menu["menu"]["sections"][i]["dishes"])):
                menu["menu"]["sections"][i]["dishes"][j]["sectionCoord"] = i
                menu["menu"]["sections"][i]["dishes"][j]["dishCoord"] = j

                dish_list.append(menu["menu"]["sections"][i]["dishes"][j])

    except Exception as e:
        return JSONResponse(status_code=400, content={"message":"trouble fetching dishes"})

    return JSONResponse(status_code=200, content={"list": dish_list})

@app.get("/fetchSections")
def fetchDishes(request: Request):
    res_id = request.state.restaurant_menu

    section_list = []

    try:
        menu = menu_collection.find_one({"_id": ObjectId(res_id)})

        for i in range(len(menu["menu"]["sections"])):
            data = {
                "name": menu["menu"]["sections"][i]["name"],
                "sectionCoord": i
            }
            section_list.append(data)

    except Exception as e:
        return JSONResponse(status_code=400, content={"message":"trouble fetching dishes"})

    return JSONResponse(status_code=200, content={"list": section_list})

# ADD AI PART HERE -------------
@app.post("/search")
def search_menu(search_request: SearchBody):

    if search_request.user_query == "" and search_request.section_filter == [] and search_request.tags_filter == [] and search_request.price_min is None and search_request.price_max is None:
        return JSONResponse(status_code=422, content={"message": "incorrect set of parameters passed"})

    if search_request.user_query:
        results = semantic_search( query_text=search_request.user_query, menu_id=search_request.menu_id, k=15, threshold=-1)

    else:
        results = []
        menu_doc = menu_collection.find_one({"_id": ObjectId(search_request.menu_id)})
        for section in menu_doc["menu"]["sections"]:
            for dish in section["dishes"]:
                results.append({
                    "name": dish["name"],
                    "description": dish.get("desc", ""),
                    "section": section["name"],
                    "price": dish["price"],
                    "tags": dish.get("tags", [])
                })

    if search_request.section_filter:
        results = [doc for doc in results for section in search_request.section_filter if doc["section"].lower() == section.lower()]

    if search_request.tags_filter:
        results = [doc for doc in results for tag in search_request.tags_filter if tag.lower() in [doc_tag.lower() for doc_tag in doc["tags"]]]

    if search_request.price_min is not None:
        results = [doc for doc in results if doc["price"] >= search_request.price_min]

    if search_request.price_max is not None:
        results = [doc for doc in results if doc["price"] <= search_request.price_max]

    return JSONResponse(status_code=200, content={"search_results": results})

@app.post("/generateEmbeddings")
def generate_embeddings(request: Request):
    res_id = request.state.restaurant_menu
    return generate_embeddings_for_menu(res_id)
# ---------------