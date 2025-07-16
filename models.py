from pydantic import BaseModel
from typing import Optional


class FetchMenuBody(BaseModel):
    res_id: str

class UpdateMenuBody(BaseModel):
    update_str: dict
    action: str

class LoginBody(BaseModel):
    username: str
    pswd: str

class RegisterBody(BaseModel):
    username: str
    pswd: str
    name_of_restaurant: str

class SearchBody(BaseModel):
    user_query: str
    menu_id: str
    section_filter: Optional[list] = []
    tags_filter: Optional[list] = []
    price_min: Optional[float] = None
    price_max: Optional[float] = None