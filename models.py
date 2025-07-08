from pydantic import BaseModel


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
    section_filter: list
    tags_filter: list
    price_min: float
    price_max: float