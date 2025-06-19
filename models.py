from pydantic import BaseModel


class FetchMenuBody(BaseModel):
    res_id: str

class UpdateMenuBody(BaseModel):
    res_id: str
    update_str: dict
    action: str
