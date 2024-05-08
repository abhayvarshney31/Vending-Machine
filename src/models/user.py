from pydantic import BaseModel


class UserRequest(BaseModel):
    username: str
    role: str
    password: str


class User(BaseModel):
    username: str
    role: str


class UserInDB(BaseModel):
    username: str
    role: str
    hashed_password: str
