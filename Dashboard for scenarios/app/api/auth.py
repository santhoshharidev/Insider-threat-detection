from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ..core import security

router = APIRouter()


class SignUp(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/signup", response_model=Token)
def signup(data: SignUp):
    # stubbed: create user and return token
    user = {"email": data.email}
    token = security.create_access_token(subject=data.email)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
def login(data: SignUp):
    # stubbed: validate credentials
    token = security.create_access_token(subject=data.email)
    return {"access_token": token, "token_type": "bearer"}
