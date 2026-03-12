from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()


class UserOut(BaseModel):
    email: str


@router.get("/me", response_model=UserOut)
def me():
    return {"email": "demo@example.com"}
