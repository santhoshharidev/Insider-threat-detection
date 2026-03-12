from fastapi import APIRouter

router = APIRouter()


@router.get("/stats")
def stats():
    return {"users": 10, "interviews": 50}
