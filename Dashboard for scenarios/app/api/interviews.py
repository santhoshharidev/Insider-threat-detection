from fastapi import APIRouter
from pydantic import BaseModel
from ..core import ai

router = APIRouter()


class StartInterviewIn(BaseModel):
    kind: str = "hr"
    company: str = None
    mode: str = "text"  # or voice


@router.post("/start")
def start_interview(payload: StartInterviewIn):
    # returns first question
    q = ai.get_first_question(kind=payload.kind, company=payload.company)
    return {"question": q}


class AnswerIn(BaseModel):
    question_id: str
    answer: str


@router.post("/answer")
def answer_question(payload: AnswerIn):
    feedback = ai.evaluate_answer(payload.question_id, payload.answer)
    return {"feedback": feedback}
