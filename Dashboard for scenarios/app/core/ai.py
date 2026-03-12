import uuid

QUESTIONS = {
    "hr": [
        {"id": "q1", "text": "Tell me about yourself."},
        {"id": "q2", "text": "Why do you want to work here?"},
    ],
    "technical": [
        {"id": "t1", "text": "Explain OOP principles."},
    ],
}


def get_first_question(kind: str = "hr", company: str = None):
    qs = QUESTIONS.get(kind, [])
    if not qs:
        return None
    return qs[0]


def evaluate_answer(question_id: str, answer: str):
    # simple heuristic-based feedback stub
    score = min(max(len(answer) // 20, 1), 5)
    feedback = {
        "confidence": round(score / 5, 2),
        "communication": round(score / 5, 2),
        "relevance": round(score / 5, 2),
        "overall": round(score / 5, 2),
        "notes": "This is a stubbed evaluation. Integrate an LLM for better feedback.",
    }
    return feedback
