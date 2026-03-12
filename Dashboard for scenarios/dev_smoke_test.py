from app.core import ai, code_runner, security


def test_ai():
    print("== AI stub test ==")
    q = ai.get_first_question(kind="hr")
    print("First question:", q)
    fb = ai.evaluate_answer(q["id"], "I am a motivated candidate with 5 years experience.")
    print("Feedback:", fb)


def test_code_runner():
    print("\n== Code runner test ==")
    code = 'print("hello world")\n'
    rc, out, err = code_runner.run_python_code(code)
    print("returncode:", rc)
    print("stdout:", out)
    print("stderr:", err)


def test_security():
    print("\n== Security token test ==")
    token = security.create_access_token("test@example.com", expires_delta=60)
    print("JWT token (truncated):", token[:80], "...")


if __name__ == '__main__':
    test_ai()
    test_code_runner()
    test_security()
