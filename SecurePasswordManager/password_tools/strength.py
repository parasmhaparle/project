
from zxcvbn import zxcvbn


def evaluate_password_strength(password: str) -> dict:
    """
    Evaluate password strength using zxcvbn.

    Returns the score, feedback, and estimated crack times.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    result = zxcvbn(password)

    return {
        "score": result["score"],
        "feedback": result["feedback"],
        "guesses": result["guesses"],
        "crack_times_display": result["crack_times_display"],
    }
