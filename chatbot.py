from pathlib import Path
from rapidfuzz import process, fuzz


def load_from_qa():
    base = Path(__file__).resolve().parent
    qa = base / 'qa.txt'
    q_to_a = {}
    if qa.exists():
        with qa.open('r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 3:
                    question = parts[1].strip()
                    answer = parts[2].strip()
                    if question:
                        q_to_a[question.lower()] = answer
    return q_to_a


FAQ_LOWER = load_from_qa()


def chatbot_response(user_query: str) -> str:
    if not user_query:
        return ""
    # exact first
    ans = FAQ_LOWER.get(user_query.lower())
    if ans:
        return ans
    # fuzzy fallback
    if FAQ_LOWER:
        best, score, _ = process.extractOne(user_query, list(FAQ_LOWER.keys()), scorer=fuzz.token_sort_ratio)
        if score >= 60:
            return FAQ_LOWER.get(best, "")
    return "Sorry, I am not sure about that. Please rephrase your question."
 