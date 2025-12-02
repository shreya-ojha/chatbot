#<!-----start nlp chatbot-------->
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpRequest

from rapidfuzz import process, fuzz

BASE_DIR = Path(__file__).resolve().parent.parent
QA_PATH = BASE_DIR / 'qa.txt'


def load_faq() -> Tuple[Dict[str, Dict[str, str]], Dict[str, str]]:
    categories: Dict[str, Dict[str, str]] = defaultdict(dict)
    flat_q_to_a: Dict[str, str] = {}

    if not QA_PATH.exists():
        return {}, {}

    with QA_PATH.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue

            category, question, answer = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if category.lower() in {"category", "general"}:
                continue

            categories[category][question] = answer
            flat_q_to_a[question.lower()] = answer

    return categories, flat_q_to_a


def get_faq_data():
    return load_faq()


def chatbot_categories(request: HttpRequest):
    categories, _ = get_faq_data()
    return JsonResponse({'categories': sorted(categories.keys())})

def chatbot_questions(request: HttpRequest, category: str):
    categories, _ = get_faq_data()
    questions = sorted(categories.get(category, {}).keys())
    return JsonResponse({'category': category, 'questions': questions})


def chatbot_answer(request: HttpRequest):
    user_query = request.GET.get('q', '').strip()
    if not user_query:
        return JsonResponse({'answer': ''})

    # Reload data every request so updated qa.txt reflects immediately
    categories, flat_qa = load_faq()

    # Exact match first
    answer = flat_qa.get(user_query.lower())
    if not answer and flat_qa:
        best_match, score, _ = process.extractOne(user_query, list(flat_qa.keys()), scorer=fuzz.token_sort_ratio)
        if score >= 60:
            answer = flat_qa.get(best_match)

    if not answer:
        return JsonResponse({'answer': "Sorry, I don’t have an answer for that yet."})

    # --- Smart media detection ---
    if "::" in answer:
        parts = [p.strip() for p in answer.split("::", 1)]
        text = parts[0]
        media = parts[1] if len(parts) > 1 else ""
        if media.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
            answer = f'{text}<br><img src="{media}" alt="Image" style="max-width:100%; border-radius:8px; margin-top:8px;">'
        elif media.lower().endswith((".pdf",)):
            answer = f'{text}<br><a href="{media}" target="_blank" style="color:#4f46e5;">📄 Open PDF</a>'
        elif media.lower().startswith("http"):
            answer = f'{text}<br><a href="{media}" target="_blank" style="color:#4f46e5;">🔗 Open Link</a>'
        else:
            answer = f'{text}<br>{media}'

    return JsonResponse({'answer': answer})
    
# ---------- END ----------
