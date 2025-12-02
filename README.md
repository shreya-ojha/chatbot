### 🤖 Intelligent FAQ Chatbot

### 📌 Introduction  
The **Intelligent FAQ Chatbot** is a lightweight, plug-and-play helpdesk assistant designed to instantly answer user queries through a structured FAQ dataset and NLP-based free-text search.  
It integrates seamlessly into any existing web application with a floating UI widget and a minimal Django backend.

This chatbot is ideal for:
- Self-service help centers  
- Internal knowledge systems  
- Application onboarding support  
- Replacing long documentation with quick, interactive answers  

Everything runs automatically using a simple `qa.txt` file — no database dependency required.

---

### ⭐ What This Project Does
This chatbot provides an interactive experience where users can:

**🔹 Browse FAQs by Category:** 
Categories are shown dynamically and are loaded directly from `qa.txt`.

**🔹 Select Questions:** 
Each category reveals its own question list automatically.

**🔹 Read Rich HTML Answers:**
Answers fully support:
- Bold, italics  
- Lists, tables  
- Emojis  
- URLs  
- Line breaks  
- PDF links  
(Images intentionally excluded for open distribution)

**🔹 Ask Free-Text Questions:**
NLP (RapidFuzz) allows the chatbot to understand:
- Unclear queries  
- Misspellings  
- Similar questions  

It then returns the closest matching answer.

---

### ⭐ Technology Stack

| Component   | Technology           |
|-------------|----------------------|
| Backend     | Django               |
| NLP Engine  | RapidFuzz            |
| Frontend    | JavaScript, HTML, CSS|
| Data Source | `qa.txt`             |
| API Format  | JSON                 |

---

### ⭐ Project Structure Overview

```
project/
│
├── chatbot/
│   ├── views.py        # API logic for categories, questions, answers
│   ├── qa.txt          # The FAQ dataset (tab-separated format)
│
├── static/
│   ├── css/
│   │   └── bot.css     # Chatbot UI styling
│   └── js/
│       └── bot.js      # Chatbot widget + API calls
│
├── templates/
│   └── login.html       # Chatbot widget injection snippet
│
└── README.md
```
---

### ⭐ How the Chatbot Works (Architecture)

## 1️⃣ FAQ Loader
The backend reads `qa.txt` and organizes it as:
- **categories → questions → answers**
- **flat dictionary for NLP**

## 2️⃣ REST-like Endpoints
The chatbot exposes three main APIs:

|             Endpoint                 |               Purpose                 |
|--------------------------------------|---------------------------------------|
| `/api/chatbot/categories/`           | Returns all categories                |
| `/api/chatbot/questions/<category>/` | Returns questions for that category   |
| `/api/chatbot/answer/?q=...`         | Returns matched answer (exact or NLP) |

## 3️⃣ Frontend Widget
The floating widget:
- Displays messages  
- Loads categories/questions  
- Sends query to backend  
- Renders HTML answers beautifully  

---

### ⭐ How to Run Locally

## 1️⃣ Clone the Project

git clone <your-repo-url>
cd chatbot-project

## 2️⃣ Create & Activate Virtual Environment

python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Mac/Linux

## 3️⃣ Install Dependencies

pip install -r requirements.txt

## 4️⃣ Run the Server

python manage.py runserver

_Your backend endpoints are live now._


### ⭐ How to Edit FAQ Data _(qa.txt Format)_
The file uses tab-separated values:

Category<TAB>Question<TAB>Answer (HTML allowed)

**Example:**
General	How do I start?	Click <b>Begin</b> to start your journey.
Help	Where is info?	Visit the Help menu.<br>More details available inside.

_No restart needed — changes are picked up automatically._


### ⭐ How to Add the Chatbot UI to Any Web Page

Add these lines to your main HTML template:

```html
<link rel="stylesheet" href="{% static 'css/bot.css' %}">
<script src="{% static 'js/bot.js' %}"></script>
```

Then add the widget:

```html
<div class="chatbot-container">
  <button class="chatbot-toggle" onclick="toggleChatbot()">🤖</button>
  <div class="chatbot-window" id="chatbotWindow">
      ...
  </div>
</div>
```

That’s it — chatbot appears instantly.

---
### ⭐ Features at a Glance

```
✔ Floating UI widget
✔ NLP free-text question matching
✔ HTML-styled answers
✔ Category → Question → Answer navigation
✔ API-based architecture
✔ Auto-refresh on FAQ updates
✔ No admin panel or database required
✔ Easy to embed anywhere
```

---
### ⭐ Future Enhancements

```
🔹 Add authentication for internal knowledgebases
🔹 Save conversation history
🔹 Provide suggestions while typing
🔹 Enable multi-language support
```
