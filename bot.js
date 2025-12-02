/* State */
let chatbotOpen = false;

/* Utility: get root window element (id or class) */
function getChatWindow() {
  return document.getElementById("chatbotWindow") || document.querySelector(".chatbot-window");
}

/* Toggle chatbot visibility and clear state when closing */
function toggleChatbot() {
  const win = getChatWindow();
  if (!win) return;
  chatbotOpen = !chatbotOpen;
  win.style.display = chatbotOpen ? "flex" : "none";
  if (chatbotOpen) loadCategories();
  else {
    win.className = (win.className || "").replace(/\bcat-\d+\b/g, "").trim();
    document.querySelectorAll("#categoryButtons .category-chip.active").forEach(c => c.classList.remove("active"));
  }
}

/* Set category class on root (cat-N) */
function setChatbotCategoryClass(idx) {
  const win = getChatWindow();
  if (!win) return;
  win.className = (win.className || "").replace(/\bcat-\d+\b/g, "").trim();
  win.classList.add("cat-" + idx);
}

/* Load categories from API and render category chips */
async function loadCategories() {
  try {
    const res = await fetch("/api/chatbot/categories/");
    const data = await res.json();
    const wrap = document.getElementById("categoryButtons");
    if (!wrap) return;
    wrap.innerHTML = "";
    const qWrap = document.getElementById("questionButtons");
    if (qWrap) qWrap.innerHTML = "";

    (data.categories || []).forEach((cat, i) => {
      const b = document.createElement("button");
      b.className = "category-chip";
      b.dataset.idx = String(i + 1);
      b.innerHTML = `<span class="num-badge">${i + 1}</span><span class="chip-text">${cat}</span>`;
      b.addEventListener("click", () => {
        document.querySelectorAll("#categoryButtons .category-chip").forEach(c => c.classList.remove("active"));
        b.classList.add("active");
        setChatbotCategoryClass(i + 1);
        loadQuestions(cat);
      });
      wrap.appendChild(b);
    });
  } catch (err) {
    console.warn("loadCategories failed", err);
  }
}

/* Load questions for a category and render them */
async function loadQuestions(cat) {
  try {
    const res = await fetch("/api/chatbot/questions/" + encodeURIComponent(cat) + "/");
    const data = await res.json();
    const qWrap = document.getElementById("questionButtons");
    if (!qWrap) return;
    qWrap.innerHTML = "";
    //appendMessage(`✅ You selected *${cat}*. Now choose a question:`, false);
    (data.questions || []).forEach((q, i) => {
      const b = document.createElement("button");
      b.className = "question-item";
      b.innerHTML = `<span class="num-badge">${i + 1}</span><span class="q-text">${q}</span>`;
      b.addEventListener("click", () => clickQuestion(q));
      qWrap.appendChild(b);
    });
  } catch (err) {
    console.warn("loadQuestions failed", err);
  }
}

/* Handle question click: show user message and fetch answer */
async function clickQuestion(q) {
  appendMessage(q, true);
  try {
    const res = await fetch("/api/chatbot/answer/?" + new URLSearchParams({ q }));
    const data = await res.json();
    let msg = data.answer || "Sorry, I don’t have an answer.";
    if (data.link) {
      const link = data.link;
      if (link.endsWith(".pdf")) msg += `<br><a href="${link}" target="_blank">📄 View PDF</a>`;
      else if (link.match(/\.(png|jpg|jpeg)$/i)) msg += `<br><img src="${link}" class="chatbot-image" onclick="openImagePopup('${link}')" style="max-width:100%;border-radius:8px;margin-top:8px;cursor:pointer;">`;
      else msg += `<br><a href="${link}" target="_blank">🔗 Open Link</a>`;
    }
    appendMessage(msg, false, false, true);
  } catch (err) {
    console.warn("clickQuestion failed", err);
    appendMessage("Sorry, an error occurred while fetching the answer.", false);
  }
  
}

/* Send freeform user message to answer API */
async function sendChatbotMessage() {
  const i = document.getElementById("chatbotInput");
  if (!i) return;
  const msg = i.value.trim();
  if (!msg) return;
  i.value = "";
  appendMessage(msg, true);
  try {
    const res = await fetch("/api/chatbot/answer/?" + new URLSearchParams({ q: msg }));
    const data = await res.json();
    let text = data.answer || "Sorry, I don’t have an answer.";
    if (data.link) text += `<br><a href="${data.link}" target="_blank">🔗 Open Link</a>`;
    appendMessage(text, false, false, true);
  } catch (err) {
    console.warn("sendChatbotMessage failed", err);
    appendMessage("Sorry, an error occurred while sending your message.", false);
  }
}

/* Append a message to the chat area (supports HTML from server) */
function appendMessage(text, isUser, showLabel = true) {
  const box = document.getElementById("chatbotMessages");
  if (!box) return;
  const div = document.createElement("div");
  div.className = "message " + (isUser ? "user-message" : "bot-message");

  if (showLabel && isUser) {
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = "Question";
    div.appendChild(label);
  }

  const content = document.createElement("div");

  if (/<img\s+|<a\s+|<br|<\/\w+>/.test(text)) {
    content.innerHTML = text;
    setTimeout(() => {
      content.querySelectorAll(".chatbot-image").forEach(img => {
        img.onclick = () => openImagePopup(img.src);
      });
    }, 0);
  } else if (text.match(/\.(png|jpg|jpeg)$/i)) {
    const img = document.createElement("img");
    img.src = text;
    img.className = "chatbot-image";
    img.onclick = () => openImagePopup(text);
    content.appendChild(img);
  } else if (text.match(/\.pdf$/i)) {
    content.innerHTML = `<a href="${text}" target="_blank">📄 View PDF</a>`;
  } else if (text.startsWith("http")) {
    content.innerHTML = `<a href="${text}" target="_blank">🔗 Open Link</a>`;
  } else {
    content.innerHTML = text;
  }

  div.appendChild(content);
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

/* Fullscreen image viewer */
/*function openImagePopup(src) {
  const existing = document.querySelector(".image-popup");
  if (existing) existing.remove();
  const popup = document.createElement("div");
  popup.className = "image-popup";
  const img = document.createElement("img");
  img.src = src;
  popup.appendChild(img);
  popup.onclick = () => popup.remove();
  document.body.appendChild(popup);
}*/

/* Expose helper to programmatically set category */
window.setChatbotCategory = function(n) {
  const chip = document.querySelector(`#categoryButtons .category-chip[data-idx="${n}"]`);
  if (chip) chip.click();
};
