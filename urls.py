
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from chatbot import views

urlpatterns = [
    path('api/chatbot/categories/', views.chatbot_categories, name='chatbot_categories'),
    path('api/chatbot/questions/<path:category>/', views.chatbot_questions, name='chatbot_questions'),
    path('api/chatbot/answer/', views.chatbot_answer, name='chatbot_answer'),  
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
if settings.DEBUG:

    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

