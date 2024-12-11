from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.


def home(request):
    return HttpResponse("Welcome to the Django App! WAF_AI testing , please go to /user/<username>")

def user_profile(request, username):
    return HttpResponse(f"User: {username}")