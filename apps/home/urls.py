
from django.urls import path, re_path
from apps.home import views

urlpatterns = [

    # # The home page
    path('', views.scan_page, name='index'),
    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
