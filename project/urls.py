
from django.contrib import admin
from django.urls import path, include

# import users.urls
from project import settings
from django.conf.urls.static import static


urlpatterns = [
    # path('admin/', admin.site.urls),
    path("", include("apps.home.urls")),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
