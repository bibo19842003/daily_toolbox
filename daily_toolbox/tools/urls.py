from django.urls import path

from . import views

app_name = "tools"

urlpatterns = [
    path("", views.index, name="index"),
    path("icons/", views.icon_list, name="icon_list"),
    path("github/", views.github_page, name="github"),
    path("api/github/ips/", views.github_ips, name="github_ips"),
    path("api/github/hosts/", views.github_hosts, name="github_hosts"),
    path("api/github/hosts/clear/", views.github_hosts_clear, name="github_hosts_clear"),
]
