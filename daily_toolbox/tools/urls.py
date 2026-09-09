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
    path("api/github/remote/", views.github_remote, name="github_remote"),
    path("api/github/remote/apply/", views.github_remote_apply, name="github_remote_apply"),
    path("wifi/", views.wifi_page, name="wifi_page"),
    path("api/wifi/interfaces/", views.wifi_interfaces, name="wifi_interfaces"),
    path("api/wifi/profiles/", views.wifi_profiles, name="wifi_profiles"),
    path("api/wifi/password/", views.wifi_password, name="wifi_password"),
    path("hardware/", views.hardware_page, name="hardware_page"),
    path("api/hardware/", views.hardware_info, name="hardware_info"),
    path("encode/", views.encode_page, name="encode_page"),
    path("api/encode/charset/", views.encode_charset, name="encode_charset"),
    path("timestamp/", views.timestamp_page, name="timestamp_page"),
]
