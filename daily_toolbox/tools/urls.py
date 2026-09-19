from django.urls import path

from . import views

app_name = "tools"

urlpatterns = [
    path("", views.index, name="index"),
    path("icons/", views.icon_list, name="icon_list"),
    path("github/", views.github_page, name="github"),
    path("github-convert/", views.gh_convert_page, name="gh_convert_page"),
    path("convert/", views.image_convert_page, name="image_convert_page"),
    path("compress/", views.compress_page, name="compress_page"),
    path("json/", views.json_page, name="json_page"),
    path("links/", views.links_page, name="links_page"),
    path("api/links/", views.link_list, name="link_list"),
    path("api/links/categories/move/", views.category_move, name="category_move"),
    path("api/links/<int:pk>/move/", views.link_move, name="link_move"),
    path("api/links/<int:pk>/", views.link_detail, name="link_detail"),
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
    path("color/", views.color_page, name="color_page"),
    path("downloader/", views.downloader_page, name="downloader_page"),
    path("api/downloader/http/", views.downloader_http_add, name="downloader_http_add"),
    path("api/downloader/bt/", views.downloader_bt_add, name="downloader_bt_add"),
    path("api/downloader/status/", views.downloader_status, name="downloader_status"),
    path("api/downloader/pause/", views.downloader_pause, name="downloader_pause"),
    path("api/downloader/resume/", views.downloader_resume, name="downloader_resume"),
    path("api/downloader/remove/", views.downloader_remove, name="downloader_remove"),
]
