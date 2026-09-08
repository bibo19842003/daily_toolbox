import re
from functools import lru_cache

from django.conf import settings
from django.shortcuts import render


def index(request):
    return render(request, "index.html")


# 图标数据来源：本地部署的 bootstrap-icons.min.css（与 icons.getbootstrap.com 同源官方数据）
ICON_CSS_PATH = (
    settings.BASE_DIR / "static" / "vendor" / "bootstrap-icons" / "bootstrap-icons.min.css"
)


@lru_cache
def load_icon_names():
    """从图标字体 CSS 中提取所有图标名，如 braces、github、house-door。"""
    css = ICON_CSS_PATH.read_text(encoding="utf-8")
    names = re.findall(r"\.bi-([a-z0-9-]+)::before", css)
    return tuple(dict.fromkeys(names))


def icon_list(request):
    return render(request, "icons.html", {"icons": load_icon_names()})
