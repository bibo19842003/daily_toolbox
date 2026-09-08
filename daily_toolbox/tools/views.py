import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST


def index(request):
    return render(request, "index.html")


# ============================================================
# 图标列表
# ============================================================

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


# ============================================================
# 访问 GitHub（解析 IP / 测延迟 / 修改 hosts）
# ============================================================

GITHUB_DOMAINS = [
    "github.com",
    "api.github.com",
    "assets-cdn.github.com",
    "github.global.ssl.fastly.net",
    "raw.githubusercontent.com",
    "gist.github.com",
    "codeload.github.com",
]

# 公共 DoH 接口（国内可达，绕过本地 DNS 污染）
DOH_PROVIDERS = [
    "https://dns.alidns.com/resolve?name={domain}&type=A",
    "https://1.12.12.12/dns-query?name={domain}&type=A",
]

HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"

# 方案二：社区维护的 GitHub 加速 hosts 订阅源（定期更新各域名最优 IP）
REMOTE_HOSTS_URL = "https://gitlab.com/ineo6/hosts/-/raw/master/hosts?ref_type=heads&inline=false"


def _doh_resolve(domain):
    """通过公共 DoH 接口解析域名，返回 A 记录 IP 列表。"""
    for tpl in DOH_PROVIDERS:
        try:
            req = urllib.request.Request(
                tpl.format(domain=domain),
                headers={"accept": "application/dns-json", "user-agent": "daily-toolbox"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips
        except Exception:
            continue
    return []


def _tcp_ping(ip, port=443, timeout=2.0):
    """测试与 IP:443 的 TCP 连接延迟（毫秒），失败返回 None。"""
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return round((time.perf_counter() - start) * 1000)
    except OSError:
        return None


def _github_web_check(ip, timeout=6):
    """预检：验证该 IP 是否为真正的 github.com 服务节点（TLS 证书校验）。

    raw.githubusercontent.com、assets-cdn.github.com 等 CDN 域名的 IP 虽然可以
    TCP 连通且延迟很低，但它们不服务 github.com 网页，写入后访问会报错，
    此预检通过证书匹配将其拦下。

    注意：即使 TLS 校验通过，GitHub 边缘也可能因反滥用策略对当前网络出口的
    github.com 主站请求返回 400 "Whoa there" 拦截页——该拦截与所选 IP 无关
    （同一边缘上 api.github.com 正常 200），写入与否不影响此结果，故不算失败。
    """
    ctx = ssl.create_default_context()
    sock = None
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname="github.com") as tls:
            sock = None  # 连接已由 tls 接管
            if not tls.getpeercert():
                return False, "未获取到证书"
            tls.sendall(
                b"HEAD / HTTP/1.1\r\nHost: github.com\r\n"
                b"User-Agent: Mozilla/5.0 (daily-toolbox)\r\nConnection: close\r\n\r\n"
            )
            data = b""
            while len(data) < 4096:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
        head = data.decode("iso-8859-1", "replace")
        if head.startswith("HTTP/"):
            status = head.split(" ")[1]
            if status == "200":
                return True, "HTTP 200"
            return True, f"HTTP {status}（GitHub 反滥用拦截，与 IP 无关）"
        return True, "TLS 证书校验通过"
    except Exception as exc:
        return False, exc.__class__.__name__
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _read_hosts_text():
    raw = HOSTS_PATH.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="replace")


def _is_github_com_mapping(line):
    """判断该行是否为 github.com 的生效映射（行首为 IP + github.com，忽略注释）。"""
    valid = line.split("#", 1)[0].split()
    return len(valid) >= 2 and valid[1] == "github.com"


def github_page(request):
    try:
        current = [line for line in _read_hosts_text().splitlines() if _is_github_com_mapping(line)]
    except OSError:
        current = []
    return render(request, "github.html", {"current_hosts": current})


@require_GET
def github_ips(request):
    """解析 GitHub 相关域名，测试各 IP 延迟，并实测每个 IP 能否服务 github.com。"""
    with ThreadPoolExecutor(max_workers=8) as pool:
        resolved = dict(zip(GITHUB_DOMAINS, pool.map(_doh_resolve, GITHUB_DOMAINS)))

    ip_domains = {}
    for domain, ips in resolved.items():
        for ip in ips:
            ip_domains.setdefault(ip, []).append(domain)

    unique_ips = list(ip_domains)
    with ThreadPoolExecutor(max_workers=20) as pool:
        latencies = dict(zip(unique_ips, pool.map(_tcp_ping, unique_ips)))
    # GitHub 边缘 IP 会在不同服务间轮换，按解析来源判断不可靠，
    # 直接用 TLS SNI + HTTP 探测实测每个 IP 能否服务 github.com
    with ThreadPoolExecutor(max_workers=10) as pool:
        web_ok = dict(zip(unique_ips, pool.map(lambda ip: _github_web_check(ip)[0], unique_ips)))

    domains_payload = [
        {
            "domain": domain,
            "ips": [{"ip": ip, "latency": latencies[ip], "web_ok": web_ok[ip]} for ip in ips],
        }
        for domain, ips in resolved.items()
    ]
    # 实测可用的 IP 排在最前，便于默认选择
    sorted_ips = sorted(
        (
            {
                "ip": ip,
                "domains": ip_domains[ip],
                "latency": latencies[ip],
                "web_ok": web_ok[ip],
            }
            for ip in unique_ips
        ),
        key=lambda item: (not item["web_ok"], item["latency"] is None, item["latency"] or 0),
    )
    return JsonResponse({"domains": domains_payload, "ips": sorted_ips})


def _backup_and_write_hosts(kept_lines):
    """备份原 hosts 后写入新内容，返回备份文件路径。"""
    backup = HOSTS_PATH.with_name("hosts.toolbox.bak")
    shutil.copy2(HOSTS_PATH, backup)
    with open(HOSTS_PATH, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write("\n".join(kept_lines) + "\n")
    return str(backup)


def _flush_dns():
    """刷新 Windows DNS 缓存，返回是否成功。"""
    if os.name != "nt":
        return False
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


@require_POST
def github_hosts(request):
    """将选中的 IP 写入 hosts，替换 github.com 的映射。"""
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "message": "请求格式错误"}, status=400)

    ip = str(payload.get("ip", "")).strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JsonResponse({"ok": False, "message": f"无效的 IP 地址：{ip}"}, status=400)

    # 预检：该 IP 必须能正常服务 github.com，否则写入后访问会得到
    # "Whoa there! invalid request" 错误页（CDN 域名的 IP 会触发此问题）
    check_ok, check_detail = _github_web_check(ip)
    if not check_ok:
        return JsonResponse(
            {
                "ok": False,
                "message": f"预检失败：该 IP 无法正常服务 github.com（{check_detail}）。"
                "请选择所属域名包含 github.com 的 IP。",
            },
            status=400,
        )

    try:
        text = _read_hosts_text()
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"无法读取 hosts 文件：{exc}"}, status=500)

    old_lines = [line for line in text.splitlines() if _is_github_com_mapping(line)]
    kept = [line for line in text.splitlines() if not _is_github_com_mapping(line)]

    stamp = timezone.localtime().strftime("%Y-%m-%d %H:%M:%S")
    new_line = f"{ip}\tgithub.com\t# Daily Toolbox {stamp}"
    kept.append(new_line)

    try:
        backup = _backup_and_write_hosts(kept)
    except PermissionError:
        return JsonResponse(
            {"ok": False, "message": "权限不足：修改 hosts 需要管理员权限，请以管理员身份运行 Django 服务器后重试"},
            status=500,
        )
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"写入 hosts 失败：{exc}"}, status=500)

    return JsonResponse({
        "ok": True,
        "old_lines": old_lines,
        "new_line": new_line,
        "backup": backup,
        "dns_flushed": _flush_dns(),
    })


@require_POST
def github_hosts_clear(request):
    """清除 hosts 中所有生效的 github.com 映射，恢复默认 DNS 解析。"""
    try:
        text = _read_hosts_text()
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"无法读取 hosts 文件：{exc}"}, status=500)

    old_lines = [line for line in text.splitlines() if _is_github_com_mapping(line)]
    if not old_lines:
        return JsonResponse({"ok": True, "removed": 0, "old_lines": [], "message": "hosts 中没有 github.com 的映射，无需清除"})

    kept = [line for line in text.splitlines() if not _is_github_com_mapping(line)]
    try:
        backup = _backup_and_write_hosts(kept)
    except PermissionError:
        return JsonResponse(
            {"ok": False, "message": "权限不足：修改 hosts 需要管理员权限，请以管理员身份运行 Django 服务器后重试"},
            status=500,
        )
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"写入 hosts 失败：{exc}"}, status=500)

    return JsonResponse({
        "ok": True,
        "removed": len(old_lines),
        "old_lines": old_lines,
        "backup": backup,
        "dns_flushed": _flush_dns(),
    })


# ------------------------------------------------------------
# 方案二：远程 hosts 订阅源（ineo6/hosts）
# ------------------------------------------------------------

REMOTE_SECTION_BEGIN = "# ===== Daily Toolbox 远程 hosts 源（ineo6/hosts）"
REMOTE_SECTION_END = "# ===== Daily Toolbox 远程 hosts 源 结束 ====="


def _fetch_remote_hosts(url, timeout=15):
    """拉取远程 hosts 订阅源内容。"""
    req = urllib.request.Request(url, headers={"user-agent": "daily-toolbox"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _parse_hosts_lines(text):
    """解析出有效映射行，返回 [(原始行, ip, [域名...]), ...]。"""
    result = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        valid = s.split("#", 1)[0].split()
        if len(valid) < 2:
            continue
        try:
            ipaddress.ip_address(valid[0])
        except ValueError:
            continue
        result.append((line, valid[0], valid[1:]))
    return result


def _line_domains(line):
    """返回该行映射的所有域名（忽略注释部分）。"""
    valid = line.split("#", 1)[0].split()
    return set(valid[1:]) if len(valid) >= 2 else set()


def _remove_old_remote_section(lines):
    """移除上一次写入的远程源段落（避免重复应用时累积）。"""
    result, in_section = [], False
    for line in lines:
        s = line.strip()
        if s.startswith(REMOTE_SECTION_BEGIN):
            in_section = True
            continue
        if s == REMOTE_SECTION_END.strip():
            in_section = False
            continue
        if not in_section:
            result.append(line)
    return result


@require_GET
def github_remote(request):
    """获取远程 hosts 源内容并解析，返回预览信息（不写入）。"""
    try:
        text = _fetch_remote_hosts(REMOTE_HOSTS_URL)
    except Exception as exc:
        return JsonResponse({"ok": False, "message": f"获取远程 hosts 失败：{exc.__class__.__name__}"}, status=502)

    mappings = _parse_hosts_lines(text)
    if not mappings:
        return JsonResponse({"ok": False, "message": "远程 hosts 内容为空或格式不符"}, status=502)

    domains = sorted({d for _, _, ds in mappings for d in ds})
    return JsonResponse({
        "ok": True,
        "added": len(mappings),
        "domain_count": len(domains),
        "domains": domains,
        "preview": [line for line, _, _ in mappings[:50]],
    })


@require_POST
def github_remote_apply(request):
    """拉取远程 hosts 源，替换本机 hosts 中相同域名的映射后合并写入。"""
    try:
        text = _fetch_remote_hosts(REMOTE_HOSTS_URL)
    except Exception as exc:
        return JsonResponse({"ok": False, "message": f"获取远程 hosts 失败：{exc.__class__.__name__}"}, status=502)

    mappings = _parse_hosts_lines(text)
    if not mappings:
        return JsonResponse({"ok": False, "message": "远程 hosts 内容为空或格式不符"}, status=502)

    remote_domains = {d for _, _, ds in mappings for d in ds}

    try:
        local_text = _read_hosts_text()
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"无法读取 hosts 文件：{exc}"}, status=500)

    # 移除与远程源域名重叠的旧映射，以及上次的远程源段落
    old_lines, kept = [], []
    lines = _remove_old_remote_section(local_text.splitlines())
    for line in lines:
        if not line.strip().startswith("#") and (_line_domains(line) & remote_domains):
            old_lines.append(line)
        else:
            kept.append(line)

    stamp = timezone.localtime().strftime("%Y-%m-%d %H:%M:%S")
    section = [
        f"{REMOTE_SECTION_BEGIN} {stamp} =====",
        *[line for line, _, _ in mappings],
        REMOTE_SECTION_END,
    ]
    kept.extend(section)

    try:
        backup = _backup_and_write_hosts(kept)
    except PermissionError:
        return JsonResponse(
            {"ok": False, "message": "权限不足：修改 hosts 需要管理员权限，请以管理员身份运行 Django 服务器后重试"},
            status=500,
        )
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"写入 hosts 失败：{exc}"}, status=500)

    github_lines = [line for line, _, ds in mappings if "github.com" in ds]
    return JsonResponse({
        "ok": True,
        "removed": len(old_lines),
        "added": len(mappings),
        "domain_count": len(remote_domains),
        "old_lines": old_lines[:20],
        "github_lines": github_lines,
        "backup": backup,
        "dns_flushed": _flush_dns(),
    })


# ------------------------------------------------------------
# 本机 WiFi 信息（netsh wlan）
# ------------------------------------------------------------

def wifi_page(request):
    return render(request, "wifi.html")


def _run_netsh(args, timeout=15):
    """执行 netsh wlan 命令，返回解码后的输出文本。"""
    completed = subprocess.run(["netsh", "wlan", *args], capture_output=True, timeout=timeout)
    text = completed.stdout.decode("gbk", "replace")
    if not text.strip():
        text = completed.stderr.decode("gbk", "replace")
    return text


@require_GET
def wifi_interfaces(request):
    """当前 WLAN 接口的连接信息（兼容中英文系统输出）。"""
    text = _run_netsh(["show", "interfaces"])
    items = []
    for line in text.splitlines():
        m = re.match(r"\s{2,}(.+?)\s*:\s(.+)$", line)
        if not m:
            continue
        label, value = m.group(1).strip(), m.group(2).strip()
        if not label or not value or label.lower() == "guid":
            continue
        items.append([label, value])
    return JsonResponse({"ok": bool(items), "items": items})


@require_GET
def wifi_profiles(request):
    """已保存的 WLAN 配置文件列表 + 当前连接的 SSID。"""
    profiles = []
    for line in _run_netsh(["show", "profiles"]).splitlines():
        m = re.match(r"\s*(?:所有用户配置文件|All User Profile)\s*:\s(.+)$", line)
        if m and m.group(1).strip():
            profiles.append(m.group(1).strip())

    current = ""
    m = re.search(r"^\s*SSID\s*:\s(.+)$", _run_netsh(["show", "interfaces"]), re.M)
    if m:
        current = m.group(1).strip()
    return JsonResponse({"ok": True, "profiles": profiles, "current": current})


@require_GET
def wifi_password(request):
    """查看指定 WiFi 的明文密码（来自本机存储的配置文件）。"""
    ssid = request.GET.get("ssid", "").strip()
    if not ssid or len(ssid) > 64 or "\n" in ssid or '"' in ssid:
        return JsonResponse({"ok": False, "message": "无效的 WiFi 名称"}, status=400)

    text = _run_netsh(["show", "profile", f'name="{ssid}"', "key=clear"])

    if "not found" in text or "找不到" in text or "没有" in text:
        return JsonResponse({"ok": False, "message": "未找到该 WiFi 的配置文件"}, status=404)

    pm = re.search(r"(?:Key Content|关键内容)\s*:\s(.+)$", text, re.M)
    if not pm:
        return JsonResponse({"ok": False, "message": "该 WiFi 未存储密码（可能是开放网络）"}, status=404)

    auth = re.search(r"(?:Authentication|身份验证)\s*:\s(.+)$", text, re.M)
    cipher = re.search(r"(?:Cipher|加密)\s*:\s(.+)$", text, re.M)
    return JsonResponse({
        "ok": True,
        "ssid": ssid,
        "password": pm.group(1).strip(),
        "auth": auth.group(1).strip() if auth else "",
        "cipher": cipher.group(1).strip() if cipher else "",
    })
