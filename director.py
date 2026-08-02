"""
AimiliVPN 多地区管理界面（Director）。

- 启动后按 ui_cfg.slots 拉起若干"地区子进程"，每个子进程运行现有引擎，互不影响。
- 本页面只做编排与展示：列出各地区、增删地区、链接到各地区自带的管理后台。
- 单地区用户无需使用本程序，直接 `python vpngate_manager.py` 即可（行为不变）。

入口：python director.py  （可选环境变量 VPNGATE_DATA_DIR / UI_HOST / UI_PORT / LOCAL_PROXY_PORT）
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import vpngate_manager
from slot_manager import SlotOrchestrator

ROOT_DIR = Path(__file__).resolve().parent
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = int(os.environ.get("UI_PORT", "8790"))
BASE_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
DATA_DIR = Path(os.environ.get("VPNGATE_DATA_DIR") or ROOT_DIR / "vpngate_data").resolve()


def build_orchestrator() -> SlotOrchestrator:
    orch = SlotOrchestrator(DATA_DIR, UI_PORT, BASE_PROXY_PORT)
    ui_cfg = vpngate_manager.load_ui_config()
    orch.sync(ui_cfg)
    return orch


ORCH: SlotOrchestrator | None = None


def render_page() -> str:
    assert ORCH is not None
    regions = ORCH.status()
    rows = ""
    if not regions:
        rows = "<tr><td colspan='6' style='text-align:center;color:#888'>尚未配置任何地区，请在下方添加</td></tr>"
    for r in regions:
        link = f"http://127.0.0.1:{r['ui_port']}/" if ":" not in UI_HOST else f"http://[::1]:{r['ui_port']}/"
        alive = "🟢 运行中" if r["alive"] else "🔴 已停止"
        rows += (
            f"<tr><td>{r['slot_id']}</td><td>{r['region'] or '(全部)'}</td>"
            f"<td>{alive}</td><td>{r['tun_dev']}</td><td>{r['proxy_port']}</td>"
            f"<td><a href='{link}' target='_blank'>管理后台 ({r['ui_port']})</a> "
            f"<button onclick=\"del('{r['slot_id']}')\">删除</button></td></tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>AimiliVPN 多地区管理</title>
<style>
 body{{font-family:-apple-system,system-ui,'Microsoft YaHei',sans-serif;margin:24px;background:#f6f7fb;color:#222}}
 h1{{font-size:20px}} table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
 th,td{{padding:10px 12px;border-bottom:1px solid #eee;text-align:left;font-size:14px}}
 th{{background:#fafbfc;color:#555}} a{{color:#2563eb;text-decoration:none}}
 button{{border:1px solid #ddd;background:#fff;border-radius:6px;padding:4px 10px;cursor:pointer}}
 .card{{background:#fff;border-radius:8px;padding:16px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
 input{{padding:6px 8px;border:1px solid #ddd;border-radius:6px;margin-right:8px}}
</style></head>
<body>
<h1>AimiliVPN · 多地区出口管理</h1>
<div class="card">
 <p style="color:#666;margin:0 0 12px">每个地区是独立的 VPN 隧道，互不影响。代理端口 {BASE_PROXY_PORT} 起、管理端口 {UI_PORT} 起分配给各地区。</p>
 <table><thead><tr><th>地区ID</th><th>地区/国家</th><th>状态</th><th>tun</th><th>代理端口</th><th>操作</th></tr></thead>
 <tbody>{rows}</tbody></table>
</div>
<div class="card">
 <h3 style="margin-top:0">添加地区出口</h3>
 <input id="region" placeholder="国家名，如 Japan / United States" />
 <input id="slotId" placeholder="地区ID（可选，如 jp）" />
 <button onclick="add()">添加</button>
 <span id="msg" style="color:#2563eb;margin-left:10px"></span>
</div>
<script>
async function add(){{
  const region=document.getElementById('region').value.trim();
  const slotId=document.getElementById('slotId').value.trim();
  if(!region){{alert('请填写国家名');return;}}
  const r=await fetch('/api/regions',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{region,slot_id:slotId}})}});
  const d=await r.json();
  document.getElementById('msg').textContent=d.ok?'已添加，正在启动…':'失败：'+(d.error||'');
  setTimeout(()=>location.reload(),1200);
}}
async function del(id){{
  if(!confirm('确定删除地区 '+id+'？将停止其隧道并清理资源'))return;
  await fetch('/api/regions/'+encodeURIComponent(id),{{method:'DELETE'}});
  location.reload();
}}
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] in ("/", "/index.html"):
            html = render_page().encode("utf-8")
            self._send(200, html, "text/html; charset=utf-8")
        elif self.path.split("?")[0] == "/api/regions":
            assert ORCH is not None
            self._send(200, json.dumps(ORCH.status(), ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?")[0] == "/api/regions":
            length = int(self.headers.get("Content-Length", "0") or "0")
            try:
                data: dict[str, Any] = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                self._send(400, b'{"ok":false,"error":"bad json"}')
                return
            region = str(data.get("region") or "").strip()
            if not region:
                self._send(400, b'{"ok":false,"error":"region required"}')
                return
            assert ORCH is not None
            ui_cfg = vpngate_manager.load_ui_config()
            ui_cfg = ORCH.add_slot(ui_cfg, {"region": region, "slot_id": data.get("slot_id"), "enabled": True})
            self._send(200, json.dumps({"ok": True, "slots": ui_cfg.get("slots")}, ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, b'{"error":"not found"}')

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.startswith("/api/regions/"):
            slot_id = self.path.split("/api/regions/", 1)[1].split("?")[0]
            assert ORCH is not None
            ui_cfg = vpngate_manager.load_ui_config()
            ORCH.remove_slot(ui_cfg, slot_id)
            self._send(200, json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, b'{"error":"not found"}')

    def log_message(self, *args: Any) -> None:  # 静默访问日志
        return


def main() -> None:
    global ORCH
    ORCH = build_orchestrator()
    server = ThreadingHTTPServer((UI_HOST, UI_PORT))
    print(f"[Director] 多地区管理界面已启动: http://127.0.0.1:{UI_PORT}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if ORCH:
            ORCH.stop_all()


if __name__ == "__main__":
    main()
