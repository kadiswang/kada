"""
KADA 多地区管理界面（Director）。

- 启动后按 ui_cfg.slots 拉起若干"地区子进程"，每个子进程运行现有引擎，互不影响。
- 本页面只做编排与展示：列出各地区、增删地区、链接到各地区自带的管理后台。
- 单地区用户无需使用本程序，直接 `python vpngate_manager.py` 即可（行为不变）。

入口：python director.py  （可选环境变量 VPNGATE_DATA_DIR / UI_HOST / UI_PORT / LOCAL_PROXY_PORT）
"""

from __future__ import annotations

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import vpngate_manager
from slot_manager import SlotOrchestrator

ROOT_DIR = Path(__file__).resolve().parent
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
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
    if not regions:
        tabs = "<div class='empty'>尚未配置任何地区，请在右上角添加</div>"
        frames = ""
    else:
        tabs = ""
        frames = ""
        for i, r in enumerate(regions):
            active = " active" if i == 0 else ""
            status = "🟢" if r["alive"] else "🔴"
            label = r["region"] or r["slot_id"]
            tabs += (
                f"<button class='tab{active}' id='tab_{r['slot_id']}' "
                f"onclick=\"selectRegion('{r['slot_id']}')\">{label} {status} "
                f"<span class='x' onclick=\"event.stopPropagation();del('{r['slot_id']}')\">×</span></button>"
            )
            display = "block" if i == 0 else "none"
            src = f"http://127.0.0.1:{r['ui_port']}/"
            frames += (
                f"<iframe id='frame_{r['slot_id']}' class='region-frame' "
                f"style='display:{display}' src='{src}'></iframe>"
            )
    return f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>KADA 多地区管理</title>
<style>
 body{{font-family:-apple-system,system-ui,'Microsoft YaHei',sans-serif;margin:0;background:#f6f7fb;color:#222;height:100vh;display:flex;flex-direction:column}}
 header{{padding:12px 20px;background:#fff;border-bottom:1px solid #eee;display:flex;align-items:center;gap:16px;flex-wrap:wrap}}
 h1{{font-size:18px;margin:0;white-space:nowrap}}
 .tabs{{display:flex;gap:8px;flex-wrap:wrap}}
 .tab{{border:1px solid #ddd;background:#fff;border-radius:18px;padding:6px 14px;cursor:pointer;font-size:14px}}
 .tab.active{{background:#2563eb;color:#fff;border-color:#2563eb}}
 .tab .x{{margin-left:6px;opacity:.6}}
 .tab .x:hover{{opacity:1}}
 .empty{{color:#888;padding:8px 0}}
 .add{{margin-left:auto;display:flex;gap:8px;align-items:center}}
 .add input{{padding:6px 8px;border:1px solid #ddd;border-radius:6px}}
 .add button{{border:none;background:#2563eb;color:#fff;border-radius:6px;padding:6px 14px;cursor:pointer}}
 .frames{{flex:1;position:relative;min-height:0}}
 .region-frame{{position:absolute;inset:0;width:100%;height:100%;border:none;background:#fff}}
</style></head>
<body>
<header>
 <h1>KADA · 多地区出口</h1>
 <div class="tabs">{tabs}</div>
 <div class="add">
  <input id="region" placeholder="国家名，如 Japan" />
  <input id="slotId" placeholder="ID(可选)" style="width:90px" />
  <button onclick="add()">添加地区</button>
 </div>
</header>
<div class="frames">{frames}</div>
<script>
function selectRegion(id){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab_'+id).classList.add('active');
  document.querySelectorAll('.region-frame').forEach(f=>f.style.display='none');
  document.getElementById('frame_'+id).style.display='block';
}}
async function add(){{
  const region=document.getElementById('region').value.trim();
  if(!region){{alert('请填写国家名');return;}}
  const slotId=document.getElementById('slotId').value.trim();
  await fetch('/api/regions',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{region,slot_id:slotId}})}});
  location.reload();
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
    server_addr = (UI_HOST, UI_PORT)
    try:
        server = ThreadingHTTPServer(server_addr, Handler)
    except (OSError, socket.gaierror):
        # Windows / 无 IPv6 环境下 "::" 解析失败，回退到 IPv4 全接口
        server = ThreadingHTTPServer(("0.0.0.0", UI_PORT), Handler)
    print(f"[Director] 多地区管理界面已启动: http://127.0.0.1:{UI_PORT}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if ORCH:
            ORCH.stop_all()


if __name__ == "__main__":
    main()
