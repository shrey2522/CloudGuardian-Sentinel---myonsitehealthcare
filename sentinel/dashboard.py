"""Control-center dashboard (FastAPI) - the whole Sentinel demo in one page.

Read side:  risk heatmap, live findings, audit trail (auto-refresh).
Write side: buttons that drive the exact same CLI commands (scan, demo-setup,
remediate --all, rollback --latest, ci-scan --gate-only) in a background
process, with their output streamed into an on-page console.
"""
import subprocess
import sys
import threading
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from sentinel.cli import build_components
from sentinel.config import settings
from sentinel.monitor import Monitor
from sentinel.models import utcnow

app = FastAPI(title="CloudGuardian Sentinel Control Center")

ACTIONS = {
    "scan":          ["scan"],
    "demo-setup":    ["demo-setup"],
    "remediate-all": ["remediate", "--all"],
    "rollback":      ["rollback", "--latest"],
    "gate":          ["ci-scan", "--gate-only"],
}

# ------------------------------------------------------------------ scan cache
_cache = {"ts": 0.0, "data": None}
_cache_lock = threading.Lock()


def _compute_state(force=False):
    with _cache_lock:
        if not force and _cache["data"] and time.time() - _cache["ts"] < 20:
            return _cache["data"]
        providers, engine, audit, remediator = build_components()
        monitor = Monitor(providers, engine, audit, remediator, settings)
        findings, statuses = monitor.scan_once()
        store = monitor.load_store()
        heatmap = {}
        for f in findings:
            heatmap.setdefault(f.provider, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
            heatmap[f.provider][f.severity] = heatmap[f.provider].get(f.severity, 0) + 1
        data = {
            "scan_time": findings[0].detected_at if findings else "clean",
            "open_count": len(findings),
            "poll_interval": settings.poll_interval,
            "auto_remediate": settings.auto_remediate,
            "heatmap": heatmap,
            "findings": [{**f.to_dict(),
                          "status": store.get(f.fingerprint, {}).get("status", "OPEN")}
                         for f in findings],
            "audit": audit.recent(limit=20),
            "providers": statuses,
        }
        _cache["ts"], _cache["data"] = time.time(), data
        return data


# ------------------------------------------------------------------- actions
_action = {"running": False, "name": None, "started_at": None,
           "finished_at": None, "exit_code": None, "lines": []}
_action_lock = threading.Lock()


def _run_action(name):
    global _cache
    cmd = [sys.executable, "-m", "sentinel"] + ACTIONS[name]
    proc = subprocess.Popen(cmd, cwd=str(settings.base_dir), text=True, bufsize=1,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for line in proc.stdout:
            _action["lines"].append(line.rstrip())
            if len(_action["lines"]) > 400:
                del _action["lines"][:150]
        _action["exit_code"] = proc.wait()
    finally:
        _action["running"] = False
        _action["finished_at"] = utcnow()
        with _cache_lock:
            _cache["ts"] = 0.0   # force fresh scan on next poll


@app.post("/api/action/{name}")
def start_action(name: str):
    if name not in ACTIONS:
        raise HTTPException(404, f"unknown action '{name}'")
    with _action_lock:
        if _action["running"]:
            return {"started": False, "reason": f"'{_action['name']}' is still running"}
        _action.update(running=True, name=name, started_at=utcnow(),
                       finished_at=None, exit_code=None, lines=[])
    threading.Thread(target=_run_action, args=(name,), daemon=True).start()
    return {"started": True, "action": name}


@app.get("/api/action/status")
def action_status():
    return dict(_action)


# ---------------------------------------------------------------------- page
PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>CloudGuardian Sentinel</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:22px}
 h1{font-size:21px;margin:0} .sub{color:#8b949e;font-size:13px;margin:4px 0 18px}
 .chips{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
 .chip{background:#161b22;border:1px solid #21262d;border-radius:14px;padding:4px 12px;font-size:12px}
 .ok{color:#56d364}.bad{color:#ff7b72}.dim{color:#8b949e}
 .bar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}
 .btn{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:8px;
      padding:10px 16px;font-size:13px;font-weight:600;cursor:pointer}
 .btn:hover{background:#30363d}.btn:disabled{opacity:.45;cursor:not-allowed}
 .btn.danger{border-color:#6e2a3a}.btn.good{border-color:#1f4c38}
 .cols{display:grid;grid-template-columns:1fr 1fr;gap:22px}
 @media(max-width:1000px){.cols{grid-template-columns:1fr}}
 .grid{display:grid;grid-template-columns:110px repeat(4,100px);gap:6px;margin-bottom:8px}
 .cell{padding:13px 6px;text-align:center;border-radius:8px;font-weight:600;font-size:14px}
 .sev{background:#161b22;color:#8b949e;font-size:11px}
 .prov{background:#161b22;color:#8b949e;display:flex;align-items:center;justify-content:center;font-size:11px}
 .f0{background:#1c2128;color:#8b949e}.f1{background:#4a1d2e;color:#ff85a0}
 .f2{background:#5a2a12;color:#ffa657}.f3{background:#3b2f12;color:#d29922}
 table{border-collapse:collapse;width:100%;font-size:12.5px}
 th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #21262d}
 th{color:#8b949e;font-weight:600}
 .badge{padding:2px 7px;border-radius:10px;font-size:10.5px;font-weight:700}
 .CRITICAL{background:#5a1d2e;color:#ff7b72}.HIGH{background:#4a3505;color:#d29922}
 .MEDIUM{background:#123f2a;color:#56d364}.LOW{background:#1f2937;color:#93c5fd}
 h2{font-size:14px;margin:0 0 10px;color:#e6edf3}
 pre{background:#010409;border:1px solid #21262d;border-radius:8px;padding:12px;font-size:11.5px;
     max-height:340px;overflow:auto;white-space:pre-wrap;margin:0;color:#8b949e}
 .ts{color:#8b949e;font-size:11.5px;white-space:nowrap}
 .spin{display:inline-block;animation:pulse 1.2s infinite}@keyframes pulse{50%{opacity:.35}}
</style></head><body>
<h1>CloudGuardian Sentinel &mdash; Control Center</h1>
<div class="sub" id="meta">loading&hellip;</div>

<div class="chips" id="chips"></div>

<div class="bar">
 <button class="btn good"  onclick="act('scan')">Scan now</button>
 <button class="btn danger" onclick="act('demo-setup')">Plant misconfigurations (demo-setup)</button>
 <button class="btn good"  onclick="act('remediate-all')">Remediate all</button>
 <button class="btn"       onclick="act('rollback')">Rollback last fix</button>
 <button class="btn"       onclick="act('gate')">Run CI gate check</button>
</div>

<div class="cols">
 <div>
  <h2>Risk heatmap</h2>
  <div class="grid" id="heatmap"></div>
  <h2 style="margin-top:18px">Open findings</h2>
  <table id="findings"><thead><tr>
   <th>Severity</th><th>Rule</th><th>Resource</th><th>Status</th></tr></thead>
   <tbody></tbody></table>
  <h2 style="margin-top:18px">Audit trail</h2>
  <table id="audit"><thead><tr>
   <th>Time</th><th>Type</th><th>Actor</th><th>Message</th></tr></thead><tbody></tbody></table>
 </div>
 <div>
  <h2 id="console-title">Console</h2>
  <pre id="console">idle</pre>
 </div>
</div>

<script>
const SEV=["CRITICAL","HIGH","MEDIUM","LOW"];
function esc(s){return (s??'').toString().replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function heat(counts){
  const provs=Object.keys(counts||{});
  let html='<div class="cell sev"></div>'+SEV.map(s=>`<div class="cell sev">${s}</div>`).join('');
  for(const p of provs){
    html+=`<div class="cell prov">${p.toUpperCase()}</div>`;
    for(const s of SEV){
      const n=(counts[p]||{})[s]||0;
      const cls=n===0?'f0':(SEV.indexOf(s)===0?'f1':SEV.indexOf(s)===1?'f2':SEV.indexOf(s)===2?'f3':'f4');
      html+=`<div class="cell ${cls}">${n}</div>`;
    }
  }
  document.getElementById('heatmap').innerHTML=html||'<div class="dim">no providers</div>';
}
async function act(name){
  const r=await fetch('/api/action/'+name,{method:'POST'});
  const d=await r.json();
  if(!d.started){document.getElementById('console').textContent=
    'busy: '+(d.reason||'another action is running');return}
  document.getElementById('console').textContent='starting '+name+' ...';
  pollAction(true);
}
let actionBusy=false;
async function pollAction(kick){
  const r=await fetch('/api/action/status');const a=await r.json();
  const con=document.getElementById('console');
  const title=document.getElementById('console-title');
  if(a.name&&(a.running||a.lines.length)){
    title.innerHTML=a.running?`Console &mdash; ${esc(a.name)} <span class="spin">&#9679;</span>`
                             :`Console &mdash; ${esc(a.name)} (exit ${a.exit_code})`;
    con.textContent=a.lines.join('\\n')||'running...';
    con.scrollTop=con.scrollHeight;
  }
  actionBusy=a.running;
  document.querySelectorAll('.btn').forEach(b=>b.disabled=a.running);
  if(a.running||kick)setTimeout(pollAction,2000);
}
async function tick(){
  try{
    const r=await fetch('/api/state');const d=await r.json();
    document.getElementById('meta').textContent=
      `last scan ${d.scan_time} | ${d.open_count} open findings | `+
      `poll ${d.poll_interval}s | auto-remediate ${d.auto_remediate}`;
    const chips=[];
    for(const [p,st] of Object.entries(d.providers||{})){
      const ok=st.healthy||p==='gcp'&&st.resources>0;
      chips.push(`<span class="chip">${p.toUpperCase()}:
        <span class="${st.healthy?'ok':'bad'}">${st.healthy?'healthy':'unhealthy'}</span>
        <span class="dim">(${st.resources??0} resources)</span></span>`);
    }
    chips.push(`<span class="chip">open findings: <span class="${d.open_count?'bad':'ok'}">${d.open_count}</span></span>`);
    document.getElementById('chips').innerHTML=chips.join('');
    heat(d.heatmap);
    document.querySelector('#findings tbody').innerHTML=d.findings.map(f=>
     `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.rule_id)}</td><td>${esc(f.resource_id)}<br><span class="ts">${esc(f.provider)} &middot; ${esc(f.region)}</span></td>
      <td>${esc(f.status)}</td></tr>`).join('')||'<tr><td colspan="4" class="dim">clean</td></tr>';
    document.querySelector('#audit tbody').innerHTML=d.audit.map(e=>
     `<tr><td class="ts">${esc(e.ts)}</td><td>${esc(e.event_type)}</td>
      <td class="ts">${esc(e.actor)}</td><td>${esc(e.message)}</td></tr>`).join('');
  }catch(e){document.getElementById('meta').textContent='refresh failed: '+e}
}
tick();pollAction();setInterval(tick,5000);setInterval(()=>{if(!actionBusy)pollAction()},5000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


@app.get("/api/state")
def state():
    return _compute_state()


@app.get("/api/findings")
def findings_only():
    return {"findings": _compute_state()["findings"]}
