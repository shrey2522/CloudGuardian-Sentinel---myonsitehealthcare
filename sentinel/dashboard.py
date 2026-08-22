"""Bonus: risk heatmap dashboard (FastAPI).

Serves a live risk heatmap (provider x severity) plus findings and audit trail.
No external JS/CSS - works offline.
"""
import json

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from sentinel.config import settings
from sentinel.monitor import Monitor
from sentinel.cli import build_components

app = FastAPI(title="CloudGuardian Sentinel Dashboard")

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>CloudGuardian Sentinel</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}
 h1{font-size:22px;margin:0 0 4px} .sub{color:#8b949e;font-size:13px;margin-bottom:20px}
 .grid{display:grid;grid-template-columns:120px repeat(4,110px);gap:6px;margin-bottom:28px;max-width:640px}
 .cell{padding:14px 8px;text-align:center;border-radius:8px;font-weight:600;font-size:15px}
 .sev{background:#161b22;color:#8b949e;font-size:12px}
 .prov{background:#161b22;color:#8b949e;display:flex;align-items:center;justify-content:center;font-size:12px}
 .f0{background:#1c2128;color:#8b949e}.f1{background:#4a1d2e;color:#ff85a0}
 .f2{background:#5a2a12;color:#ffa657}.f3{background:#3b2f12;color:#d29922}.f4{background:#123f2a;color:#56d364}
 table{border-collapse:collapse;width:100%;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d}
 th{color:#8b949e;font-weight:600}
 .badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
 .CRITICAL{background:#5a1d2e;color:#ff7b72}.HIGH{background:#4a3505;color:#d29922}
 .MEDIUM{background:#123f2a;color:#56d364}.LOW{background:#1f2937;color:#93c5fd}
 h2{font-size:16px;margin:24px 0 10px;color:#e6edf3}
 .ts{color:#8b949e;font-size:12px}
</style></head><body>
<h1>CloudGuardian Sentinel &mdash; Risk Heatmap</h1>
<div class="sub" id="meta">loading&hellip;</div>
<div class="grid" id="heatmap"></div>
<h2>Open findings</h2><table id="findings"><thead><tr>
<th>Severity</th><th>Rule</th><th>Resource</th><th>Provider</th><th>Status</th><th>Detected</th>
</tr></thead><tbody></tbody></table>
<h2>Recent audit events</h2><table id="audit"><thead><tr>
<th>Time</th><th>Type</th><th>Actor</th><th>Message</th>
</tr></thead><tbody></tbody></table>
<script>
const SEV=["CRITICAL","HIGH","MEDIUM","LOW"];
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
  document.getElementById('heatmap').innerHTML=html;
}
function esc(s){return (s??'').toString().replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function tick(){
  const r=await fetch('/api/state');const d=await r.json();
  document.getElementById('meta').textContent=
    `last scan ${d.scan_time} | ${d.open_count} open findings | poll ${d.poll_interval}s | auto-remediate ${d.auto_remediate}`;
  heat(d.heatmap);
  document.querySelector('#findings tbody').innerHTML=d.findings.map(f=>
   `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.rule_id)}</td><td>${esc(f.resource_id)}</td><td>${esc(f.provider)}</td>
    <td>${esc(f.status)}</td><td class="ts">${esc(f.last_seen)}</td></tr>`).join('');
  document.querySelector('#audit tbody').innerHTML=d.audit.map(e=>
   `<tr><td class="ts">${esc(e.ts)}</td><td>${esc(e.event_type)}</td><td>${esc(e.actor)}</td>
    <td>${esc(e.message)}</td></tr>`).join('');
}
tick(); setInterval(tick, 5000);
</script></body></html>"""


def _state():
    providers, engine, audit, remediator = build_components()
    monitor = Monitor(providers, engine, audit, remediator, settings)
    findings, statuses = monitor.scan_once()
    store = monitor.load_store()
    open_records = [rec for rec in store.values()
                    if rec.get("status") in ("OPEN", "REMEDIATING", "REMEDIATION_FAILED")]
    heatmap = {}
    for f in findings:
        heatmap.setdefault(f.provider, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        heatmap[f.provider][f.severity] = heatmap[f.provider].get(f.severity, 0) + 1
    return {
        "scan_time": findings[0].detected_at if findings else "clean",
        "open_count": len(findings),
        "poll_interval": settings.poll_interval,
        "auto_remediate": settings.auto_remediate,
        "heatmap": heatmap,
        "findings": [{**f.to_dict(), "status": store.get(f.fingerprint, {}).get("status", "OPEN")}
                     for f in findings],
        "audit": audit.recent(limit=15),
        "providers": statuses,
    }


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


@app.get("/api/state")
def state():
    return _state()


@app.get("/api/findings")
def findings_only():
    return {"findings": _state()["findings"]}
