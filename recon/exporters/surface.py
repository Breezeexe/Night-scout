# ruff: noqa: E501
"""Safe deterministic exporters for attack-surface graph snapshots."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from recon.surface.models import SurfaceGraphSnapshot
from recon.surface.tree import build_tree_projection


async def export_graph_json(snapshot: SurfaceGraphSnapshot, destination: Path) -> Path:
    payload = snapshot.model_dump(mode="json")
    return _atomic_json(destination, payload)


async def export_tree_json(snapshot: SurfaceGraphSnapshot, destination: Path) -> Path:
    return _atomic_json(destination, build_tree_projection(snapshot))


async def export_surface_html(snapshot: SurfaceGraphSnapshot, destination: Path) -> Path:
    graph_json = (
        json.dumps(
            snapshot.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    tree_json = (
        json.dumps(
            build_tree_projection(snapshot),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    html = _HTML_TEMPLATE.replace("__GRAPH_DATA__", graph_json).replace("__TREE_DATA__", tree_json)
    return _atomic_text(destination, html)


def _atomic_json(destination: Path, payload: Any) -> Path:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return _atomic_text(destination, text)


def _atomic_text(destination: Path, text: str) -> Path:
    path = destination.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return path


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Night Scout · Surface Graph</title>
<style>
:root{color-scheme:dark;--bg:#071018;--panel:#0e1b26;--panel2:#122534;--line:#284457;--text:#eaf5fb;--muted:#8ca7b7;--cyan:#43d9d0;--blue:#4f8cff;--amber:#ffc857;--red:#ff6b78;--green:#63e6a5;--violet:#bc8cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% -10%,#15374a 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}header{position:sticky;top:0;z-index:5;padding:20px 28px;background:rgba(7,16,24,.93);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}h1{margin:0;font-size:22px;letter-spacing:.02em}.subtitle{color:var(--muted);margin-top:4px}.controls{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}input,select{background:#09151e;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 12px;outline:none}input{min-width:300px}main{display:grid;grid-template-columns:minmax(520px,1fr) 380px;gap:18px;padding:18px 28px}.summary{display:grid;grid-template-columns:repeat(4,minmax(100px,1fr));gap:10px;margin-bottom:14px}.metric,.panel{background:linear-gradient(145deg,rgba(18,37,52,.96),rgba(10,25,35,.96));border:1px solid var(--line);border-radius:12px;box-shadow:0 16px 36px rgba(0,0,0,.18)}.metric{padding:13px}.metric strong{display:block;font-size:22px;color:var(--cyan)}.metric span{color:var(--muted);font-size:12px}.panel{padding:15px;min-height:120px}.tree ul{list-style:none;margin:0;padding-left:25px;position:relative}.tree ul:before{content:"";position:absolute;left:9px;top:0;bottom:12px;border-left:1px solid var(--line)}.tree>ul{padding-left:0}.tree>ul:before{display:none}.tree li{position:relative;margin:5px 0}.tree li:before{content:"";position:absolute;left:-16px;top:17px;width:15px;border-top:1px solid var(--line)}.tree>ul>li:before{display:none}.node{display:flex;align-items:center;gap:8px;width:100%;text-align:left;background:#0b1923;border:1px solid transparent;color:var(--text);border-radius:9px;padding:8px 10px;cursor:pointer}.node:hover,.node.active{border-color:var(--cyan);background:#102836}.toggle{width:18px;color:var(--muted)}.kind{font-size:10px;color:var(--cyan);letter-spacing:.08em}.value{overflow-wrap:anywhere}.badge{font-size:10px;padding:2px 6px;border-radius:999px;background:#1c3444;color:var(--muted)}.CONFIRMED{color:var(--green)}.HYPOTHESIS{color:var(--amber)}.HISTORICAL{color:var(--violet)}.OUT_OF_SCOPE{color:var(--red)}.http-status{font-weight:800;color:#061018}.http-1xx{background:var(--muted)}.http-2xx{background:var(--green)}.http-3xx{background:var(--blue);color:#fff}.http-4xx{background:var(--amber)}.http-5xx{background:var(--red)}.relation{font-size:10px;color:#6d8fa2}.hidden{display:none!important}.details{position:sticky;top:132px;max-height:calc(100vh - 155px);overflow:auto}.details h2{font-size:17px;margin:0 0 8px}.details h3{font-size:13px;margin:16px 0 7px;color:var(--cyan)}.details dl{display:grid;grid-template-columns:110px 1fr;gap:7px;margin:12px 0}.details dt{color:var(--muted)}.details dd{margin:0;overflow-wrap:anywhere}.details pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#071018;padding:10px;border-radius:8px;color:#b9d1de;font-size:11px}.http-history{width:100%;border-collapse:collapse;font-size:11px}.http-history th,.http-history td{text-align:left;vertical-align:top;padding:6px 4px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.http-history th{color:var(--muted);font-weight:500}.http-history-note{display:block;margin-top:6px;color:var(--muted);font-size:10px}.empty{color:var(--muted);padding:20px;text-align:center}@media(max-width:950px){main{grid-template-columns:1fr}.details{position:static;max-height:none}.summary{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<header><h1>Night Scout · Surface Graph</h1><div class="subtitle" id="subtitle"></div><div class="controls"><input id="search" placeholder="Search domains, URLs, IPs, technologies, CVEs…"><select id="state"><option value="">All states</option><option>CONFIRMED</option><option>HYPOTHESIS</option><option>HISTORICAL</option><option>OBSERVED</option></select><select id="kind"><option value="">All node kinds</option></select></div></header>
<main><section><div class="summary"><div class="metric"><strong id="nodes">0</strong><span>surface nodes</span></div><div class="metric"><strong id="edges">0</strong><span>semantic edges</span></div><div class="metric"><strong id="confirmed">0</strong><span>confirmed</span></div><div class="metric"><strong id="hypotheses">0</strong><span>hypotheses</span></div></div><div class="panel tree" id="tree"></div></section><aside class="panel details" id="details"><div class="empty">Select a node to inspect evidence and coverage.</div></aside></main>
<script type="application/json" id="graph-data">__GRAPH_DATA__</script>
<script type="application/json" id="tree-data">__TREE_DATA__</script>
<script>
const graph=JSON.parse(document.getElementById('graph-data').textContent),projection=JSON.parse(document.getElementById('tree-data').textContent),byId=new Map(graph.nodes.map(n=>[n.node_id,n]));
const $=id=>document.getElementById(id);
$('subtitle').textContent=`target ${graph.target_id} · generated ${new Date(graph.generated_at).toLocaleString()} · fingerprint ${graph.fingerprint.slice(0,12)}`;
$('nodes').textContent=graph.statistics.node_count;$('edges').textContent=graph.statistics.edge_count;$('confirmed').textContent=graph.statistics.nodes_by_state.CONFIRMED||0;$('hypotheses').textContent=graph.statistics.nodes_by_state.HYPOTHESIS||0;
Object.keys(graph.statistics.nodes_by_kind).sort().forEach(k=>{const o=document.createElement('option');o.textContent=k;$('kind').append(o)});
function httpStatusCode(n){const code=Number(n&&n.metadata&&n.metadata.status_code);return Number.isInteger(code)&&code>=100&&code<=599?code:null}
function httpStatusClass(code){return `http-${Math.floor(code/100)}xx`}
function appendHttpBadge(container,n){const code=httpStatusCode(n);if(code===null)return;const badge=document.createElement('span');badge.className=`badge http-status ${httpStatusClass(code)}`;badge.textContent=String(code);badge.title=`Latest observed HTTP response: ${code}`;container.append(badge)}
function nodeSearchText(n){return [n.value,n.label,n.kind,...(n.sources||[]),httpStatusCode(n)||''].join(' ').toLowerCase()}
function renderItem(item){const li=document.createElement('li');if(item.$ref){const b=document.createElement('button');b.className='node';b.dataset.id=item.$ref;b.innerHTML=`<span class="toggle">↗</span><span class="relation">${item.relation||'REF'}</span><span class="value"></span>`;b.querySelector('.value').textContent=item.label;appendHttpBadge(b,byId.get(item.$ref));li.append(b);return li}const n=item.node,b=document.createElement('button');b.className='node';b.dataset.id=n.id;b.dataset.kind=n.kind;b.dataset.state=n.discovery_state;b.dataset.search=nodeSearchText(n);const children=item.children||[],has=children.length>0;b.innerHTML=`<span class="toggle">${has?'▸':'·'}</span><span class="kind"></span><span class="value"></span><span class="badge ${n.discovery_state}"></span>`;b.querySelector('.kind').textContent=n.kind;b.querySelector('.value').textContent=n.label;b.querySelector('.badge').textContent=n.discovery_state;appendHttpBadge(b,n);if(item.relation){const r=document.createElement('span');r.className='relation';r.textContent=item.relation;b.insertBefore(r,b.querySelector('.kind'))}li.append(b);if(has){const ul=document.createElement('ul');ul.classList.add('hidden');let loaded=false;li.append(ul);b.querySelector('.toggle').onclick=e=>{e.stopPropagation();if(!loaded){children.forEach(c=>ul.append(renderItem(c)));loaded=true}ul.classList.toggle('hidden');b.querySelector('.toggle').textContent=ul.classList.contains('hidden')?'▸':'▾'}}return li}
function graphTreeNode(n){return {node:{id:n.node_id,kind:n.kind,value:n.value,label:n.label,roles:n.roles,scope_state:n.scope_state,discovery_state:n.discovery_state,liveness_state:n.liveness_state,confidence:n.confidence,observation_count:n.observation_count,sources:n.sources,metadata:n.metadata},children:[]}}
function render(items){const tree=$('tree');tree.textContent='';const root=document.createElement('ul');items.forEach(i=>root.append(renderItem(i)));tree.append(root)}
function appendHttpHistory(container,n){const http=n.metadata&&n.metadata.http,history=http&&Array.isArray(http.history)?http.history:[];if(!history.length)return;const heading=document.createElement('h3');heading.textContent='HTTP response history';container.append(heading);const table=document.createElement('table');table.className='http-history';const head=document.createElement('thead');head.innerHTML='<tr><th>Observed</th><th>Method</th><th>Status</th><th>Redirect / details</th></tr>';table.append(head);const body=document.createElement('tbody');[...history].reverse().forEach(item=>{const row=document.createElement('tr'),observed=document.createElement('td'),method=document.createElement('td'),status=document.createElement('td'),details=document.createElement('td');observed.textContent=new Date(item.observed_at).toLocaleString();method.textContent=item.method;appendHttpBadge(status,{metadata:{status_code:item.status_code}});details.textContent=item.location||item.content_type||item.title||'—';row.append(observed,method,status,details);body.append(row)});table.append(body);container.append(table);if(http.history_truncated){const note=document.createElement('small');note.className='http-history-note';note.textContent=`Showing latest ${history.length} of ${http.history_total} response observations.`;container.append(note)}}
function show(id){const n=byId.get(id);if(!n)return;document.querySelectorAll('.node.active').forEach(e=>e.classList.remove('active'));document.querySelectorAll(`.node[data-id="${CSS.escape(id)}"]`).forEach(e=>e.classList.add('active'));const d=$('details');d.textContent='';const h=document.createElement('h2');h.textContent=n.label;d.append(h);const badges=document.createElement('div');[n.kind,n.scope_state,n.discovery_state,n.liveness_state,...n.roles].forEach(v=>{const s=document.createElement('span');s.className='badge '+v;s.textContent=v;badges.append(s);badges.append(' ')});appendHttpBadge(badges,n);d.append(badges);const code=httpStatusCode(n),rows=[['Node ID',n.node_id],['Confidence',n.confidence],['Novelty',n.novelty],['Observations',n.observation_count],['First seen',new Date(n.first_seen).toLocaleString()],['Last seen',new Date(n.last_seen).toLocaleString()],['Sources',n.sources.join(', ')]];if(code!==null){rows.push(['HTTP response',`${n.metadata.method||'UNKNOWN'} ${code}`]);rows.push(['Status observed',new Date(n.metadata.status_observed_at).toLocaleString()]);if(n.metadata.location)rows.push(['Redirect',n.metadata.location])}const dl=document.createElement('dl');rows.forEach(([k,v])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k;dd.textContent=v;dl.append(dt,dd)});d.append(dl);appendHttpHistory(d,n);const p=document.createElement('pre');p.textContent=JSON.stringify(n.metadata,null,2);d.append(p)}
render(projection.tree);
document.addEventListener('click',e=>{const b=e.target.closest('.node');if(b)show(b.dataset.id)});
function filter(){const q=$('search').value.trim().toLowerCase(),state=$('state').value,kind=$('kind').value;if(!q&&!state&&!kind){render(projection.tree);return}const matches=graph.nodes.filter(n=>(!q||nodeSearchText(n).includes(q))&&(!state||n.discovery_state===state)&&(!kind||n.kind===kind)).slice(0,500).map(graphTreeNode);render(matches);if(!matches.length)$('tree').innerHTML='<div class="empty">No matching surface nodes.</div>'}
$('search').oninput=filter;$('state').onchange=filter;$('kind').onchange=filter;
</script></body></html>"""
