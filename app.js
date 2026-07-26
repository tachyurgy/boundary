import { ROLES, RESOURCE_TYPES, ACTIONS, DEFECTS, shouldAllow, actualAllow, runHarness, SEV_ORDER } from './authz.js';

const $ = (s) => document.querySelector(s);

const ACTORS = [
  { id: 'u_mem_01', name: 'Rosalind Vance', role: 'member', orgId: 'org_northwind', clients: [], panel: [], assignedTickets: [], breakGlass: false },
  { id: 'u_mem_02', name: 'Desmond Achebe', role: 'member', orgId: 'org_calder', clients: [], panel: [], assignedTickets: [], breakGlass: false },
  { id: 'u_thr_01', name: 'Dr. Ingrid Solheim', role: 'therapist', orgId: 'org_northwind', clients: ['u_mem_01'], panel: [], assignedTickets: [], breakGlass: false },
  { id: 'u_thr_02', name: 'Dr. Anselm Ferreira', role: 'therapist', orgId: 'org_calder', clients: ['u_mem_02'], panel: [], assignedTickets: [], breakGlass: false },
  { id: 'u_lead_01', name: 'Dr. Perpetua Okonjo', role: 'care_lead', orgId: 'org_northwind', clients: [], panel: ['u_thr_01'], assignedTickets: [], breakGlass: false },
  { id: 'u_adm_01', name: 'Harriet Blythe', role: 'org_admin', orgId: 'org_northwind', clients: [], panel: [], assignedTickets: [], breakGlass: false },
  { id: 'u_sup_01', name: 'Casimir Nowak', role: 'support', orgId: 'internal', clients: [], panel: [], assignedTickets: ['u_mem_01'], breakGlass: false },
  { id: 'u_plt_01', name: 'Yusra Al-Amin', role: 'platform_admin', orgId: 'internal', clients: [], panel: [], assignedTickets: [], breakGlass: false },
];

const RESOURCES = [
  { id: 'note_1001', type: 'session_note', orgId: 'org_northwind', subjectId: 'u_mem_01', providerId: 'u_thr_01', authorId: 'u_thr_01', locked: false },
  { id: 'note_1002', type: 'session_note', orgId: 'org_calder', subjectId: 'u_mem_02', providerId: 'u_thr_02', authorId: 'u_thr_02', locked: true },
  { id: 'asmt_2001', type: 'assessment', orgId: 'org_northwind', subjectId: 'u_mem_01', providerId: 'u_thr_01' },
  { id: 'asmt_2002', type: 'assessment', orgId: 'org_calder', subjectId: 'u_mem_02', providerId: 'u_thr_02' },
  { id: 'plan_3001', type: 'care_plan', orgId: 'org_northwind', subjectId: 'u_mem_01', providerId: 'u_thr_01' },
  { id: 'appt_4001', type: 'appointment', orgId: 'org_northwind', subjectId: 'u_mem_01', providerId: 'u_thr_01' },
  { id: 'appt_4002', type: 'appointment', orgId: 'org_calder', subjectId: 'u_mem_02', providerId: 'u_thr_02' },
  { id: 'elig_5001', type: 'eligibility', orgId: 'org_northwind', subjectId: 'u_mem_01' },
  { id: 'elig_5002', type: 'eligibility', orgId: 'org_calder', subjectId: 'u_mem_02' },
  { id: 'util_6001', type: 'utilization_agg', orgId: 'org_northwind', cohortSize: 340 },
  { id: 'util_6002', type: 'utilization_agg', orgId: 'org_northwind', cohortSize: 7 },
  { id: 'util_6003', type: 'utilization_agg', orgId: 'org_calder', cohortSize: 190 },
  { id: 'inv_7001', type: 'invoice', orgId: 'org_northwind' },
  { id: 'log_8001', type: 'audit_log', orgId: 'org_northwind' },
];

let enabled = { role_only_note_read: true, tenant_from_param: true, support_unbounded: true, agg_no_k_anonymity: true, breakglass_unlogged: false };
let sevFilter = 'all';
let selected = null;

const SEV_CLS = { critical: 'bad', high: 'bad', medium: 'warn', low: 'mute' };

function results() { return runHarness(ACTORS, RESOURCES, enabled); }

function renderMetrics() {
  const r = results();
  const over = r.findings.filter((f) => f.kind === 'over_permissive');
  const crit = over.filter((f) => f.severity === 'critical');
  const phiLeak = over.filter((f) => f.phi);
  const xTenant = over.filter((f) => f.crossTenant);

  const tiles = [
    { k: 'Assertions', v: r.tested.toLocaleString(), sub: `${ACTORS.length} actors × ${RESOURCES.length} objects × ${ACTIONS.length} actions`, cls: '' },
    { k: 'Passing', v: ((r.passed / r.tested) * 100).toFixed(1) + '%', sub: `${r.passed} matched policy`, cls: r.passed === r.tested ? 'good' : 'warn' },
    { k: 'Over-permissive', v: String(over.length), sub: 'allowed where policy denies', cls: over.length ? 'bad' : 'good' },
    { k: 'Critical', v: String(crit.length), sub: 'PHI across a tenant boundary', cls: crit.length ? 'bad' : 'good' },
    { k: 'PHI exposed', v: String(phiLeak.length), sub: 'clinical records reachable', cls: phiLeak.length ? 'bad' : 'good' },
    { k: 'Cross-tenant', v: String(xTenant.length), sub: 'another employer\'s data', cls: xTenant.length ? 'bad' : 'good' },
  ];
  $('#metrics').innerHTML = tiles.map((t) =>
    `<div class="metric ${t.cls}"><div class="k">${t.k}</div><div class="v">${t.v}</div><div class="sub">${t.sub}</div></div>`).join('');
}

function renderDefects() {
  $('#defects').innerHTML = Object.entries(DEFECTS).map(([k, d]) => `
    <label style="display:flex;gap:9px;align-items:flex-start;padding:9px 16px;border-bottom:1px solid var(--line);cursor:pointer">
      <input type="checkbox" data-d="${k}" ${enabled[k] ? 'checked' : ''} style="margin-top:3px">
      <span style="flex:1;min-width:0">
        <span style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap">
          <span style="font-size:12.5px;color:${enabled[k] ? 'var(--rose)' : 'var(--ink-3)'}">${d.label}</span>
          <span class="chip ${SEV_CLS[d.severity]}" style="font-size:9px">${d.severity}</span>
        </span>
        <span class="mono" style="display:block;font-size:10px;color:var(--ink-3);margin-top:2px">${d.cwe}</span>
        <span class="note" style="display:block;margin-top:3px">${d.note}</span>
      </span>
    </label>`).join('') + `<div class="pad note">
    Toggle a defect off and the harness re-runs. This is the loop the harness is for: a fix is not
    &ldquo;the report is shorter&rdquo;, it is that the specific assertions which were failing now pass
    and nothing else regressed.
  </div>`;

  $('#defects').querySelectorAll('input').forEach((el) =>
    el.addEventListener('change', () => { enabled[el.dataset.d] = el.checked; selected = null; render(); }));
}

function renderFindings() {
  const r = results();
  const list = r.findings
    .filter((f) => f.kind === 'over_permissive')
    .filter((f) => sevFilter === 'all' || f.severity === sevFilter)
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  $('#fCount').textContent = `${list.length} shown`;
  $('#findings').innerHTML = list.length ? list.map((f, i) => `
    <div class="row ${selected === i ? 'sel' : ''}" data-i="${i}" style="grid-template-columns:62px minmax(0,1fr) 44px">
      <div><span class="chip ${SEV_CLS[f.severity]}" style="font-size:9px">${f.severity}</span></div>
      <div>
        <div class="t">${ROLES[f.actor.role].label} → ${RESOURCE_TYPES[f.resource.type].label}</div>
        <div class="m">${f.actor.name} can ${f.action} ${f.resource.id}${f.crossTenant ? ' · CROSS-TENANT' : ''}</div>
      </div>
      <div class="num">${f.phi ? '<span class="chip bad" style="font-size:9px">PHI</span>' : ''}</div>
    </div>`).join('')
    : `<div class="empty" style="color:var(--accent)">No over-permissive access. Every actor is denied exactly what policy denies.</div>`;

  $('#findings').querySelectorAll('.row').forEach((el) =>
    el.addEventListener('click', () => { selected = +el.dataset.i; renderDetail(list); }));

  renderDetail(list);
}

function renderDetail(list) {
  const f = list[selected];
  if (!f) {
    $('#detail').innerHTML = `<div class="empty">Select a finding to see the exact request, the policy predicate that should have denied it, and the defect responsible.</div>`;
    return;
  }
  const rt = RESOURCE_TYPES[f.resource.type];

  $('#detail').innerHTML = `
    <div class="dsec">
      <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:11px">
        <span class="pill ${SEV_CLS[f.severity]}">${f.severity}</span>
        ${f.phi ? '<span class="pill bad">PHI</span>' : ''}
        ${f.crossTenant ? '<span class="pill bad">cross-tenant</span>' : ''}
      </div>
      <div class="card">
        <div class="desc" style="color:var(--rose)">${f.actor.name} can ${f.action} ${f.resource.id}</div>
        <div class="act">Policy says this must be denied. The implementation allows it.</div>
      </div>
    </div>

    <div class="dsec">
      <h3>Request</h3>
      <pre class="mono" style="margin:0;font-size:10.5px;background:var(--bg-2);border:1px solid var(--line);border-radius:7px;padding:10px;overflow-x:auto;color:var(--ink-2);white-space:pre-wrap">${f.action.toUpperCase()} /v1/${f.resource.type}s/${f.resource.id}
Authorization: Bearer &lt;session for ${f.actor.id}&gt;

actor.role   = ${f.actor.role}
actor.org    = ${f.actor.orgId}
object.org   = ${f.resource.orgId}${f.resource.subjectId ? `
object.subject = ${f.resource.subjectId}` : ''}${f.resource.authorId ? `
object.author  = ${f.resource.authorId}` : ''}${f.resource.cohortSize != null ? `
object.cohort  = ${f.resource.cohortSize}` : ''}

expected → 403 Forbidden
actual   → 200 OK</pre>
    </div>

    <div class="dsec">
      <h3>Why policy denies it</h3>
      <dl class="kv">
        <dt>Actor</dt><dd>${f.actor.name} — ${ROLES[f.actor.role].label}</dd>
        <dt>Role scope</dt><dd style="font-family:var(--sans);font-size:12.5px">${ROLES[f.actor.role].description}</dd>
        <dt>Object</dt><dd>${rt.label}</dd>
        <dt>Contains PHI</dt><dd style="color:${rt.phi ? 'var(--rose)' : 'var(--ink-2)'}">${rt.phi ? 'yes' : 'no'}</dd>
        <dt>Tenant boundary</dt><dd style="color:${f.crossTenant ? 'var(--rose)' : 'var(--ink-2)'}">${f.crossTenant ? `crossed — actor in ${f.actor.orgId}, object in ${f.resource.orgId}` : 'same tenant'}</dd>
      </dl>
      ${f.resource.cohortSize != null && f.resource.cohortSize < 25 ? `<div class="card" style="margin-top:10px;border-color:#6d2f39">
        <div class="act">Cohort size is ${f.resource.cohortSize}, below the k-anonymity floor of 25. At this size a
        &ldquo;utilization report&rdquo; is not aggregate data — it identifies which employees sought
        mental health care to their own employer.</div>
      </div>` : ''}
    </div>

    ${f.defectInfo ? `<div class="dsec">
      <h3>Responsible defect</h3>
      <div class="card" style="border-color:#6d2f39">
        <div class="desc">${f.defectInfo.label}</div>
        <div class="mono" style="font-size:10.5px;color:var(--ink-3);margin:4px 0 6px">${f.defectInfo.cwe}</div>
        <div class="act">${f.defectInfo.note}</div>
      </div>
    </div>` : ''}`;
}

function render() { renderMetrics(); renderDefects(); renderFindings(); }

$('#sevFilter').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-s]');
  if (!b) return;
  sevFilter = b.dataset.s; selected = null;
  $('#sevFilter').querySelectorAll('button').forEach((x) => x.classList.toggle('primary', x.dataset.s === sevFilter));
  renderFindings();
});

render();
window.authz = { ACTORS, RESOURCES, runHarness, shouldAllow, actualAllow, enabled };
