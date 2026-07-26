// Authorization model and a test harness that tries to break it.
//
// Broken object-level authorization is consistently the most common serious flaw
// in multi-tenant products, and it is invisible to scanners: every request is a
// well-formed, authenticated 200. The only way to find it is to enumerate the
// cross product of actors, objects and actions and compare what the system does
// against what policy says it should do. That is what this is.

export const ROLES = {
  member:        { label: 'Member', description: 'An individual using the benefit.' },
  therapist:     { label: 'Provider', description: 'Licensed clinician delivering care.' },
  care_lead:     { label: 'Care team lead', description: 'Clinical supervisor over a provider panel.' },
  org_admin:     { label: 'Employer admin', description: 'HR benefits administrator at the customer.' },
  support:       { label: 'Support agent', description: 'Internal support staff.' },
  platform_admin:{ label: 'Platform admin', description: 'Internal engineering and operations.' },
};

export const RESOURCE_TYPES = {
  session_note:   { label: 'Clinical session note', phi: true,  sensitivity: 'high' },
  assessment:     { label: 'Assessment result (PHQ-9, GAD-7)', phi: true, sensitivity: 'high' },
  care_plan:      { label: 'Care plan', phi: true, sensitivity: 'high' },
  appointment:    { label: 'Appointment', phi: true, sensitivity: 'medium' },
  eligibility:    { label: 'Benefit eligibility record', phi: false, sensitivity: 'medium' },
  utilization_agg:{ label: 'Aggregate utilization report', phi: false, sensitivity: 'low' },
  invoice:        { label: 'Employer invoice', phi: false, sensitivity: 'low' },
  audit_log:      { label: 'Access audit log', phi: false, sensitivity: 'medium' },
};

export const ACTIONS = ['read', 'write', 'delete', 'export'];

// The policy. Written as predicates over (actor, resource) rather than a static
// role-permission grid, because almost every real rule here is relational — a
// provider may read a note *they authored for a client on their panel*, which no
// amount of role checking alone can express.
export const POLICY = {
  session_note: {
    read: (a, r) => (a.role === 'therapist' && r.authorId === a.id)
                 || (a.role === 'care_lead' && a.panel.includes(r.providerId) && r.orgId === a.orgId)
                 || (a.role === 'platform_admin' && a.breakGlass),
    write: (a, r) => a.role === 'therapist' && r.authorId === a.id && !r.locked,
    delete: () => false,   // clinical records are never deleted, only amended
    export: (a, r) => a.role === 'therapist' && r.authorId === a.id,
  },
  assessment: {
    read: (a, r) => (a.role === 'member' && r.subjectId === a.id)
                 || (a.role === 'therapist' && a.clients.includes(r.subjectId))
                 || (a.role === 'care_lead' && a.panel.includes(r.providerId) && r.orgId === a.orgId)
                 || (a.role === 'platform_admin' && a.breakGlass),
    write: (a, r) => a.role === 'member' && r.subjectId === a.id,
    delete: () => false,
    export: (a, r) => a.role === 'member' && r.subjectId === a.id,
  },
  care_plan: {
    read: (a, r) => (a.role === 'member' && r.subjectId === a.id)
                 || (a.role === 'therapist' && a.clients.includes(r.subjectId))
                 || (a.role === 'care_lead' && a.panel.includes(r.providerId) && r.orgId === a.orgId),
    write: (a, r) => a.role === 'therapist' && a.clients.includes(r.subjectId),
    delete: () => false,
    export: (a, r) => a.role === 'member' && r.subjectId === a.id,
  },
  appointment: {
    read: (a, r) => (a.role === 'member' && r.subjectId === a.id)
                 || (a.role === 'therapist' && r.providerId === a.id)
                 || (a.role === 'support' && a.assignedTickets.includes(r.subjectId)),
    write: (a, r) => (a.role === 'member' && r.subjectId === a.id) || (a.role === 'therapist' && r.providerId === a.id),
    delete: (a, r) => (a.role === 'member' && r.subjectId === a.id) || (a.role === 'therapist' && r.providerId === a.id),
    export: () => false,
  },
  eligibility: {
    read: (a, r) => (a.role === 'member' && r.subjectId === a.id)
                 || (a.role === 'org_admin' && r.orgId === a.orgId)
                 || (a.role === 'support' && a.assignedTickets.includes(r.subjectId)),
    write: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId,
    delete: () => false,
    export: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId,
  },
  // The critical one. An employer admin may see aggregates about their own
  // population and only above a k-anonymity floor — below it, a "utilization
  // report" identifies who sought mental health care.
  utilization_agg: {
    read: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId && r.cohortSize >= 25,
    write: () => false,
    delete: () => false,
    export: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId && r.cohortSize >= 25,
  },
  invoice: {
    read: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId,
    write: () => false,
    delete: () => false,
    export: (a, r) => a.role === 'org_admin' && r.orgId === a.orgId,
  },
  audit_log: {
    read: (a, r) => (a.role === 'platform_admin') || (a.role === 'org_admin' && r.orgId === a.orgId),
    write: () => false,
    delete: () => false,
    export: (a, r) => a.role === 'platform_admin',
  },
};

/** The intended answer. */
export function shouldAllow(actor, resource, action) {
  const t = POLICY[resource.type];
  if (!t || !t[action]) return false;
  return !!t[action](actor, resource);
}

// ---------------------------------------------------------------------------
// The implementation under test, with deliberate defects. Each mirrors a real
// pattern: a role check that forgot the ownership predicate, a tenant scope read
// from a client-supplied parameter, a support tool with no ticket binding, an
// aggregate endpoint with no k-anonymity floor.
// ---------------------------------------------------------------------------

export const DEFECTS = {
  role_only_note_read: {
    label: 'Session note read checks role but not authorship',
    cwe: 'CWE-639 Authorization Bypass Through User-Controlled Key',
    severity: 'critical',
    note: 'Any authenticated provider can read any provider\'s session notes, across every employer.',
  },
  tenant_from_param: {
    label: 'Employer scope taken from a request parameter',
    cwe: 'CWE-639',
    severity: 'critical',
    note: 'The org id is read from the query string instead of the session, so changing it returns another employer\'s data.',
  },
  support_unbounded: {
    label: 'Support tooling not bound to an assigned ticket',
    cwe: 'CWE-266 Incorrect Privilege Assignment',
    severity: 'high',
    note: 'A support agent can look up any member, not only the one who opened the ticket they are working.',
  },
  agg_no_k_anonymity: {
    label: 'Aggregate report has no minimum cohort size',
    cwe: 'CWE-359 Exposure of Private Information',
    severity: 'high',
    note: 'A small-team utilization report re-identifies which employees sought mental health care.',
  },
  breakglass_unlogged: {
    label: 'Platform admin break-glass access is not gated or logged',
    cwe: 'CWE-778 Insufficient Logging',
    severity: 'medium',
    note: 'Internal staff can read clinical records without an approved break-glass session or an audit record.',
  },
};

export function actualAllow(actor, resource, action, enabled) {
  // Start from correct policy, then apply whichever defects are switched on.
  let allow = shouldAllow(actor, resource, action);
  const applied = [];

  if (enabled.role_only_note_read && resource.type === 'session_note' && action === 'read'
      && ['therapist', 'care_lead'].includes(actor.role)) {
    if (!allow) { allow = true; applied.push('role_only_note_read'); }
  }
  if (enabled.tenant_from_param && ['eligibility', 'invoice', 'utilization_agg'].includes(resource.type)
      && actor.role === 'org_admin' && resource.orgId !== actor.orgId) {
    if (!allow && ['read', 'export'].includes(action)) { allow = true; applied.push('tenant_from_param'); }
  }
  if (enabled.support_unbounded && actor.role === 'support'
      && ['appointment', 'eligibility'].includes(resource.type) && action === 'read') {
    if (!allow) { allow = true; applied.push('support_unbounded'); }
  }
  // Only read and export — a missing cohort floor lets a small report be *seen*,
  // it cannot grant write or delete on an aggregate that nobody may mutate.
  if (enabled.agg_no_k_anonymity && resource.type === 'utilization_agg' && ['read', 'export'].includes(action)
      && actor.role === 'org_admin' && resource.orgId === actor.orgId && resource.cohortSize < 25) {
    if (!allow) { allow = true; applied.push('agg_no_k_anonymity'); }
  }
  if (enabled.breakglass_unlogged && actor.role === 'platform_admin'
      && ['session_note', 'assessment'].includes(resource.type) && action === 'read' && !actor.breakGlass) {
    if (!allow) { allow = true; applied.push('breakglass_unlogged'); }
  }
  return { allow, applied };
}

// ---------------------------------------------------------------------------
// The harness. Enumerate every triple, compare intent against behaviour, and
// classify. A pass is not "no error" — it is "denied exactly what policy denies".
// ---------------------------------------------------------------------------

export function runHarness(actors, resources, enabled) {
  const findings = [];
  let tested = 0, passed = 0;

  for (const a of actors) {
    for (const r of resources) {
      for (const action of ACTIONS) {
        tested++;
        const expected = shouldAllow(a, r, action);
        const { allow, applied } = actualAllow(a, r, action, enabled);

        if (expected === allow) { passed++; continue; }

        const crossTenant = a.orgId !== r.orgId;
        const rt = RESOURCE_TYPES[r.type];
        const defect = applied[0] ? DEFECTS[applied[0]] : null;

        // Severity escalates on PHI and again when the boundary crossed is a tenant.
        let severity = defect?.severity || 'medium';
        if (allow && !expected) {
          if (rt.phi && crossTenant) severity = 'critical';
          else if (rt.phi) severity = severity === 'medium' ? 'high' : severity;
        }

        findings.push({
          actor: a, resource: r, action,
          expected, actual: allow,
          kind: allow && !expected ? 'over_permissive' : 'over_restrictive',
          crossTenant, phi: rt.phi, severity,
          defect: applied[0] || null,
          defectInfo: defect,
        });
      }
    }
  }
  return { tested, passed, findings };
}

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
