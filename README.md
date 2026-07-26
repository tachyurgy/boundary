# Boundary

**Authorization test harness for multi-tenant clinical data, with policy as the oracle.**

Live: **https://boundary.levelbrook.com**

## What this is

Broken object-level authorization is the most common serious flaw in multi-tenant products and
the hardest to catch, because every exploiting request is well-formed, authenticated and returns a clean 200.
No scanner finds it.

## Engineering notes

### Full cross product against a policy oracle

The harness enumerates every (actor, object,
action) triple and compares what the implementation does against what policy says. A pass is not "no error", it
is "denied exactly what policy denies". On clean policy that is 448 assertions with zero findings.

### Policy as predicates, not a role grid

Nearly every real rule here is relational: a provider may
read a note they authored for a client on their panel. No amount of role checking expresses that.

### Defects that actually ship

The injected defects are a role check that forgot the ownership
predicate, a tenant scope read from a request parameter instead of the session, and support tooling not bound to
an assigned ticket. Flip one on and exactly the assertions that should fail, fail.

### Severity is derived

PHI raises severity and PHI crossing a tenant boundary makes it critical,
rather than severity being hand-assigned per finding.

### A k-anonymity floor

An employer admin can see aggregates about their own population, but below
a cohort size a "report" tells an employer which of their employees sought mental health care. Every role check
in the system would happily authorise that.

## Stack

Vanilla JavaScript, predicate-based policy engine, 448 assertions


## Running it

Static. Open `index.html`, or serve the directory:

```
python3 -m http.server 8000
```

## Honest scope

This is a focused engineering demo, not a production system. The data is synthetic and generated
locally so that the behaviour is reproducible. The reasoning, the arithmetic and the failure modes
are the point; the surface area is deliberately narrow.

## License

MIT
