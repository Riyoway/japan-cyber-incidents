# Threat actor attribution

`incident.threat_actor` remains the compatibility field for a known actor name. When attribution evidence is available, `incident.threat_actor_attribution` records how strong that attribution is and where it came from.

Statuses:

- `confirmed`: the named actor is publicly tied to the incident by strong victim, law-enforcement, incident-response, or equivalent evidence.
- `suspected`: a credible security analysis attributes the incident, but the attribution is not conclusively established.
- `attacker_claim`: the actor or its leak site claims the victim; this is not treated as independently verified attribution.
- `unknown`: the incident was reviewed but no supported actor attribution was established.

Do not promote a leak-site claim to `confirmed` solely because the victim separately confirmed that a cyberattack or data leak occurred.
