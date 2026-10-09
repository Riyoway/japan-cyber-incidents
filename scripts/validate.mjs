import { readFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));
const errors = [];
const ids = new Set();
const allowedConfidence = new Set(["high", "medium", "low", "unknown"]);
const allowedBusinessModels = new Set(["b2b", "b2c", "b2g", "public", "internal", "nonprofit", "other"]);
const allowedTimePrecision = new Set(["exact", "approximate", "range", "time_band", "unknown"]);
const allowedTimeBands = new Set(["overnight", "morning", "afternoon", "evening", "night", "unknown"]);
const allowedLocationPrecision = new Set(["exact", "city", "prefecture", "unknown"]);
const allowedThreatActorTypes = new Set(["ransomware_group", "cybercrime_group", "state_sponsored", "hacktivist", "individual", "unknown"]);
const allowedAttributionStatuses = new Set(["confirmed", "suspected", "attacker_claim", "unknown"]);

const isDate = (v) => v === null || /^\d{4}-\d{2}-\d{2}$/.test(v);
const isDateTime = (v) => typeof v === "string" && !Number.isNaN(Date.parse(v));
const isCount = (v) => v === null || (Number.isInteger(v) && v >= 0);
const isTime = (v) => v === null || (typeof v === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(v));
const isHttpUrl = (v) => {
  if (v === null) return true;
  try {
    const url = new URL(v);
    return /^https?:$/.test(url.protocol);
  } catch {
    return false;
  }
};

function validateEstimate(estimate, p) {
  if (!estimate || typeof estimate !== "object" || Array.isArray(estimate)) {
    errors.push(`${p} must be an object`);
    return;
  }
  if (!(estimate.value === null || (Number.isInteger(estimate.value) && estimate.value >= 0))) {
    errors.push(`${p}.value must be null or a non-negative integer`);
  }
  if (typeof estimate.unit !== "string") errors.push(`${p}.unit is required`);
  if (typeof estimate.estimate_type !== "string") errors.push(`${p}.estimate_type is required`);
  if (!(estimate.basis === null || typeof estimate.basis === "string")) errors.push(`${p}.basis must be string or null`);
  if (!allowedConfidence.has(estimate.confidence)) errors.push(`${p}.confidence is invalid`);
}

function validateEventTime(value, p) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${p} must be an object`);
    return;
  }
  if (!isTime(value.start)) errors.push(`${p}.start must be HH:MM or null`);
  if (!isTime(value.end)) errors.push(`${p}.end must be HH:MM or null`);
  if (!(value.timezone === null || typeof value.timezone === "string")) errors.push(`${p}.timezone must be string or null`);
  if (!allowedTimePrecision.has(value.precision)) errors.push(`${p}.precision is invalid`);
  if (!allowedTimeBands.has(value.time_band)) errors.push(`${p}.time_band is invalid`);
  if (!(value.basis === null || typeof value.basis === "string")) errors.push(`${p}.basis must be string or null`);
}

function validateThreatActorAttribution(value, p, threatActor) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${p} must be an object`);
    return;
  }

  if (!(value.name === null || typeof value.name === "string")) errors.push(`${p}.name must be string or null`);
  if (!allowedThreatActorTypes.has(value.actor_type)) errors.push(`${p}.actor_type is invalid`);
  if (!Array.isArray(value.aliases) || value.aliases.some((alias) => typeof alias !== "string")) errors.push(`${p}.aliases must be an array of strings`);
  if (!allowedAttributionStatuses.has(value.status)) errors.push(`${p}.status is invalid`);
  if (!allowedConfidence.has(value.confidence)) errors.push(`${p}.confidence is invalid`);
  if (!(value.basis === null || typeof value.basis === "string")) errors.push(`${p}.basis must be string or null`);
  if (!Array.isArray(value.sources) || value.sources.some((url) => !isHttpUrl(url) || url === null)) errors.push(`${p}.sources must be an array of http(s) URLs`);
  if (!isDate(value.reviewed_at) || value.reviewed_at === null) errors.push(`${p}.reviewed_at must be YYYY-MM-DD`);

  if (value.status === "unknown") {
    if (value.name !== null) errors.push(`${p}.name must be null when status is unknown`);
    if (threatActor !== null) errors.push(`${p} requires incident.threat_actor to be null when status is unknown`);
  } else {
    if (typeof value.name !== "string" || value.name.length === 0) errors.push(`${p}.name is required for a named attribution`);
    if (threatActor !== value.name) errors.push(`${p}.name must match incident.threat_actor`);
  }
}

if (typeof data.schema_version !== "string") errors.push("root.schema_version is required");
if (!isDateTime(data.generated_at)) errors.push("root.generated_at must be an ISO datetime");
if (!Array.isArray(data.incidents) || data.incidents.length === 0) errors.push("root.incidents must be a non-empty array");

for (const [index, item] of (data.incidents ?? []).entries()) {
  const p = `incidents[${index}]`;
  if (!item.id || typeof item.id !== "string") errors.push(`${p}.id is required`);
  if (ids.has(item.id)) errors.push(`${p}.id is duplicated: ${item.id}`);
  ids.add(item.id);

  const org = item.organization ?? {};
  if (!org.name) errors.push(`${p}.organization.name is required`);
  if (!org.type) errors.push(`${p}.organization.type is required`);
  if (!org.size) errors.push(`${p}.organization.size is required`);
  if (!Array.isArray(org.industry) || org.industry.length === 0) errors.push(`${p}.organization.industry must be non-empty`);
  if (!Array.isArray(org.business_model) || org.business_model.length === 0) errors.push(`${p}.organization.business_model must be non-empty`);
  for (const model of org.business_model ?? []) {
    if (!allowedBusinessModels.has(model)) errors.push(`${p}.organization.business_model contains unsupported value: ${model}`);
  }

  validateEstimate(org.estimated_total_users ?? {}, `${p}.organization.estimated_total_users`);

  if (org.website !== undefined && !isHttpUrl(org.website)) errors.push(`${p}.organization.website must be an http(s) URL or null`);
  if (org.employee_count !== undefined) validateEstimate(org.employee_count, `${p}.organization.employee_count`);

  if (org.headquarters !== undefined) {
    const hq = org.headquarters;
    if (!hq || typeof hq !== "object" || Array.isArray(hq)) {
      errors.push(`${p}.organization.headquarters must be an object`);
    } else {
      if (!(hq.address === null || typeof hq.address === "string")) errors.push(`${p}.organization.headquarters.address must be string or null`);
      if (!(hq.prefecture === null || typeof hq.prefecture === "string")) errors.push(`${p}.organization.headquarters.prefecture must be string or null`);
      if (!(hq.city === null || typeof hq.city === "string")) errors.push(`${p}.organization.headquarters.city must be string or null`);
      if (!(hq.latitude === null || (typeof hq.latitude === "number" && hq.latitude >= -90 && hq.latitude <= 90))) errors.push(`${p}.organization.headquarters.latitude is invalid`);
      if (!(hq.longitude === null || (typeof hq.longitude === "number" && hq.longitude >= -180 && hq.longitude <= 180))) errors.push(`${p}.organization.headquarters.longitude is invalid`);
      if (!allowedLocationPrecision.has(hq.precision)) errors.push(`${p}.organization.headquarters.precision is invalid`);
      if (!isHttpUrl(hq.source)) errors.push(`${p}.organization.headquarters.source must be an http(s) URL or null`);
    }
  }

  if (org.listing !== undefined) {
    const listing = org.listing;
    if (!listing || typeof listing !== "object" || Array.isArray(listing)) {
      errors.push(`${p}.organization.listing must be an object`);
    } else {
      if (!(listing.is_listed === null || typeof listing.is_listed === "boolean")) errors.push(`${p}.organization.listing.is_listed must be boolean or null`);
      if (!(listing.market === null || typeof listing.market === "string")) errors.push(`${p}.organization.listing.market must be string or null`);
      if (!(listing.ticker === null || typeof listing.ticker === "string")) errors.push(`${p}.organization.listing.ticker must be string or null`);
    }
  }

  const incident = item.incident ?? {};
  if (!incident.title) errors.push(`${p}.incident.title is required`);
  if (!Array.isArray(incident.types) || incident.types.length === 0) errors.push(`${p}.incident.types must be non-empty`);
  for (const key of ["occurred_at", "detected_at", "disclosed_at"]) {
    if (!isDate(incident[key])) errors.push(`${p}.incident.${key} must be YYYY-MM-DD or null`);
  }
  if (!incident.disclosed_at) errors.push(`${p}.incident.disclosed_at is required`);

  if (incident.occurred_time !== undefined) validateEventTime(incident.occurred_time, `${p}.incident.occurred_time`);
  if (incident.detected_time !== undefined) validateEventTime(incident.detected_time, `${p}.incident.detected_time`);

  if (typeof incident.status === "string") {
    if (!incident.status) errors.push(`${p}.incident.status must not be empty`);
  } else if (incident.status && typeof incident.status === "object" && !Array.isArray(incident.status)) {
    if (!incident.status.value || typeof incident.status.value !== "string") errors.push(`${p}.incident.status.value is required`);
    if (!isDate(incident.status.as_of) || incident.status.as_of === null) errors.push(`${p}.incident.status.as_of must be YYYY-MM-DD`);
  } else {
    errors.push(`${p}.incident.status must be a legacy string or { value, as_of } snapshot`);
  }

  if (!(incident.threat_actor === null || typeof incident.threat_actor === "string")) errors.push(`${p}.incident.threat_actor must be string or null`);
  if (incident.threat_actor_attribution !== undefined) validateThreatActorAttribution(incident.threat_actor_attribution, `${p}.incident.threat_actor_attribution`, incident.threat_actor);
  if (!(incident.ransomware === null || typeof incident.ransomware === "boolean")) errors.push(`${p}.incident.ransomware must be boolean or null`);
  if (!(incident.malware_family === undefined || incident.malware_family === null || typeof incident.malware_family === "string")) errors.push(`${p}.incident.malware_family must be string or null`);
  for (const key of ["vulnerabilities", "affected_systems", "affected_regions"]) {
    if (incident[key] !== undefined && (!Array.isArray(incident[key]) || incident[key].some((v) => typeof v !== "string"))) {
      errors.push(`${p}.incident.${key} must be an array of strings`);
    }
  }

  const impact = item.impact ?? {};
  if (!(impact.confirmed_breach === null || typeof impact.confirmed_breach === "boolean")) errors.push(`${p}.impact.confirmed_breach must be boolean or null`);
  for (const key of ["affected_users", "affected_organizations", "records"]) {
    if (!isCount(impact[key])) errors.push(`${p}.impact.${key} must be null or a non-negative integer`);
  }
  if (!Array.isArray(impact.data_exposed)) errors.push(`${p}.impact.data_exposed must be an array`);
  if (typeof impact.service_disruption !== "boolean") errors.push(`${p}.impact.service_disruption must be boolean`);
  if (impact.service_recovered_at !== undefined && !isDate(impact.service_recovered_at)) errors.push(`${p}.impact.service_recovered_at must be YYYY-MM-DD or null`);

  if (!Array.isArray(item.sources) || item.sources.length === 0) {
    errors.push(`${p}.sources must contain at least one source`);
  } else {
    for (const [sourceIndex, source] of item.sources.entries()) {
      if (!isHttpUrl(source.url)) errors.push(`${p}.sources[${sourceIndex}].url is invalid`);
      if (!source.publisher || !source.kind) errors.push(`${p}.sources[${sourceIndex}] needs publisher and kind`);
      if (!isDate(source.published_at)) errors.push(`${p}.sources[${sourceIndex}].published_at must be YYYY-MM-DD or null`);
      if (!(source.title === undefined || source.title === null || typeof source.title === "string")) errors.push(`${p}.sources[${sourceIndex}].title must be string or null`);
    }
  }

  if (!allowedConfidence.has(item.confidence)) errors.push(`${p}.confidence is invalid`);
  if (!isDateTime(item.last_updated)) errors.push(`${p}.last_updated must be an ISO datetime`);
}

if (errors.length) {
  console.error(`Validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`OK: ${data.incidents.length} incidents validated (${data.schema_version})`);
