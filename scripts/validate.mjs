import { readFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));
const errors = [];
const ids = new Set();
const allowedConfidence = new Set(["high", "medium", "low", "unknown"]);
const allowedBusinessModels = new Set(["b2b", "b2c", "b2g", "public", "internal", "nonprofit", "other"]);

const isDate = (v) => v === null || /^\d{4}-\d{2}-\d{2}$/.test(v);
const isDateTime = (v) => typeof v === "string" && !Number.isNaN(Date.parse(v));
const isCount = (v) => v === null || (Number.isInteger(v) && v >= 0);

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

  const estimate = org.estimated_total_users ?? {};
  if (!(estimate.value === null || (Number.isInteger(estimate.value) && estimate.value >= 0))) errors.push(`${p}.organization.estimated_total_users.value must be null or a non-negative integer`);
  if (!allowedConfidence.has(estimate.confidence)) errors.push(`${p}.organization.estimated_total_users.confidence is invalid`);

  const incident = item.incident ?? {};
  if (!incident.title) errors.push(`${p}.incident.title is required`);
  if (!Array.isArray(incident.types) || incident.types.length === 0) errors.push(`${p}.incident.types must be non-empty`);
  for (const key of ["occurred_at", "detected_at", "disclosed_at"]) {
    if (!isDate(incident[key])) errors.push(`${p}.incident.${key} must be YYYY-MM-DD or null`);
  }
  if (!incident.disclosed_at) errors.push(`${p}.incident.disclosed_at is required`);

  if (typeof incident.status === "string") {
    if (!incident.status) errors.push(`${p}.incident.status must not be empty`);
  } else if (incident.status && typeof incident.status === "object" && !Array.isArray(incident.status)) {
    if (!incident.status.value || typeof incident.status.value !== "string") errors.push(`${p}.incident.status.value is required`);
    if (!isDate(incident.status.as_of) || incident.status.as_of === null) errors.push(`${p}.incident.status.as_of must be YYYY-MM-DD`);
  } else {
    errors.push(`${p}.incident.status must be a legacy string or { value, as_of } snapshot`);
  }

  if (!(incident.ransomware === null || typeof incident.ransomware === "boolean")) errors.push(`${p}.incident.ransomware must be boolean or null`);

  const impact = item.impact ?? {};
  if (!(impact.confirmed_breach === null || typeof impact.confirmed_breach === "boolean")) errors.push(`${p}.impact.confirmed_breach must be boolean or null`);
  for (const key of ["affected_users", "affected_organizations", "records"]) {
    if (!isCount(impact[key])) errors.push(`${p}.impact.${key} must be null or a non-negative integer`);
  }
  if (!Array.isArray(impact.data_exposed)) errors.push(`${p}.impact.data_exposed must be an array`);
  if (typeof impact.service_disruption !== "boolean") errors.push(`${p}.impact.service_disruption must be boolean`);

  if (!Array.isArray(item.sources) || item.sources.length === 0) {
    errors.push(`${p}.sources must contain at least one source`);
  } else {
    for (const [sourceIndex, source] of item.sources.entries()) {
      try {
        const url = new URL(source.url);
        if (!/^https?:$/.test(url.protocol)) throw new Error();
      } catch {
        errors.push(`${p}.sources[${sourceIndex}].url is invalid`);
      }
      if (!source.publisher || !source.kind) errors.push(`${p}.sources[${sourceIndex}] needs publisher and kind`);
      if (!isDate(source.published_at)) errors.push(`${p}.sources[${sourceIndex}].published_at must be YYYY-MM-DD or null`);
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
