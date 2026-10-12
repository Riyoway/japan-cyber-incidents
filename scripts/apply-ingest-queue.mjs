import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const DATA_FILE = path.join(ROOT, "data", "incidents.json");
const QUEUE_DIR = path.join(ROOT, "data", "queue");
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);

function assertSafePath(key) {
  const parts = key.split(".");
  if (!parts.length || parts.some((part) => !part || FORBIDDEN_SEGMENTS.has(part))) {
    throw new Error(`Unsafe or invalid path: ${key}`);
  }
  return parts;
}

function getParent(target, key, create = true) {
  const parts = assertSafePath(key);
  const leaf = parts.pop();
  let cursor = target;
  for (const part of parts) {
    if (cursor[part] == null) {
      if (!create) return [null, leaf];
      cursor[part] = {};
    }
    if (typeof cursor[part] !== "object" || Array.isArray(cursor[part])) {
      throw new Error(`Cannot descend into non-object path segment: ${part}`);
    }
    cursor = cursor[part];
  }
  return [cursor, leaf];
}

function setPath(target, key, value) {
  const [parent, leaf] = getParent(target, key, true);
  parent[leaf] = value;
}

function appendPath(target, key, values) {
  if (!Array.isArray(values)) throw new Error(`append value must be an array: ${key}`);
  const [parent, leaf] = getParent(target, key, true);
  if (parent[leaf] == null) parent[leaf] = [];
  if (!Array.isArray(parent[leaf])) throw new Error(`append target is not an array: ${key}`);

  const signature = (item) => {
    if (item && typeof item === "object" && !Array.isArray(item) && typeof item.url === "string") return `url:${item.url}`;
    return `json:${JSON.stringify(item)}`;
  };
  const seen = new Set(parent[leaf].map(signature));
  for (const value of values) {
    const sig = signature(value);
    if (!seen.has(sig)) {
      parent[leaf].push(value);
      seen.add(sig);
    }
  }
}

function applyOperation(dataset, operation, now) {
  if (!operation || typeof operation !== "object") throw new Error("Queue operation must be an object");

  if (operation.operation === "create") {
    const record = structuredClone(operation.record);
    if (!record || typeof record !== "object" || typeof record.id !== "string" || !record.id) {
      throw new Error("create operation requires record.id");
    }
    if (dataset.incidents.some((item) => item.id === record.id)) {
      throw new Error(`Incident already exists: ${record.id}`);
    }
    record.last_updated = now;
    dataset.incidents.push(record);
    return record.id;
  }

  if (operation.operation === "patch") {
    if (typeof operation.id !== "string" || !operation.id) throw new Error("patch operation requires id");
    const record = dataset.incidents.find((item) => item.id === operation.id);
    if (!record) throw new Error(`Incident not found: ${operation.id}`);

    const set = operation.set ?? {};
    if (typeof set !== "object" || Array.isArray(set)) throw new Error(`patch.set must be an object: ${operation.id}`);
    for (const [key, value] of Object.entries(set)) setPath(record, key, value);

    const append = operation.append ?? {};
    if (typeof append !== "object" || Array.isArray(append)) throw new Error(`patch.append must be an object: ${operation.id}`);
    for (const [key, values] of Object.entries(append)) appendPath(record, key, values);

    record.last_updated = now;
    return record.id;
  }

  throw new Error(`Unsupported queue operation: ${operation.operation}`);
}

if (!fs.existsSync(QUEUE_DIR)) {
  console.log("No ingest queue directory; nothing to apply.");
  process.exit(0);
}

const queueFiles = fs.readdirSync(QUEUE_DIR)
  .filter((name) => name.endsWith(".json"))
  .sort();

if (queueFiles.length === 0) {
  console.log("No queued JSON files; nothing to apply.");
  process.exit(0);
}

const dataset = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
if (!Array.isArray(dataset.incidents)) throw new Error("data/incidents.json has no incidents array");

const now = new Date().toISOString();
const touched = [];

for (const filename of queueFiles) {
  const fullPath = path.join(QUEUE_DIR, filename);
  const payload = JSON.parse(fs.readFileSync(fullPath, "utf8"));
  const operations = Array.isArray(payload.operations) ? payload.operations : [payload];
  if (operations.length === 0) throw new Error(`Queue file has no operations: ${filename}`);
  for (const operation of operations) touched.push(applyOperation(dataset, operation, now));
}

dataset.incidents.sort((a, b) => {
  const dateCompare = String(b?.incident?.disclosed_at ?? "").localeCompare(String(a?.incident?.disclosed_at ?? ""));
  return dateCompare || String(a.id).localeCompare(String(b.id));
});
dataset.generated_at = now;

fs.writeFileSync(DATA_FILE, `${JSON.stringify(dataset, null, 2)}\n`, "utf8");
for (const filename of queueFiles) fs.unlinkSync(path.join(QUEUE_DIR, filename));

console.log(`Applied ${touched.length} operation(s): ${touched.join(", ")}`);
console.log(`generated_at=${now}`);
