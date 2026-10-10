import { readFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));
const candidates = data.incidents
  .filter((item) => item?.impact?.confirmed_breach !== true)
  .sort((a, b) => String(b.incident?.disclosed_at).localeCompare(String(a.incident?.disclosed_at)));
console.log(`TOTAL=${data.incidents.length}`);
console.log(`CANDIDATES=${candidates.length}`);
for (const item of candidates) {
  console.log(`${item.id}\t${item.incident?.disclosed_at ?? ""}\t${item.organization?.name ?? ""}\t${item.impact?.confirmed_breach ?? "null"}\t${item.impact?.records ?? ""}\t${item.impact?.affected_users ?? ""}`);
}
