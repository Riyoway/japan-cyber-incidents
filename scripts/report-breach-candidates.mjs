import { readFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));

const candidates = data.incidents.filter((item) => item?.impact?.confirmed_breach !== true);
console.log(`TOTAL=${data.incidents.length}`);
console.log(`CANDIDATES=${candidates.length}`);
for (const item of candidates) {
  console.log(JSON.stringify({
    id: item.id,
    organization: item.organization?.name ?? null,
    disclosed_at: item.incident?.disclosed_at ?? null,
    title: item.incident?.title ?? null,
    types: item.incident?.types ?? [],
    confirmed_breach: item.impact?.confirmed_breach ?? null,
    affected_users: item.impact?.affected_users ?? null,
    records: item.impact?.records ?? null,
    data_exposed: item.impact?.data_exposed ?? [],
    note: item.impact?.affected_users_note ?? null,
    sources: (item.sources ?? []).map((s) => ({ kind: s.kind, publisher: s.publisher, title: s.title ?? null, url: s.url }))
  }));
}
