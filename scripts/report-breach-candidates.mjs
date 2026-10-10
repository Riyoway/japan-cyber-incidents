import { readFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));

const candidates = data.incidents.filter((item) => item?.impact?.confirmed_breach !== true);
const definiteWords = /(漏えい(?!した可能性)|漏洩(?!した可能性)|流出(?!した可能性)|窃取|不正取得|取得されたことを確認|外部に送信|公開され|持ち出し|exfiltrat|data breach)/i;
const possibleWords = /(可能性|おそれ|恐れ|疑い|調査中|確認されていない|確認されず)/;

const scored = candidates.map((item) => {
  const text = [item.incident?.title, ...(item.incident?.types ?? []), item.impact?.affected_users_note, item.impact?.service_disruption_note].filter(Boolean).join(" ");
  let score = 0;
  if ((item.incident?.types ?? []).includes("data_breach")) score += 8;
  if (definiteWords.test(text)) score += 5;
  if ((item.impact?.records ?? 0) > 0) score += 2;
  if ((item.impact?.affected_users ?? 0) > 0) score += 2;
  if ((item.impact?.data_exposed ?? []).length > 0) score += 2;
  if (possibleWords.test(text)) score -= 3;
  return { item, score };
}).sort((a, b) => b.score - a.score || String(b.item.incident?.disclosed_at).localeCompare(String(a.item.incident?.disclosed_at)));

console.log(`TOTAL=${data.incidents.length}`);
console.log(`CANDIDATES=${candidates.length}`);
console.log("=== HIGH SIGNAL (score >= 5) ===");
for (const { item, score } of scored.filter((x) => x.score >= 5)) {
  console.log(JSON.stringify({
    score,
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
