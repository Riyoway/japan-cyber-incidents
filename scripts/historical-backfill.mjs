import { readFile, writeFile } from "node:fs/promises";
import { gunzipSync } from "node:zlib";

const DATA_PATH = new URL("../data/incidents.json", import.meta.url);
const BACKFILL_ROOT = new URL("../data/.backfill/", import.meta.url);

const sourceCatalog = {
  vivisec: {
    kind: "security_media",
    publisher: "Vivisec",
    published_at: null,
    url: "https://vivisec.net/2026-unauthorized-access-incidents/",
    title: "2026年 不正アクセス・サイバー攻撃事例",
  },
  cyberondokei: {
    kind: "incident_tracker",
    publisher: "サイバー攻撃被害情報クロック",
    published_at: null,
    url: "https://www.cyber-ondokei.net/",
    title: "サイバー攻撃被害情報クロック",
  },
  techplus: {
    kind: "news",
    publisher: "TECH+",
    published_at: "2026-09-30",
    url: "https://news.mynavi.jp/techplus/article/20260930-5050581/",
    title: "2026年9月のサイバー攻撃・情報漏えい事例",
  },
  rocket: {
    kind: "security_media",
    publisher: "セキュリティ対策Lab",
    published_at: null,
    url: "https://rocket-boys.co.jp/security-measures-lab/2026-09-latest-cyber-attack-cases/",
    title: "2026年9月 サイバー攻撃・情報漏えい事例",
  },
  jluggage: {
    kind: "news_summary",
    publisher: "Japan Luggage Express",
    published_at: null,
    url: "https://www.jluggage.com/blog/japan-news/cyber-attack-companies-japan/",
    title: "Cyber Attack Companies Japan",
  },
  official_whiteessence: {
    kind: "official",
    publisher: "ホワイトエッセンス株式会社",
    published_at: "2026-04-17",
    url: "https://www.whiteessence.co.jp/news/?action=detail&id=43",
    title: "不正アクセスに関する調査結果のお知らせ",
  },
  official_jorsa: {
    kind: "official",
    publisher: "一般社団法人日本レコード協会",
    published_at: "2026-04-08",
    url: "https://www.jorsa.or.jp/ja/news/detail2320.html",
    title: "不正アクセスによる個人情報漏えいに関するお知らせ",
  },
};

const stripTokens = [
  "株式会社", "有限会社", "合同会社", "一般社団法人", "公益社団法人", "一般財団法人", "公益財団法人",
  "学校法人", "国立大学法人", "公立大学法人", "独立行政法人", "地方独立行政法人", "社会福祉法人", "医療法人",
];

function normalizeName(value = "") {
  let out = value.normalize("NFKC").toLowerCase();
  for (const token of stripTokens) out = out.replaceAll(token.toLowerCase(), "");
  return out.replace(/[\s\u3000・･\-ー－（）()「」『』【】\[\]/／,，.。&＆]/g, "");
}

function normalizeService(value = "") {
  return value.normalize("NFKC").toLowerCase().replace(/[\s\u3000・･\-ー－（）()「」『』【】\[\]/／,，.。&＆]/g, "");
}

function dayDistance(a, b) {
  if (!a || !b) return Number.POSITIVE_INFINITY;
  return Math.abs(new Date(`${a}T00:00:00Z`).getTime() - new Date(`${b}T00:00:00Z`).getTime()) / 86400000;
}

function overlaps(a = [], b = []) {
  const set = new Set(a);
  return b.some((value) => set.has(value));
}

function isSameCandidate(a, b) {
  if (normalizeName(a.name) !== normalizeName(b.name)) return false;
  if (dayDistance(a.date, b.date) > 14) return false;
  const aService = normalizeService(a.service ?? "");
  const bService = normalizeService(b.service ?? "");
  if (aService && bService && aService !== bService) return false;
  return overlaps(a.types, b.types);
}

function mergeCandidates(candidates) {
  const merged = [];
  for (const candidate of candidates.sort((a, b) => a.date.localeCompare(b.date))) {
    const existing = merged.find((item) => isSameCandidate(item, candidate));
    if (!existing) {
      merged.push({ ...candidate, source_keys: [candidate.source] });
      continue;
    }
    existing.date = existing.date < candidate.date ? existing.date : candidate.date;
    existing.types = [...new Set([...existing.types, ...candidate.types])];
    if ((candidate.summary?.length ?? 0) > (existing.summary?.length ?? 0)) existing.summary = candidate.summary;
    existing.service ??= candidate.service;
    existing.records = Math.max(existing.records ?? -1, candidate.records ?? -1);
    if (existing.records < 0) existing.records = null;
    existing.affected = Math.max(existing.affected ?? -1, candidate.affected ?? -1);
    if (existing.affected < 0) existing.affected = null;
    if (candidate.confirmed === true) existing.confirmed = true;
    else if (existing.confirmed !== true && candidate.confirmed === false) existing.confirmed = false;
    existing.source_keys = [...new Set([...existing.source_keys, candidate.source])];
  }
  return merged;
}

function candidateMatchesExisting(candidate, record) {
  if (normalizeName(candidate.name) !== normalizeName(record.organization?.name ?? "")) return false;
  const disclosed = record.incident?.disclosed_at ?? null;
  if (candidate.date === disclosed) return true;
  const distance = dayDistance(candidate.date, disclosed);
  const candidateService = normalizeService(candidate.service ?? "");
  const existingService = normalizeService(record.organization?.service ?? "");
  if (candidateService && existingService && (candidateService.includes(existingService) || existingService.includes(candidateService)) && distance <= 60) return true;
  return distance <= 14 && overlaps(candidate.types, record.incident?.types ?? []);
}

function inferOrganization(name) {
  if (/(大学|大学校|高専|学校|学園|学院)/.test(name)) {
    return { type: "educational_institution", industry: ["education"], business_model: ["public"] };
  }
  if (/(市役所|区役所|町役場|村役場|県庁|府庁|省|庁|局|地方公共団体|独立行政法人)/.test(name)) {
    return { type: "public_institution", industry: ["public_administration"], business_model: ["public"] };
  }
  if (/(協会|財団|社団|連盟|組合)/.test(name)) {
    return { type: "organization", industry: ["unknown"], business_model: ["other"] };
  }
  return { type: "company", industry: ["unknown"], business_model: ["other"] };
}

function inferDataExposed(summary = "") {
  const values = [];
  const add = (value) => { if (!values.includes(value)) values.push(value); };
  if (/氏名|名前/.test(summary)) add("name");
  if (/メール|mail/i.test(summary)) add("email_address");
  if (/電話/.test(summary)) add("phone_number");
  if (/住所/.test(summary)) add("address");
  if (/生年月日/.test(summary)) add("date_of_birth");
  if (/クレジット|カード情報/.test(summary)) add("credit_card_information");
  if (/パスワード/.test(summary)) add("password");
  if (/口座/.test(summary)) add("bank_account_information");
  if (/マイナンバー/.test(summary)) add("my_number");
  if (/免許/.test(summary)) add("drivers_license_information");
  if (/IPアドレス|IP address/i.test(summary)) add("ip_address");
  return values;
}

function incidentTitle(candidate) {
  const prefix = candidate.service ? `${candidate.service} ` : "";
  const types = new Set(candidate.types);
  if (types.has("ransomware")) return `${prefix}ランサムウェア被害`;
  if (types.has("data_breach")) return `${prefix}不正アクセスによる情報漏えい`;
  if (types.has("potential_data_breach")) return `${prefix}不正アクセスによる情報漏えいの可能性`;
  if (types.has("account_compromise")) return `${prefix}アカウントへの不正アクセス`;
  if (types.has("website_compromise")) return `${prefix}Webサイトへの不正アクセス・改ざん`;
  if (types.has("vulnerability_exploitation")) return `${prefix}脆弱性悪用による不正アクセス`;
  if (types.has("third_party_incident")) return `${prefix}外部サービス・委託先のセキュリティインシデント`;
  if (types.has("service_disruption")) return `${prefix}サイバー攻撃によるサービス障害`;
  return `${prefix}サイバーセキュリティインシデント`;
}

function isServiceDisruption(candidate) {
  if (candidate.types.includes("service_disruption")) return true;
  return /(サービス.{0,8}(停止|障害)|システム.{0,8}(停止|障害)|暗号化|利用停止|業務停止)/.test(candidate.summary ?? "");
}

function buildRecord(candidate, now) {
  const org = inferOrganization(candidate.name);
  const sourceKeys = candidate.source_keys ?? [candidate.source];
  const sources = sourceKeys.map((key) => sourceCatalog[key]).filter(Boolean).map((source) => ({ ...source }));
  const confirmed = candidate.confirmed === true ? true : candidate.confirmed === false ? false : null;
  const disruption = isServiceDisruption(candidate);
  const ransomware = candidate.types.includes("ransomware");
  const note = candidate.summary || null;

  return {
    id: `${candidate.date}-${candidate.slug}`,
    organization: {
      name: candidate.name,
      name_en: null,
      type: org.type,
      size: "unknown",
      industry: org.industry,
      business_model: org.business_model,
      service: candidate.service ?? null,
      country: "JP",
      estimated_total_users: {
        value: null,
        unit: "people",
        estimate_type: "unknown",
        basis: null,
        confidence: "unknown",
      },
    },
    incident: {
      title: incidentTitle(candidate),
      types: [...new Set(candidate.types)],
      occurred_at: null,
      detected_at: null,
      disclosed_at: candidate.date,
      status: { value: "reported", as_of: candidate.date },
      attack_vector: null,
      threat_actor: null,
      ransomware,
      malware_family: null,
      vulnerabilities: [],
      affected_systems: candidate.service ? [candidate.service] : [],
      affected_regions: [],
    },
    impact: {
      confirmed_breach: confirmed,
      affected_users: candidate.affected ?? null,
      affected_users_note: note,
      affected_organizations: 1,
      records: candidate.records ?? null,
      data_exposed: inferDataExposed(candidate.summary),
      service_disruption: disruption,
      service_disruption_note: disruption ? note : null,
      service_recovered_at: null,
    },
    sources,
    confidence: sourceKeys.some((key) => key.startsWith("official_")) ? "high" : "medium",
    last_updated: now,
  };
}

const dataset = JSON.parse(await readFile(DATA_PATH, "utf8"));
const rawCandidates = [];
for (let month = 1; month <= 9; month += 1) {
  const mm = String(month).padStart(2, "0");
  const encoded = (await readFile(new URL(`2026-${mm}.b64`, BACKFILL_ROOT), "utf8")).trim();
  const decoded = gunzipSync(Buffer.from(encoded, "base64")).toString("utf8");
  rawCandidates.push(...JSON.parse(decoded));
}

const candidates = mergeCandidates(rawCandidates);
const now = new Date().toISOString();
const added = [];
const skipped = [];
const working = [...dataset.incidents];

for (const candidate of candidates) {
  if (working.some((record) => candidateMatchesExisting(candidate, record))) {
    skipped.push(candidate);
    continue;
  }
  const record = buildRecord(candidate, now);
  if (working.some((item) => item.id === record.id)) {
    skipped.push(candidate);
    continue;
  }
  working.push(record);
  added.push(record);
}

working.sort((a, b) => b.incident.disclosed_at.localeCompare(a.incident.disclosed_at) || a.id.localeCompare(b.id));
dataset.generated_at = now;
dataset.incidents = working;
await writeFile(DATA_PATH, `${JSON.stringify(dataset)}\n`, "utf8");

const byMonth = {};
for (const record of added) {
  const month = record.incident.disclosed_at.slice(0, 7);
  byMonth[month] = (byMonth[month] ?? 0) + 1;
}

console.log(`Historical backfill generated_at=${now}`);
console.log(`Historical backfill: reviewed ${rawCandidates.length} discovery records, consolidated to ${candidates.length} candidate incidents; added ${added.length}; skipped ${skipped.length}; total ${working.length}.`);
console.log(`Added by month: ${JSON.stringify(byMonth)}`);
