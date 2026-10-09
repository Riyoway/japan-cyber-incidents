import { readFile, writeFile } from "node:fs/promises";

const dataPath = new URL("../data/incidents.json", import.meta.url);
const schemaPath = new URL("../schema/incident.schema.json", import.meta.url);

const reviewedAt = "2026-10-10";

const attributions = [
  {
    id: "2026-09-26-ikegami-tsushinki",
    name: "Qilin",
    actor_type: "ransomware_group",
    aliases: [],
    status: "attacker_claim",
    confidence: "high",
    basis: "Qilin listed Ikegami Tsushinki on its leak site and claimed theft of internal data. Ikegami later confirmed that information believed to be held by the company had appeared on an attacker's dark-web site, but public technical evidence has not independently established Qilin as the intrusion operator.",
    sources: [
      "https://www.galaxywarden.com/blog/breach/ikegami-tsushinki-company-limited-qilin-2026-09",
      "https://www.ikegami.co.jp/en/news/detail/574/"
    ]
  },
  {
    id: "2026-07-13-nichirei",
    name: "RansomHouse",
    actor_type: "ransomware_group",
    aliases: ["Ransomhouse"],
    status: "attacker_claim",
    confidence: "high",
    basis: "RansomHouse listed Nichirei on its leak site and claimed to have stolen internal data. Nichirei confirmed a cyberattack but deliberately withheld technical attack details and has not publicly confirmed RansomHouse attribution.",
    sources: [
      "https://www.galaxywarden.com/blog/breach/nichirei-ransomhouse-2026-08",
      "https://www.nichirei.co.jp/ir/news/2026/t_in226.html"
    ]
  },
  {
    id: "2026-06-24-nidec-chaun-choung",
    name: "Blackfield",
    actor_type: "ransomware_group",
    aliases: ["BlackField"],
    status: "attacker_claim",
    confidence: "medium",
    basis: "Blackfield listed Nidec Chaun-Choung Technology Corporation (CCIC) on its leak site and claimed compromise and data theft. The public evidence located is a leak-site claim rather than independent technical attribution.",
    sources: [
      "https://www.galaxywarden.com/blog/breach/ccic-com-tw-blackfield-2026-06",
      "https://www.dexpose.io/blackfield-ransomware-strikes-nidec-chaun-choung-technology-corporation/"
    ]
  },
  {
    id: "2026-05-12-tokyo-hoso",
    name: "Qilin",
    actor_type: "ransomware_group",
    aliases: [],
    status: "attacker_claim",
    confidence: "medium",
    basis: "Qilin publicly claimed TokyoHosoKogyo Corporation and the victim appeared in ransomware leak-site monitoring. Tokyo Hoso Kogyo confirmed a ransomware incident but its public notice does not identify Qilin as the attacker.",
    sources: [
      "https://ransomfeed.it/index.php?id_post=31684&page=post_details",
      "https://www.dexpose.io/qilin-targets-tokyohosokogyo-corporation-in-ransomware-attack/",
      "https://www.tokyohoso.co.jp/news/1366/"
    ]
  },
  {
    id: "2026-05-07-tokyo-seimitsu-us",
    name: "AiLock",
    actor_type: "ransomware_group",
    aliases: ["Ailock"],
    status: "attacker_claim",
    confidence: "high",
    basis: "AiLock listed Accretech America Inc. on its leak site after Tokyo Seimitsu confirmed a ransomware attack at the U.S. subsidiary. The company's disclosure does not publicly attribute the attack to AiLock.",
    sources: [
      "https://www.galaxywarden.com/blog/breach/accretech-america-inc-ailock-2026-05",
      "https://www.accretech.com/en/news/cyber-incident_20260507.html"
    ]
  },
  {
    id: "2026-04-30-eitech-pro",
    name: "SafePay",
    actor_type: "ransomware_group",
    aliases: ["Safepay"],
    status: "attacker_claim",
    confidence: "medium",
    basis: "SafePay listed eitecpro.co.jp on its leak site and claimed exfiltration of internal files. The attribution is retained as an attacker claim because no independent technical attribution was located in the reviewed public sources.",
    sources: [
      "https://www.galaxywarden.com/blog/breach/eitecpro-co-jp-safepay-2026-05"
    ]
  },
  {
    id: "2026-03-10-higashiyama-sangyo",
    name: "Qilin",
    actor_type: "ransomware_group",
    aliases: ["QILIN"],
    status: "attacker_claim",
    confidence: "high",
    basis: "Higashiyama Sangyo's own final investigation update states that its dark-web investigation found company data published on the QILIN ransomware group's blog. This strongly corroborates Qilin's possession/publication claim, but the public report does not state that forensic evidence conclusively attributed the initial intrusion to Qilin.",
    sources: [
      "https://www.higashiyama.com/829/"
    ]
  },
  {
    id: "2026-02-03-anabuki-kosan-group",
    name: "Qilin",
    actor_type: "ransomware_group",
    aliases: [],
    status: "attacker_claim",
    confidence: "medium",
    basis: "Qilin publicly claimed Anabuki Kosan on its leak site. Anabuki Kosan confirmed a ransomware incident and later confirmed information leakage, but its public disclosures reviewed here do not identify Qilin as the attacker.",
    sources: [
      "https://www.dexpose.io/qilin-ransomware-attack-targets-anabuki-kosan/",
      "https://ransomfeed.it/index.php?id_post=29574&page=post_details",
      "https://www.anabuki.ne.jp/cms_upload/news/427/20260311_higaihassei3.pdf"
    ]
  }
];

const data = JSON.parse(await readFile(dataPath, "utf8"));
const schema = JSON.parse(await readFile(schemaPath, "utf8"));

schema.$defs.threatActorAttribution = {
  type: "object",
  required: ["name", "actor_type", "aliases", "status", "confidence", "basis", "sources", "reviewed_at"],
  properties: {
    name: { type: ["string", "null"] },
    actor_type: {
      enum: ["ransomware_group", "cybercrime_group", "state_sponsored", "hacktivist", "individual", "unknown"]
    },
    aliases: { type: "array", items: { type: "string" } },
    status: { enum: ["confirmed", "suspected", "attacker_claim", "unknown"] },
    confidence: { enum: ["high", "medium", "low", "unknown"] },
    basis: { type: ["string", "null"] },
    sources: { type: "array", items: { type: "string", format: "uri" } },
    reviewed_at: { type: "string", format: "date" }
  },
  additionalProperties: false
};

schema.$defs.incident.properties.threat_actor_attribution = {
  oneOf: [
    { $ref: "#/$defs/threatActorAttribution" },
    { type: "null" }
  ]
};

const now = new Date().toISOString();
const changed = [];
for (const attribution of attributions) {
  const item = data.incidents.find((incident) => incident.id === attribution.id);
  if (!item) throw new Error(`Incident not found: ${attribution.id}`);

  const next = {
    name: attribution.name,
    actor_type: attribution.actor_type,
    aliases: attribution.aliases,
    status: attribution.status,
    confidence: attribution.confidence,
    basis: attribution.basis,
    sources: attribution.sources,
    reviewed_at: reviewedAt
  };

  const previous = JSON.stringify(item.incident.threat_actor_attribution ?? null);
  const replacement = JSON.stringify(next);
  if (item.incident.threat_actor !== attribution.name || previous !== replacement) {
    item.incident.threat_actor = attribution.name;
    item.incident.threat_actor_attribution = next;
    item.last_updated = now;
    changed.push(attribution.id);
  }
}

if (changed.length > 0) {
  data.schema_version = "1.1.0";
  data.generated_at = now;
}

await writeFile(schemaPath, `${JSON.stringify(schema, null, 2)}\n`, "utf8");
await writeFile(dataPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");

console.log(`Threat actor attribution backfill complete: ${changed.length} incident(s) changed.`);
for (const id of changed) console.log(`- ${id}`);
