import { readFile, writeFile } from "node:fs/promises";

const dataPath = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(dataPath, "utf8"));
const now = new Date().toISOString();

function requireIncident(id) {
  const item = data.incidents.find((entry) => entry.id === id);
  if (!item) throw new Error(`Incident not found: ${id}`);
  return item;
}

function addSource(item, source) {
  if (!item.sources.some((existing) => existing.url === source.url)) {
    item.sources.push(source);
  }
}

const changed = [];

{
  const item = requireIncident("2026-08-10-sbcreative-businessit");
  item.incident.title = "Business+ITへの不正アクセスによる取引先担当者情報の不正取得";
  item.incident.types = ["vulnerability_exploitation", "unauthorized_access", "data_breach"];
  item.incident.occurred_at = "2026-08-06";
  item.incident.detected_at = "2026-08-06";
  item.incident.status = { value: "investigation_completed", as_of: "2026-09-14" };
  item.incident.attack_vector = "お取引先専用サービスの一部システムに存在した脆弱性を悪用した外部からの不正アクセス。";
  item.impact.confirmed_breach = true;
  item.impact.affected_users = 1132;
  item.impact.affected_users_note = "取引先担当者1,132名、1,137件。氏名、会社名、メールアドレス、電話番号が対象。2026-09-14の調査完了時点でも対象範囲に変更なし。";
  item.impact.records = 1137;
  item.impact.data_exposed = ["name", "company_name", "email_address", "phone_number"];
  item.impact.service_disruption = true;
  item.impact.service_disruption_note = "確認後、お取引先専用サービスおよび新規会員登録機能を一時停止し、安全確認・脆弱性修正を実施。";
  addSource(item, {
    kind: "official",
    publisher: "SBクリエイティブ株式会社",
    published_at: "2026-08-10",
    url: "https://www.softbankcr.co.jp/ja/news/2026/0810_it-21/",
    title: "「ビジネス＋IT」への不正アクセスに関するご報告"
  });
  addSource(item, {
    kind: "official",
    publisher: "SBクリエイティブ株式会社",
    published_at: "2026-09-14",
    url: "https://www.softbankcr.co.jp/ja/news/2026/0914_it-22/",
    title: "「ビジネス＋IT」への不正アクセスに関する調査結果および再発防止策について"
  });
  item.confidence = "high";
  item.last_updated = now;
  changed.push(item.id);
}

{
  const item = requireIncident("2026-08-03-kodansha-mail");
  item.incident.title = "フィッシングを起点とするメールアカウント侵害による連絡先情報流出";
  item.incident.types = ["phishing", "account_compromise", "data_breach"];
  item.incident.occurred_at = "2026-07-27";
  item.incident.detected_at = "2026-07-30";
  item.incident.status = { value: "contained", as_of: "2026-08-03" };
  item.incident.attack_vector = "取引先を偽装したフィッシングメールから偽ログイン画面へ誘導され、社員が認証情報を入力したことでメールアカウントへ不正ログインされた。";
  item.impact.confirmed_breach = true;
  item.impact.affected_users = null;
  item.impact.affected_users_note = "不正アクセスを受けた社員の連絡先情報が最大3,812件窃取され、そのうち553件のメールアドレス宛に当該社員を装ったフィッシングメールが送信された。3,812件は連絡先件数でありユニーク人数としては扱わない。";
  item.impact.records = 3812;
  item.impact.data_exposed = ["name", "email_address"];
  item.impact.service_disruption = false;
  item.impact.service_disruption_note = null;
  addSource(item, {
    kind: "official",
    publisher: "株式会社講談社",
    published_at: "2026-08-03",
    url: "https://www.kodansha.co.jp/notices/723",
    title: "不正アクセスによる個人情報流出のお詫びとお知らせ"
  });
  item.confidence = "high";
  item.last_updated = now;
  changed.push(item.id);
}

data.generated_at = now;
await writeFile(dataPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
console.log(`Confirmed-breach correction complete: ${changed.length} incident(s).`);
for (const id of changed) console.log(`- ${id}`);
