import { readFile, writeFile } from "node:fs/promises";

const path = new URL("../data/incidents.json", import.meta.url);
const data = JSON.parse(await readFile(path, "utf8"));
const now = new Date().toISOString();
const beforeConfirmed = data.incidents.filter((x) => x?.impact?.confirmed_breach === true).length;
const touched = [];
const added = [];

const source = (kind, publisher, published_at, url, title) => ({ kind, publisher, published_at, url, title });
const addSource = (item, s) => {
  item.sources ??= [];
  if (!item.sources.some((x) => x.url === s.url)) item.sources.push(s);
};
const setConfirmed = (item, asOf, note, opts = {}) => {
  const types = new Set(item.incident.types ?? []);
  types.delete("potential_data_breach");
  types.add("data_breach");
  item.incident.types = [...types];
  item.incident.status = { value: "impact_confirmed", as_of: asOf };
  item.impact.confirmed_breach = true;
  if (opts.affected_users !== undefined) item.impact.affected_users = opts.affected_users;
  if (opts.records !== undefined) item.impact.records = opts.records;
  if (opts.data_exposed !== undefined) item.impact.data_exposed = opts.data_exposed;
  if (opts.service_disruption !== undefined) item.impact.service_disruption = opts.service_disruption;
  if (opts.service_disruption_note !== undefined) item.impact.service_disruption_note = opts.service_disruption_note;
  if (opts.service_recovered_at !== undefined) item.impact.service_recovered_at = opts.service_recovered_at;
  item.impact.affected_users_note = note;
  item.confidence = opts.confidence ?? "high";
  item.last_updated = now;
};
const patch = (id, fn) => {
  const item = data.incidents.find((x) => x.id === id);
  if (!item) throw new Error(`Missing incident: ${id}`);
  fn(item);
  touched.push(id);
};
const estimateUnknown = () => ({ value: null, unit: "people", estimate_type: "unknown", basis: null, confidence: "unknown" });
const makeIncident = ({ id, name, type = "company", industry, business_model, service = null, title, types, occurred_at = null, detected_at = null, disclosed_at, statusAsOf, attack_vector = null, ransomware = false, affected_users = null, records = null, data_exposed = [], service_disruption = false, service_disruption_note = null, note, sources, affected_organizations = 1 }) => ({
  id,
  organization: {
    name,
    name_en: null,
    type,
    size: "unknown",
    industry,
    business_model,
    service,
    country: "JP",
    estimated_total_users: estimateUnknown()
  },
  incident: {
    title,
    types,
    occurred_at,
    detected_at,
    disclosed_at,
    status: { value: "impact_confirmed", as_of: statusAsOf ?? disclosed_at },
    attack_vector,
    threat_actor: null,
    ransomware
  },
  impact: {
    confirmed_breach: true,
    affected_users,
    affected_users_note: note,
    affected_organizations,
    records,
    data_exposed,
    service_disruption,
    service_disruption_note
  },
  sources,
  confidence: "high",
  last_updated: now
});
const add = (item) => {
  if (data.incidents.some((x) => x.id === item.id)) return;
  data.incidents.push(item);
  added.push(item.id);
};

// Existing records whose later public disclosures confirmed actual acquisition, viewing,
// publication, exfiltration, or leakage. Attacker-only claims are intentionally excluded.
patch("2026-07-13-nichirei", (item) => {
  setConfirmed(item, "2026-09-18", "最終調査で漏えいを確認。配送先3,308件、取引先6,849件、従業員・元従業員・家族・求職者43,709件の計53,866件。", {
    records: 53866,
    affected_users: null,
    data_exposed: ["name", "address", "phone_number", "email_address", "date_of_birth", "gender", "employee_number", "compensation_information", "hr_information"],
    service_recovered_at: "2026-07-24"
  });
  addSource(item, source("official", "株式会社ニチレイ", "2026-09-18", "https://www.nichirei.co.jp/news/2026/524.html", "当社グループでのシステム障害発生について（第7報）"));
});

patch("2026-06-23-kddi-mail", (item) => {
  setConfirmed(item, "2026-07-21", "後続調査で12,231,954件のメールアドレスの漏えいを確認。うち7,616,173件はパスワード情報を含む。", {
    affected_users: 12231954,
    records: 12231954,
    data_exposed: ["email_address", "password"]
  });
  addSource(item, source("official", "KDDI株式会社", "2026-07-21", "https://newsroom.kddi.com/news/assets/2026/kddi_nr_s-73_4619/kddi_nr_s-73_4619_pdf_01.pdf", "不正アクセスによる情報漏えいに関する調査結果について"));
});

patch("2026-03-06-murata", (item) => {
  setConfirmed(item, "2026-04-06", "外部専門機関の調査により、顧客・取引先情報および従業員等の個人情報が第三者に不正取得されていたことを確認。公表数は取得済みと可能性を含むため確定漏えい件数は未設定。", { affected_users: null, records: null });
  addSource(item, source("official", "株式会社村田製作所", "2026-04-06", "https://corporate.murata.com/ja-jp/newsroom/news/company/general/2026/0406", "当社グループへの不正アクセスに関する調査結果について"));
});

patch("2026-03-10-higashiyama-sangyo", (item) => {
  setConfirmed(item, "2026-05-12", "QILINのブログ上で自社データの公開を確認し、外部専門機関の最終報告を踏まえて会社自身が情報漏えいがあったと判断。", { affected_users: null, records: null });
  addSource(item, source("official", "東山産業株式会社", "2026-05-12", "https://www.higashiyama.com/829/", "当社サーバー等へのランサムウェア攻撃に関するお知らせとお詫び（第4報）"));
});

patch("2026-02-03-anabuki-kosan-group", (item) => {
  setConfirmed(item, "2026-04-03", "ランサムウェア被害の後続調査で情報流出を確認し、第4報として公表。公開資料から一意に確定できる人数・レコード総数は未設定。", { affected_users: null, records: null });
  addSource(item, source("official", "穴吹興産株式会社", "2026-04-03", "https://www.anabuki.ne.jp/cms_upload/news/429/20260403_higaihassei4.pdf", "情報流出に関するお知らせとお詫び（ランサムウェア被害発生のお知らせ（第4報））"));
});

patch("2026-09-30-kansai-univ-international", (item) => {
  setConfirmed(item, "2026-10-06", "eポートフォリオシステム上の複数ファイルが外部から繰り返し取得されていたことをアクセス記録で確認。", { affected_users: null, records: null, service_disruption: true });
  addSource(item, source("official", "関西国際大学", "2026-10-06", "https://www.kuins.ac.jp/news/2026/10/post_1450.html", "不正アクセスによる情報の外部流出と情報システムの停止について（お詫びとご報告）"));
});

patch("2026-05-01-money-forward", (item) => {
  setConfirmed(item, "2026-06-23", "GitHub上の侵害されたリポジトリに個人情報が含まれており、個人情報の流出は当該GitHubリポジトリに限定されることを最終調査で確認。本番データベースからの漏えいは確認されていない。", { affected_users: null, records: null });
  addSource(item, source("official", "株式会社マネーフォワード", "2026-06-23", "https://corp.moneyforward.com/news/info/20260623-mf-press-1/", "GitHubへの不正アクセスに関する詳細調査の完了およびセキュリティ対策強化のお知らせ（第四報）"));
});

patch("2026-04-03-campfire", (item) => {
  setConfirmed(item, "2026-06-02", "フォレンジック調査で個人情報を含むクエリ結果1件の出力を確認。225,846人は漏えい確定人数ではなく潜在的な影響範囲のため affected_users には採用しない。", { affected_users: null, records: 1 });
  addSource(item, source("official", "株式会社CAMPFIRE", "2026-06-02", "https://campfire.co.jp/press/2026/06/02/campfire/", "不正アクセスに関する調査結果と再発防止策について"));
});

patch("2026-06-15-delightful-meruhai", (item) => {
  setConfirmed(item, "2026-08-13", "メール配信SaaS「める配くん」における不正アクセスについて、運営会社が情報漏えい事故として公表。確定総件数は公開情報から一意に設定できないため未設定。", { affected_users: null, records: null });
  addSource(item, source("official", "株式会社ディライトフル", "2026-08-13", "https://www.dlfl.jp/news/%E5%BC%8A%E7%A4%BE%E3%83%A1%E3%83%BC%E3%83%AB%E9%85%8D%E4%BF%A1saas%E6%83%85%E5%A0%B1%E6%BC%8F%E3%81%88%E3%81%84%E4%BA%8B%E6%95%85%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6%E3%81%AE%E3%81%8A%E7%9F%A5/", "弊社メール配信SaaS情報漏えい事故についてのお知らせ"));
});

patch("2026-09-09-applynow-platform", (item) => {
  setConfirmed(item, "2026-10-02", "ApplyNowの調査結果を受け、利用企業が同サービスで管理していた個人情報の外部漏えいを確認したと公表。", { affected_users: null, records: null });
  addSource(item, source("official_victim", "株式会社ワンダーテーブル", "2026-10-02", "https://wondertable.com/blogs/news-release/%E5%80%8B%E4%BA%BA%E6%83%85%E5%A0%B1%E6%BC%8F%E3%81%88%E3%81%84%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6%E3%81%8A%E7%9F%A5%E3%82%89%E3%81%9B%E3%81%A8%E3%81%8A%E8%A9%AB%E3%81%B3", "個人情報漏えいについてお知らせとお詫び"));
});

patch("2026-05-28-asoview", (item) => {
  setConfirmed(item, "2026-05-28", "宿泊予約管理システムへの不正アクセスにより予約データ27,163件が外部に流出したことが公表された。人数とは一致しないため affected_users は未設定。", { affected_users: null, records: 27163 });
  addSource(item, source("official", "アソビュー株式会社", "2026-05-28", "https://www.asoview.co.jp/news/articles/wMidTEDr", "不正アクセスによる個人情報漏えいに関するお知らせ"));
});

patch("2026-07-30-rakuten-drive", (item) => {
  setConfirmed(item, "2026-10-06", "調査で複数の情報取得を確認。687アカウントのプロフィール情報、313アカウントの認証関連情報、15,382アカウントで保存された写真・文書の取得・閲覧が確認された。範囲が重なるため総人数は未設定。", {
    affected_users: null,
    records: null,
    data_exposed: ["account_name", "profile", "password_hash", "stored_photos", "stored_documents"]
  });
  addSource(item, source("official", "楽天ドライブ", "2026-10-06", "https://support.rakuten-drive.com/hc/ja/articles/62934949147929--%E9%87%8D%E8%A6%81-%E6%A5%BD%E5%A4%A9%E3%83%89%E3%83%A9%E3%82%A4%E3%83%96-%E3%81%AB%E3%81%8A%E3%81%91%E3%82%8B%E4%B8%8D%E6%AD%A3%E3%82%A2%E3%82%AF%E3%82%BB%E3%82%B9%E3%81%AE%E7%99%BA%E7%94%9F%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6", "【重要】楽天ドライブ における不正アクセスの発生について"));
});

patch("2026-07-07-frau-international", (item) => {
  setConfirmed(item, "2026-08-03", "外部専門機関の調査で管理メールデータが外部へ出力されたことを確認。個人情報3,560件については漏えい可能性として公表されているため、確定レコード数には採用しない。", { affected_users: null, records: null });
  addSource(item, source("official", "株式会社フラウ・インターナショナル", "2026-08-03", "https://www.frau-inter.co.jp/other/20260803_6519/", "不正アクセスに関する調査結果のお知らせ"));
});

patch("2026-06-04-visual-arts", (item) => {
  setConfirmed(item, "2026-06-04", "不正アクセス後、未発売タイトルのマスターデータが第三者により公開されたことを確認。個人情報等の追加流出範囲は可能性段階のため件数は未設定。", { affected_users: null, records: null });
  addSource(item, source("official_press_release", "株式会社ビジュアルアーツ", "2026-06-04", "https://prtimes.jp/main/html/rd/p/000000091.000147227.html", "不正アクセスに関するお知らせ"));
});

// Missing confirmed incidents found during the one-time audit.
add(makeIncident({
  id: "2026-10-05-white-essence-system",
  name: "ホワイトエッセンス株式会社",
  industry: ["healthcare", "dental", "software"],
  business_model: ["b2c", "b2b"],
  service: "予約サイト・基幹システム",
  title: "予約サイト・基幹システムへの不正アクセスによる個人情報漏えい",
  types: ["vulnerability_exploitation", "unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-08-05",
  detected_at: "2026-08-05",
  disclosed_at: "2026-10-05",
  attack_vector: "予約サイトのプログラム上の脆弱性を悪用し、予約サイトを起点に基幹システムへ不正アクセスしたと公表されている。",
  affected_users: null,
  records: null,
  data_exposed: ["name", "address", "phone_number", "email_address", "date_of_birth", "gender", "employer", "login_id", "password_hash", "service_usage_information"],
  service_disruption: true,
  service_disruption_note: "2026年8月12日から予約サイト・基幹システムを一時停止。",
  note: "外部専門機関の調査で約105万アカウント分の個人情報が外部へ持ち出されていたことを確認。概数かつ顧客・加盟院関係者・本部社員等を含むため records/affected_users は未設定。",
  sources: [
    source("official", "ホワイトエッセンス株式会社", "2026-10-05", "https://www.whiteessence.com/news/2026/10/", "不正アクセスによる個人情報の漏えいに関するお詫びとお知らせ"),
    source("news", "ITmedia NEWS", "2026-10-05", "https://www.itmedia.co.jp/news/archive/2610", "ホワイトエッセンス、約105万アカウントの個人情報流出")
  ]
}));

add(makeIncident({
  id: "2026-10-05-gmo-infoq",
  name: "GMOリサーチ&AI株式会社",
  industry: ["market_research", "internet_service"],
  business_model: ["b2c", "b2b"],
  service: "infoQ",
  title: "infoQへの不正アクセスによる個人情報持ち出し",
  types: ["vulnerability_exploitation", "unauthorized_access", "data_breach", "account_abuse", "service_disruption"],
  occurred_at: "2026-10-02",
  detected_at: "2026-10-03",
  disclosed_at: "2026-10-05",
  attack_vector: "サイトで使用していたソフトウェアの脆弱性を悪用して侵入。",
  affected_users: null,
  records: 948498,
  data_exposed: ["name", "name_kana", "gender", "date_of_birth", "email_address", "address", "phone_number", "password_hash", "member_id", "nickname", "points", "usage_information"],
  service_disruption: true,
  service_disruption_note: "2026年10月3日15時にinfoQへの外部アクセスを遮断しサービス停止。",
  note: "会員個人情報が外部に持ち出されたことを確認。948,498件は10月5日時点で同社が保有する個人情報の最大対象件数。611件・2,869,500円分のポイント不正交換も確認。",
  sources: [source("official", "GMOリサーチ&AI株式会社", "2026-10-05", "https://gmo-research.ai/pressroom/notice/notice-20261005", "infoQへの不正アクセスによる個人情報漏えいに関するお詫びとお知らせ")]
}));

add(makeIncident({
  id: "2026-10-05-monogatari-yakiniku-king",
  name: "株式会社物語コーポレーション",
  industry: ["restaurant", "mobile_app"],
  business_model: ["b2c"],
  service: "焼肉きんぐ公式アプリ",
  title: "焼肉きんぐ公式アプリ会員管理システムへの不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach"],
  occurred_at: "2026-10-02",
  detected_at: "2026-10-02",
  disclosed_at: "2026-10-05",
  affected_users: 10788963,
  records: 10788963,
  data_exposed: ["member_number", "name", "email_address", "phone_number"],
  note: "登録10,808,784件のうち10,788,963件の会員情報漏えいを確認。ログインパスワード、生年月日、性別、郵便番号、ポイント・店舗利用履歴は漏えいなし。",
  sources: [source("official", "株式会社物語コーポレーション", "2026-10-05", "https://www.monogatari.co.jp/news/261005_news/", "焼肉きんぐ公式アプリ 会員管理システムへの第三者からの不正アクセスによる個人情報漏えいに関するお詫び")]
}));

add(makeIncident({
  id: "2026-10-06-mrmax",
  name: "株式会社ミスターマックス・ホールディングス",
  industry: ["retail", "ecommerce", "mobile_app"],
  business_model: ["b2c"],
  service: "MrMaxアプリ・オンラインストア",
  title: "MrMaxアプリ・オンラインストアへの不正アクセスによる情報流出",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-10-03",
  detected_at: "2026-10-03",
  disclosed_at: "2026-10-06",
  affected_users: null,
  records: null,
  data_exposed: ["member_id", "name", "email_address", "phone_number"],
  service_disruption: true,
  service_disruption_note: "発覚後にサービスを一時停止し、同日中に外部アクセスを遮断。",
  note: "会員個人情報の一部が外部に流出したことを確認。最大1,735,154人は会員登録されていた対象範囲で、全員の流出確定数ではないため件数は未設定。",
  sources: [source("official", "株式会社ミスターマックス・ホールディングス", "2026-10-06", "https://www.mrmax.co.jp/info/incident_20261006/", "不正アクセスによる情報流出に関するお詫びとお知らせ")]
}));

add(makeIncident({
  id: "2026-10-05-kufu-machi-talk",
  name: "株式会社くふうカンパニー",
  industry: ["internet_service", "community_platform"],
  business_model: ["b2c"],
  service: "くふう まちトークβ版",
  title: "くふう まちトークβ版への不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-10-02",
  detected_at: "2026-10-02",
  disclosed_at: "2026-10-05",
  affected_users: 1,
  records: 1,
  data_exposed: ["email_address"],
  service_disruption: true,
  service_disruption_note: "2026年10月5日にサービス停止。",
  note: "少なくとも1名のメールアドレス漏えいを確認。生年月日・性別は漏えい可能性として調査継続中。",
  sources: [source("official", "株式会社くふうカンパニー", "2026-10-05", "https://kufu.co.jp/2026/10/05/kufu-announce/", "くふう まちトークβ版への不正アクセスに関するお知らせとお詫び")]
}));

add(makeIncident({
  id: "2026-10-01-jaea-jrr3",
  name: "国立研究開発法人日本原子力研究開発機構",
  type: "research_institute",
  industry: ["research", "nuclear"],
  business_model: ["public"],
  service: "JRR-3研究支援サイト",
  title: "JRR-3研究支援サイトへの不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-09-25",
  detected_at: "2026-09-25",
  disclosed_at: "2026-10-01",
  affected_users: 175,
  records: 367,
  data_exposed: ["identity_document_images", "my_number", "medical_examination_results", "radiation_worker_certificate"],
  service_disruption: true,
  service_disruption_note: "不正アクセス確認日に研究支援サイトへの外部アクセスを停止。",
  note: "2,419ファイルの不正ダウンロードを確認。そのうち個人情報を含む367ファイル・175人分が漏えい。身分証画像200件（6名はマイナンバー含む）、健康診断結果146件、放射線業務従事者証明書21件。",
  sources: [source("official", "日本原子力研究開発機構", "2026-10-01", "https://www.jaea.go.jp/02/press2026/p26100105/", "不正アクセスによる情報漏えいについて")]
}));

add(makeIncident({
  id: "2026-10-07-toda",
  name: "戸田建設株式会社",
  industry: ["construction"],
  business_model: ["b2b", "b2g"],
  title: "社内システムへの不正アクセスによる取引先・従業員情報漏えい",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-10-01",
  detected_at: "2026-10-05",
  disclosed_at: "2026-10-07",
  affected_users: null,
  records: null,
  data_exposed: ["email_address", "transaction_data", "name", "address", "phone_number", "department"],
  service_disruption: true,
  service_disruption_note: "被害拡大防止のため関連システム・通信を遮断して調査。",
  note: "取引先担当者メールアドレス最大7,200件、取引データ最大6,000件、従業員4,778名分の氏名・住所・電話・メール・所属部署の漏えいを確認。単位が異なるため単純合算しない。",
  sources: [source("official", "戸田建設株式会社", "2026-10-07", "https://www.toda.co.jp/news/2026/20261007_006350.html", "個人情報漏洩に関するお知らせとお詫び")]
}));

add(makeIncident({
  id: "2026-09-29-eplus-sumachike-refund",
  name: "株式会社イープラス",
  industry: ["ticketing", "entertainment"],
  business_model: ["b2c", "b2b"],
  service: "スマチケ払戻し情報管理システム",
  title: "スマチケ払戻し情報管理システムへの不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach"],
  occurred_at: "2026-09-11",
  detected_at: "2026-09-14",
  disclosed_at: "2026-09-29",
  affected_users: null,
  records: 1463,
  data_exposed: ["email_address", "name_kana", "bank_account_information", "postal_code", "address", "name"],
  note: "1,463件の個人情報漏えいを確認。内訳は銀行振込払戻し751件、カード払戻し644件、郵便払出証書払戻し68件。",
  sources: [source("official", "株式会社イープラス", "2026-09-29", "https://corp.eplus.jp/press-release/1824/", "電子チケット「スマチケ」払戻し情報管理システムへの不正アクセスによる個人情報漏えいに関するお詫びとお知らせ")]
}));

add(makeIncident({
  id: "2026-06-30-aflac",
  name: "アフラック生命保険株式会社",
  industry: ["insurance"],
  business_model: ["b2c"],
  service: "アフラック よりそうネット等",
  title: "よりそうネット等への不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  occurred_at: "2026-06-10",
  detected_at: "2026-06-25",
  disclosed_at: "2026-06-30",
  affected_users: 4400000,
  records: null,
  data_exposed: ["name", "date_of_birth", "gender", "address", "phone_number", "insured_person_information", "beneficiary_name", "policy_number", "coverage_information", "bank_account_information"],
  service_disruption: true,
  service_disruption_note: "情報漏えい拡大防止のため「よりそうネット」を停止し、後に安全性確認後に一部を除き再開。",
  note: "約440万人の顧客関連個人情報の漏えいを確認。うち約22万人は保険料振替口座情報を含む。",
  sources: [
    source("official", "アフラック生命保険株式会社", "2026-06-30", "https://www.aflac.co.jp/corp/profile/news/2026/", "当社システムに対する不正アクセスの発生および情報漏えいに関するお詫びとお知らせ"),
    source("official", "アフラック生命保険株式会社", "2026-10-01", "https://www.aflac.co.jp/info/yorisou_faq.html", "当社システムに対する不正アクセスの発生および情報漏えいに関するFAQ")
  ]
}));

add(makeIncident({
  id: "2026-04-23-2rinkan",
  name: "株式会社和光ケミカル（2りんかん運営関連）",
  industry: ["retail", "automotive", "mobile_app"],
  business_model: ["b2c"],
  service: "2りんかんアプリ・会員サーバー",
  title: "2りんかん会員サーバーへの不正アクセスによる個人情報漏えい",
  types: ["unauthorized_access", "data_breach", "service_disruption"],
  disclosed_at: "2026-04-23",
  statusAsOf: "2026-06-19",
  attack_vector: "アプリのAPIを悪用した不正アクセス。",
  affected_users: 3179454,
  records: 3179454,
  data_exposed: ["name", "address", "phone_number", "date_of_birth", "gender", "email_address", "member_number", "points", "app_user_id", "password", "vehicle_information"],
  service_disruption: true,
  service_disruption_note: "調査・対策のためアプリの一部機能を制限。",
  note: "最終調査で3,179,454名分の会員データが取得されたことを特定。第二報の最大3,455,754名から下方修正。",
  sources: [source("official", "2りんかん", "2026-06-19", "https://2rinkan.jp/annai/20260423/", "当社における不正アクセスによる個人情報漏えいに関するお詫びとお知らせ【最終報】")]
}));

add(makeIncident({
  id: "2026-07-14-media4u-sms",
  name: "株式会社メディア4u",
  industry: ["saas", "communications", "sms"],
  business_model: ["b2b"],
  service: "SMS配信システム",
  title: "SMS配信システムへの不正アクセスによるアカウント管理情報漏えい",
  types: ["vulnerability_exploitation", "unauthorized_access", "data_breach"],
  occurred_at: "2026-06-24",
  detected_at: "2026-06-24",
  disclosed_at: "2026-07-14",
  affected_users: null,
  records: 95412,
  data_exposed: ["account_management_information", "contact_name", "email_address"],
  note: "アカウント管理情報一覧ファイル95,412レコードの外部流出を確認。うち個人情報に該当し得る情報を含む精査対象は22,928レコード。人数とは一致しない。",
  sources: [
    source("official", "株式会社メディア4u", "2026-07-14", "https://www.media4u.co.jp/news/3351", "SMS配信システムへの不正アクセスに関するお知らせとお詫び"),
    source("official", "株式会社メディア4u", "2026-07-17", "https://www.media4u.co.jp/news/3354", "SMS配信システムへの不正アクセスに関するお知らせとお詫び（第2報）")
  ]
}));

add(makeIncident({
  id: "2026-10-05-resortinn-ishigaki",
  name: "リゾーツ琉球株式会社",
  industry: ["hospitality", "hotel"],
  business_model: ["b2c"],
  service: "ホテルリゾートイン石垣島",
  title: "宿泊管理システムへの不正アクセスによる宿泊者情報漏えい",
  types: ["third_party_incident", "unauthorized_access", "data_breach"],
  occurred_at: "2026-09-18",
  detected_at: null,
  disclosed_at: "2026-10-05",
  affected_users: 17170,
  records: 17170,
  data_exposed: ["name", "name_kana", "email_address", "phone_number", "postal_code", "address", "date_of_birth", "gender", "occupation", "nationality", "passport_image", "signature_image", "face_photo"],
  note: "宿泊管理システム提供事業者への不正アクセスにより17,170名分の情報が不正取得。うちパスポート画像234名、署名画像6名、顔写真5名を含む。",
  sources: [source("official", "リゾーツ琉球株式会社", "2026-10-05", "https://www.resorts.co.jp/resortinn-ishigaki/news_detail?actual_object_id=31763", "宿泊管理システムへの不正アクセスに伴うホテルリゾートイン石垣島のお客様情報の漏えいに関するお詫びとお知らせ")]
}));

add(makeIncident({
  id: "2026-09-28-shueisha-happy-plus-community",
  name: "株式会社集英社",
  industry: ["publishing", "media"],
  business_model: ["b2c", "b2b"],
  service: "HAPPY PLUS COMMUNITY",
  title: "HAPPY PLUS COMMUNITYへの不正アクセスによるブロガー個人情報漏えい",
  types: ["unauthorized_access", "data_breach"],
  occurred_at: "2026-09-09",
  detected_at: "2026-09-09",
  disclosed_at: "2026-09-28",
  affected_users: 2835,
  records: 2835,
  data_exposed: ["name", "email_address", "address", "phone_number", "date_of_birth", "gender", "occupation", "profile_image", "profile", "social_media_account", "marital_status", "children_information"],
  note: "ブロガー2,835名の個人情報漏えいを確認。ほかに案件情報630件、送信メール11,237件、取引先一覧10,780件も閲覧・取得対象として公表。",
  sources: [source("official", "株式会社集英社", "2026-09-28", "https://www.shueisha.co.jp/wp-content/uploads/2026/09/Shueisha20260928-1.pdf", "HAPPY PLUS COMMUNITYへの不正アクセスによる個人情報漏洩のお詫びとお知らせ")]
}));

add(makeIncident({
  id: "2026-09-29-unirita-document-system",
  name: "株式会社ユニリタ",
  industry: ["software", "saas"],
  business_model: ["b2b"],
  service: "社内文書管理システム",
  title: "社内文書管理システムへの不正アクセスによる情報窃取",
  types: ["unauthorized_access", "data_breach"],
  occurred_at: null,
  detected_at: "2026-09-28",
  disclosed_at: "2026-09-29",
  affected_users: null,
  records: null,
  data_exposed: ["confidential_business_information", "customer_related_information"],
  note: "特定の社内文書管理システムへの不正アクセスと情報の窃取を確認。顧客情報等を含む具体的な影響範囲は調査継続中のため件数は未設定。",
  sources: [source("official", "株式会社ユニリタ", "2026-09-29", "https://www.unirita.co.jp/news/2026/media_20260929.html", "情報漏洩に関するお知らせとお詫び")]
}));

if (touched.length || added.length) {
  data.generated_at = now;
  data.incidents.sort((a, b) => {
    const dateCmp = String(b.incident?.disclosed_at ?? "").localeCompare(String(a.incident?.disclosed_at ?? ""));
    return dateCmp || String(b.id).localeCompare(String(a.id));
  });
  await writeFile(path, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

const afterConfirmed = data.incidents.filter((x) => x?.impact?.confirmed_breach === true).length;
console.log(`Confirmed breach audit complete`);
console.log(`TOTAL=${data.incidents.length}`);
console.log(`CONFIRMED_BEFORE=${beforeConfirmed}`);
console.log(`CONFIRMED_AFTER=${afterConfirmed}`);
console.log(`PATCHED=${touched.length}`);
for (const id of touched) console.log(`PATCH ${id}`);
console.log(`ADDED=${added.length}`);
for (const id of added) console.log(`ADD ${id}`);
console.log(`GENERATED_AT=${data.generated_at}`);
