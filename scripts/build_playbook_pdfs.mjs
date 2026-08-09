import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
const OUT_DIR = path.join(ROOT, "output", "pdf");
const TMP_DIR = path.join(ROOT, "tmp", "pdfs");

// One entry per compiled field reference. Add a collection here rather than forking this script.
const PUBLICATIONS = [
  {
    key: "ai-pqc",
    docId: "GN-PUB-AIPQC-001",
    fileStem: "GreyNOC_AI_PQC_Playbooks",
    version: "v2.0.0",
    publicationDate: "2026-07-27",
    documentTitle: "GreyNOC AI, Post-Quantum & E2EE Security Playbooks",
    coverTitleHtml: "AI, Post-Quantum &amp;<br>E2EE Security Playbooks",
    runningTitleHtml: "AI, Post-Quantum &amp; E2EE Security Playbooks",
    subtitleHtml: `Enterprise governance, detection and response, migration operations,
      and authorized bug-bounty methodology.`,
    disciplineLabel: "Evidence-backed, authorized use",
    noticeHtml: `<strong>Authorized testing only.</strong> Bug-bounty sections are bound by
      CONVENTIONS Sections 6-8. Standards and regulatory status must be re-verified against the
      versioned reference baseline before operational or compliance use.`,
    sources: [
      "09-ai-automated-agent-abuse.md",
      "19-ai-security-incident-response.md",
      "20-ai-serving-plane-isolation.md",
      "01-cryptographic-inventory-pqc-readiness.md",
      "02-harvest-now-decrypt-later.md",
      "03-hybrid-tls-kem-downgrade.md",
      "04-e2ee-messaging-protocol-security.md",
      "05-pq-signature-token-integrity.md",
      "06-ai-augmented-detection-guardrails.md",
      "07-bugbounty-pqc-e2ee-methodology.md",
      "08-bugbounty-crypto-implementation-defects.md",
      "09-pq-vpn-ipsec-ssh.md",
      "10-pq-pki-certificate-lifecycle.md",
      "11-pq-code-signing-firmware.md",
      "12-pq-e2ee-realtime-media.md",
      "13-crypto-agility-migration-ops.md",
      "14-quantum-risk-governance.md",
      "15-bugbounty-ai-attack-surface-methodology.md",
      "16-bugbounty-llm-application-defects.md",
      "17-bugbounty-ai-supply-chain-model-artifacts.md",
      "18-bugbounty-agentic-systems-mcp.md",
      "19-bugbounty-model-behavior-safety-boundaries.md",
      "20-bugbounty-inference-infrastructure-isolation.md",
      "21-ai-governance-asset-third-party-risk.md",
      "22-ai-secure-development-tev-v-change-management.md",
      "23-ai-data-governance-privacy-retention.md",
      "24-ai-resilience-continuity-decommissioning.md",
      "25-pq-key-management-data-at-rest.md",
      "26-pq-enterprise-identity-messaging-trust.md",
      "27-pq-capacity-interoperability-vendor-assurance.md",
      "CONVENTIONS.md",
    ],
  },
  {
    key: "transmission",
    docId: "GN-PUB-TXPHY-001",
    fileStem: "GreyNOC_Transmission_Physical_Layer_Playbooks",
    version: "v1.1.0",
    publicationDate: "2026-08-09",
    documentTitle: "GreyNOC Transmission & Physical Layer Security Playbooks",
    coverTitleHtml: "Transmission &amp;<br>Physical Layer Playbooks",
    runningTitleHtml: "Transmission &amp; Physical Layer Security Playbooks",
    subtitleHtml: `Radio-frequency spectrum, nanometer-scale optical media, and post-quantum
      cryptography in silicon - detection, response, and the coverage audit behind the collection.`,
    disciplineLabel: "Baseline-derived, locally calibrated",
    noticeHtml: `<strong>Detection is bounded by what you instrument.</strong> Passive interception
      of RF and optical media is undetectable in principle - the control is cryptographic, not
      telemetric. Every threshold in these playbooks is a deviation from a locally recorded
      baseline; published absolute values are not portable between sites. An empty alert queue for
      an uninstrumented band or span is a coverage gap, not a clean result.`,
    sources: [
      "QAQC-physical-layer-coverage.md",
      "TX-01-rf-spectrum-intrusion.md",
      "TX-02-optical-nm-data-transmission-intrusion.md",
      "TX-03-pq-nanometer-silicon-physical-attack.md",
      "CONVENTIONS.md",
    ],
  },
];

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function normalizeText(value) {
  return value
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2212]/g, "-")
    .replace(/\u2192/g, "->")
    .replace(/\u2190/g, "<-")
    .replace(/\u2248/g, "~")
    .replace(/\u2265/g, ">=")
    .replace(/\u2264/g, "<=");
}

function inlineMarkdown(value, fileStem) {
  let text = escapeHtml(normalizeText(value));
  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, href) => {
    let target = href;
    if (!/^(https?:|mailto:|#)/.test(href)) {
      target = `https://github.com/GreyNOC/Playbooks/blob/main/${href.replaceAll("\\", "/")}`;
    }
    return `<a href="${escapeHtml(target)}">${label}</a>`;
  });
  return text.replaceAll("§", "Section ");
}

function slug(value) {
  return normalizeText(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function isTableSeparator(line) {
  return /^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$/.test(line);
}

function splitTableRow(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function markdownToHtml(markdown, fileName) {
  const fileStem = path.basename(fileName, ".md");
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const output = [];
  let paragraph = [];
  let inCode = false;
  let code = [];
  let listType = null;

  const closeParagraph = () => {
    if (paragraph.length) {
      output.push(`<p>${inlineMarkdown(paragraph.join(" "), fileStem)}</p>`);
      paragraph = [];
    }
  };
  const closeList = () => {
    if (listType) {
      output.push(`</${listType}>`);
      listType = null;
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.startsWith("```")) {
      closeParagraph();
      closeList();
      if (inCode) {
        output.push(`<pre><code>${escapeHtml(normalizeText(code.join("\n")))}</code></pre>`);
        code = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (/^\s*$/.test(line)) {
      closeParagraph();
      closeList();
      continue;
    }
    if (/^---+\s*$/.test(line)) {
      closeParagraph();
      closeList();
      output.push("<hr>");
      continue;
    }
    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    if (heading) {
      closeParagraph();
      closeList();
      if (heading[1].length === 1) continue;
      const level = Math.min(heading[1].length + 1, 5);
      const id = `${fileStem}-${slug(heading[2])}`;
      output.push(`<h${level} id="${id}">${inlineMarkdown(heading[2], fileStem)}</h${level}>`);
      continue;
    }
    if (
      line.includes("|") &&
      i + 1 < lines.length &&
      isTableSeparator(lines[i + 1])
    ) {
      closeParagraph();
      closeList();
      const header = splitTableRow(line);
      i += 1;
      const rows = [];
      while (i + 1 < lines.length && lines[i + 1].includes("|") && lines[i + 1].trim() !== "") {
        rows.push(splitTableRow(lines[i + 1]));
        i += 1;
      }
      output.push("<table><thead><tr>");
      for (const cell of header) output.push(`<th>${inlineMarkdown(cell, fileStem)}</th>`);
      output.push("</tr></thead><tbody>");
      for (const row of rows) {
        output.push("<tr>");
        for (const cell of row) output.push(`<td>${inlineMarkdown(cell, fileStem)}</td>`);
        output.push("</tr>");
      }
      output.push("</tbody></table>");
      continue;
    }
    const bullet = /^\s*[-*]\s+(.+)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.+)$/.exec(line);
    if (bullet || numbered) {
      closeParagraph();
      const wanted = bullet ? "ul" : "ol";
      if (listType !== wanted) {
        closeList();
        output.push(`<${wanted}>`);
        listType = wanted;
      }
      const itemLines = [(bullet || numbered)[1]];
      while (i + 1 < lines.length) {
        const next = lines[i + 1];
        if (
          /^\s*$/.test(next) ||
          /^(#{1,4})\s+/.test(next) ||
          /^\s*[-*]\s+/.test(next) ||
          /^\s*\d+[.)]\s+/.test(next) ||
          /^>\s?/.test(next) ||
          next.startsWith("```") ||
          /^---+\s*$/.test(next) ||
          (next.includes("|") && i + 2 < lines.length && isTableSeparator(lines[i + 2]))
        ) break;
        itemLines.push(next.trim());
        i += 1;
      }
      output.push(`<li>${inlineMarkdown(itemLines.join(" "), fileStem)}</li>`);
      continue;
    }
    const quote = /^>\s?(.*)$/.exec(line);
    if (quote) {
      closeParagraph();
      closeList();
      const quoteLines = [quote[1]];
      while (i + 1 < lines.length) {
        const nextQuote = /^>\s?(.*)$/.exec(lines[i + 1]);
        if (!nextQuote) break;
        quoteLines.push(nextQuote[1]);
        i += 1;
      }
      output.push(`<blockquote>${inlineMarkdown(quoteLines.join(" "), fileStem)}</blockquote>`);
      continue;
    }
    paragraph.push(line.trim());
  }
  closeParagraph();
  closeList();
  if (inCode && code.length) {
    output.push(`<pre><code>${escapeHtml(normalizeText(code.join("\n")))}</code></pre>`);
  }
  return output.join("\n");
}

function titleFromMarkdown(markdown, fallback) {
  const h1 = /^#\s+(.+)$/m.exec(markdown);
  if (h1 && h1[1].trim().toLowerCase() !== "greynoc security playbook") {
    return normalizeText(h1[1]);
  }
  const h2 = /^##\s+(.+)$/m.exec(markdown);
  return normalizeText(h2 ? h2[1] : (h1 ? h1[1] : fallback));
}

function buildHtml(publication) {
  const documents = publication.sources.map((source) => {
    const markdown = fs.readFileSync(path.join(ROOT, source), "utf8");
    return {
      source,
      id: path.basename(source, ".md"),
      title: titleFromMarkdown(markdown, source),
      html: markdownToHtml(markdown, source),
    };
  });

  const toc = documents
    .map((doc, index) => `<li><a href="#doc-${doc.id}"><span>${String(index + 1).padStart(2, "0")}</span>${escapeHtml(doc.title)}</a></li>`)
    .join("\n");

  const sections = documents
    .map((doc) => `
    <section class="playbook" id="doc-${doc.id}" aria-labelledby="title-${doc.id}">
      <div class="source-label">SOURCE: ${escapeHtml(doc.source)}</div>
      <h1 id="title-${doc.id}">${escapeHtml(doc.title)}</h1>
      ${doc.html}
    </section>`)
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(publication.documentTitle)} ${publication.version}</title>
<style>
  :root { --ink:#14212d; --muted:#506578; --accent:#06765f; --line:#cbd7df; --wash:#eef5f4; }
  * { box-sizing:border-box; }
  html { font-family: Arial, "Segoe UI", sans-serif; color:var(--ink); font-size:10.2pt; }
  body { margin:0; line-height:1.42; }
  a { color:#075f8a; text-decoration:none; }
  .cover { min-height:9.1in; display:flex; flex-direction:column; justify-content:center; page-break-after:always; }
  .eyebrow, .source-label { color:var(--accent); font-weight:700; letter-spacing:.09em; font-size:8pt; }
  .cover h1 { font-size:34pt; line-height:1.04; margin:.15in 0 .18in; color:var(--ink); }
  .cover .subtitle { font-size:15pt; color:var(--muted); max-width:6.7in; }
  .meta { margin-top:.55in; display:grid; grid-template-columns:1fr 1fr; gap:.14in .3in; max-width:5.6in; }
  .meta div { border-top:1px solid var(--line); padding-top:.06in; }
  .meta b { display:block; color:var(--accent); font-size:7.5pt; letter-spacing:.08em; }
  .notice { margin-top:.5in; padding:.16in .2in; border-left:4px solid var(--accent); background:var(--wash); max-width:6.7in; }
  .toc { page-break-after:always; }
  .toc h1 { font-size:25pt; }
  .toc ol { list-style:none; padding:0; columns:2; column-gap:.4in; }
  .toc li { break-inside:avoid; margin:0 0 .08in; border-bottom:1px dotted var(--line); }
  .toc li a { display:grid; grid-template-columns:.3in 1fr; color:var(--ink); }
  .toc li span { color:var(--accent); font-weight:700; }
  .playbook { page-break-before:always; }
  .playbook > h1 { font-size:23pt; line-height:1.1; margin:.06in 0 .2in; border-bottom:2px solid var(--accent); padding-bottom:.08in; }
  h2 { font-size:15pt; margin:.22in 0 .07in; color:#084f48; break-after:avoid; }
  h3 { font-size:12.2pt; margin:.18in 0 .05in; color:#234b61; break-after:avoid; }
  h4, h5 { font-size:10.8pt; margin:.15in 0 .04in; break-after:avoid; }
  p { margin:.04in 0 .09in; orphans:3; widows:3; }
  ul, ol { margin:.04in 0 .1in .25in; padding-left:.13in; }
  li { margin:.025in 0; }
  code { font-family:"Cascadia Mono","Consolas",monospace; font-size:.88em; background:#edf1f4; padding:0 .025in; }
  pre { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; font:7.2pt/1.28 "Cascadia Mono","Consolas",monospace; background:#f3f6f8; border:1px solid #d5dfe5; border-left:3px solid var(--accent); padding:.1in; break-inside:auto; }
  pre code { background:transparent; padding:0; }
  table { width:100%; border-collapse:collapse; table-layout:fixed; margin:.08in 0 .14in; font-size:8pt; }
  thead { display:table-header-group; }
  tr { break-inside:avoid; }
  th { background:#dcebe8; color:#123a35; text-align:left; }
  th, td { border:1px solid #b8c8d1; padding:.055in; vertical-align:top; overflow-wrap:anywhere; }
  blockquote { margin:.1in 0; padding:.08in .15in; border-left:4px solid var(--accent); background:var(--wash); }
  hr { border:0; border-top:1px solid var(--line); margin:.16in 0; }
  strong { color:#0c2e3b; }
  @media print {
    a { color:inherit; }
    .cover, .toc, .playbook { break-after:page; }
  }
</style>
</head>
<body>
  <section class="cover" aria-labelledby="publication-title">
    <div class="eyebrow">GREYNOC SECURITY PLAYBOOKS</div>
    <h1 id="publication-title">${publication.coverTitleHtml}</h1>
    <div class="subtitle">${publication.subtitleHtml}</div>
    <div class="meta">
      <div><b>DOCUMENT</b>${publication.docId}</div>
      <div><b>VERSION</b>${publication.version}</div>
      <div><b>PUBLICATION DATE</b>${publication.publicationDate}</div>
      <div><b>CLASSIFICATION</b>PUBLIC // GreyNOC Field Reference</div>
      <div><b>SOURCE</b>GreyNOC/Playbooks</div>
      <div><b>DISCIPLINE</b>${publication.disciplineLabel}</div>
    </div>
    <div class="notice">${publication.noticeHtml}</div>
  </section>
  <nav class="toc" aria-labelledby="toc-title">
    <div class="eyebrow">PUBLICATION MAP</div>
    <h1 id="toc-title">Contents</h1>
    <ol>${toc}</ol>
  </nav>
  <main>${sections}</main>
</body>
</html>`;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  if (args.includes("--list")) return { list: true, selected: [] };
  if (args.length === 0) return { list: false, selected: PUBLICATIONS };
  const selected = [];
  for (const arg of args) {
    const match = PUBLICATIONS.find((pub) => pub.key === arg);
    if (!match) {
      throw new Error(
        `Unknown publication "${arg}". Valid keys: ${PUBLICATIONS.map((p) => p.key).join(", ")}`,
      );
    }
    selected.push(match);
  }
  return { list: false, selected };
}

const { list, selected } = parseArgs(process.argv);

if (list) {
  for (const pub of PUBLICATIONS) {
    console.log(`${pub.key.padEnd(14)} ${pub.version.padEnd(8)} ${pub.sources.length} sources -> ${pub.fileStem}.pdf`);
  }
  process.exit(0);
}

// Validate every source across every selected publication before launching a browser.
for (const pub of selected) {
  for (const source of pub.sources) {
    if (!fs.existsSync(path.join(ROOT, source))) {
      throw new Error(`Missing publication source for "${pub.key}": ${source}`);
    }
  }
}

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

const executableCandidates = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
].filter(Boolean);
const executablePath = executableCandidates.find((candidate) => fs.existsSync(candidate));
if (!executablePath) throw new Error("Chrome or Edge executable not found; set CHROME_PATH");

const browser = await chromium.launch({ executablePath, headless: true });
const built = [];
try {
  for (const pub of selected) {
    const outPdf = path.join(OUT_DIR, `${pub.fileStem}.pdf`);
    const tmpHtml = path.join(TMP_DIR, `${pub.fileStem}.html`);
    const html = buildHtml(pub);
    fs.writeFileSync(tmpHtml, html, "utf8");

    const page = await browser.newPage();
    try {
      await page.setContent(html, { waitUntil: "load" });
      await page.emulateMedia({ media: "print" });
      await page.pdf({
        path: outPdf,
        format: "Letter",
        printBackground: true,
        tagged: true,
        outline: true,
        displayHeaderFooter: true,
        margin: { top: "0.63in", right: "0.62in", bottom: "0.62in", left: "0.62in" },
        headerTemplate: `<div style="font:8px Arial;color:#4c6372;width:100%;padding:0 0.62in;border-bottom:1px solid #d5dfe5">
      <b style="color:#06765f">GreyNOC</b> &nbsp; ${pub.runningTitleHtml}
    </div>`,
        footerTemplate: `<div style="font:8px Arial;color:#4c6372;width:100%;padding:0 0.62in;border-top:1px solid #d5dfe5;display:flex;justify-content:space-between">
      <span>${pub.docId} // PUBLIC</span><span>${pub.version} &nbsp; | &nbsp; <span class="pageNumber"></span>/<span class="totalPages"></span></span>
    </div>`,
      });
    } finally {
      await page.close();
      fs.rmSync(tmpHtml, { force: true });
    }
    built.push({ key: pub.key, outPdf, sourceCount: pub.sources.length });
  }
} finally {
  await browser.close();
  if (fs.existsSync(TMP_DIR) && fs.readdirSync(TMP_DIR).length === 0) fs.rmdirSync(TMP_DIR);
  const tmpParent = path.dirname(TMP_DIR);
  if (fs.existsSync(tmpParent) && fs.readdirSync(tmpParent).length === 0) fs.rmdirSync(tmpParent);
}

for (const entry of built) {
  console.log(`Built ${entry.outPdf} from ${entry.sourceCount} Markdown sources. [${entry.key}]`);
}
