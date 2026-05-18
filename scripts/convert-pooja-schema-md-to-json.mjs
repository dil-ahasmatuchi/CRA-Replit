/**
 * One-time helper: Resources/Pooja_SCHEMA_OBJECTS.md → Resources/Pooja_SCHEMA_OBJECTS.json
 * Parses ## / ### sections and GitHub-style markdown tables into structured JSON for migration.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const mdPath = path.join(repoRoot, "Resources", "Pooja_SCHEMA_OBJECTS.md");
const outPath = path.join(repoRoot, "Resources", "Pooja_SCHEMA_OBJECTS.json");

function splitTableRow(line) {
  const t = line.trim();
  if (!t.startsWith("|")) return null;
  const parts = t.split("|");
  // leading empty + cells + trailing empty
  const inner = parts.slice(1, -1).map((c) => c.trim());
  return inner;
}

function isSeparatorTableRow(line) {
  const cells = splitTableRow(line);
  if (!cells || cells.length === 0) return false;
  return cells.every((c) => /^:?-{3,}:?$/.test(c.replace(/\s/g, "")));
}

function isLikelyTableHeaderRow(line) {
  return splitTableRow(line) !== null && line.includes("|") && line.trim().startsWith("|");
}

function parseTable(lines, startIdx) {
  const headerLine = lines[startIdx];
  const headers = splitTableRow(headerLine);
  if (!headers || headers.length === 0) return null;
  const sepLine = lines[startIdx + 1];
  if (!sepLine || !isSeparatorTableRow(sepLine)) return null;

  const rows = [];
  let i = startIdx + 2;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim().startsWith("|")) break;
    if (isSeparatorTableRow(line)) {
      i += 1;
      continue;
    }
    const cells = splitTableRow(line);
    if (!cells) break;
    const row = {};
    for (let c = 0; c < headers.length; c++) {
      const key = headers[c] ?? `col_${c}`;
      row[key] = cells[c] ?? "";
    }
    rows.push(row);
    i += 1;
  }
  return { headers, rows, nextIndex: i };
}

function slugFromHeading(heading) {
  const m = /`([^`]+)`/.exec(heading);
  return m ? m[1] : null;
}

function main() {
  const text = fs.readFileSync(mdPath, "utf8");
  const lines = text.split(/\r?\n/);

  let i = 0;
  const preambleLines = [];
  while (i < lines.length && !lines[i].startsWith("## ")) {
    preambleLines.push(lines[i]);
    i += 1;
  }

  const sections = [];

  while (i < lines.length) {
    const heading = lines[i];
    if (!heading.startsWith("## ")) {
      i += 1;
      continue;
    }
    i += 1;
    const section = {
      heading: heading.trim(),
      slug: slugFromHeading(heading),
      parts: [],
    };
    const parts = section.parts;

    let paragraphBuffer = [];

    const flushParagraph = () => {
      if (paragraphBuffer.length === 0) return;
      const joined = paragraphBuffer.join("\n").trimEnd();
      paragraphBuffer = [];
      if (joined.length > 0) {
        parts.push({ type: "paragraph", markdown: joined });
      }
    };

    while (i < lines.length && !lines[i].startsWith("## ")) {
      const line = lines[i];

      if (line.startsWith("### ")) {
        flushParagraph();
        const subHeading = line.trim();
        i += 1;
        const bodyLines = [];
        while (i < lines.length && !lines[i].startsWith("## ") && !lines[i].startsWith("### ")) {
          bodyLines.push(lines[i]);
          i += 1;
        }
        parts.push({
          type: "subsection",
          heading: subHeading,
          markdown: bodyLines.join("\n").trimEnd(),
        });
        continue;
      }

      if (isLikelyTableHeaderRow(line) && i + 1 < lines.length && isSeparatorTableRow(lines[i + 1])) {
        flushParagraph();
        const table = parseTable(lines, i);
        if (table) {
          parts.push({
            type: "table",
            headers: table.headers,
            rowCount: table.rows.length,
            rows: table.rows,
          });
          i = table.nextIndex;
        } else {
          paragraphBuffer.push(line);
          i += 1;
        }
        continue;
      }

      paragraphBuffer.push(line);
      i += 1;
    }

    flushParagraph();
    sections.push(section);
  }

  const output = {
    sourceFile: "Resources/Pooja_SCHEMA_OBJECTS.md",
    convertedAt: new Date().toISOString(),
    formatVersion: 1,
    description:
      "Structured export of markdown tables and prose blocks for one-time migration into CRA mock catalog types.",
    preambleMarkdown: preambleLines.join("\n").trimEnd(),
    sections,
  };

  fs.writeFileSync(outPath, JSON.stringify(output, null, 2), "utf8");
  const bytes = fs.statSync(outPath).size;
  console.log(`Wrote ${outPath} (${(bytes / 1024 / 1024).toFixed(2)} MiB)`);
  console.log(`Sections: ${sections.length}`);
  for (const s of sections) {
    const tables = s.parts.filter((p) => p.type === "table");
    const rowTotal = tables.reduce((acc, t) => acc + (t.rowCount ?? 0), 0);
    console.log(`  - ${s.slug ?? s.heading.slice(0, 50)}: ${tables.length} table(s), ${rowTotal} data rows`);
  }
}

main();
