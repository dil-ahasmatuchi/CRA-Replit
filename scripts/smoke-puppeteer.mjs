import puppeteer from "puppeteer";

const url = process.argv[2] ?? "http://localhost:5175/cyber-risk/overview";

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
const page = await browser.newPage();
page.on("console", (msg) => console.log("CONSOLE", msg.type(), msg.text()));
page.on("pageerror", (err) => console.log("PAGEERROR", err.message));

await page.goto(url, { waitUntil: "networkidle0", timeout: 120_000 });
await new Promise((r) => setTimeout(r, 8000));

const root = await page.evaluate(() => {
  const el = document.getElementById("root");
  return el ? { len: el.innerHTML.length, head: el.innerHTML.slice(0, 400) } : null;
});
console.log("ROOT", JSON.stringify(root));

await browser.close();
