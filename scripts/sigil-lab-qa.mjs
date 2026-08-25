import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";

const url = process.argv[2] ?? "http://127.0.0.1:8080/";
await mkdir("/workspace/screenshots", { recursive: true });
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error") errors.push(m.text());
});

await page.goto(url, { waitUntil: "networkidle" });
await page.getByText("What are you making?").waitFor({ timeout: 10000 });
await page.getByText("Useful for").waitFor({ timeout: 10000 });
await page.getByRole("radio", { name: /Glyph/ }).click();
await page.getByText("Evidence you must prove untouched").waitFor();
await page.getByRole("radio", { name: /Reflection/ }).click();
await page.getByText("Sending a file across a channel").waitFor();
await page.getByRole("radio", { name: /Seal/ }).click();
await page.getByText("Archives you cannot replace").waitFor();
await page.getByRole("button", { name: "Inscribe a Seal" }).click();
await page.getByText("Your mark").waitFor({ timeout: 20000 });
await page.getByText("binding").first().waitFor();
await page.getByRole("button", { name: "Shatter Keystone" }).click();
await page.getByRole("button", { name: "De-scribe" }).click();
await page.getByText("Keystone copy used").waitFor({ timeout: 20000 });
await page.getByRole("button", { name: "Restore pieces" }).click();
await page.getByRole("button", { name: "Burn Keystones" }).click();
await page.getByRole("button", { name: "De-scribe" }).click();
await page.getByText("Ember used").waitFor({ timeout: 20000 });
await page.getByRole("button", { name: "Restore pieces" }).click();
await page.getByRole("button", { name: "Hex" }).click();
await page.getByRole("button", { name: "De-scribe" }).click();
await page.getByText("De-scribed", { exact: true }).waitFor({ timeout: 20000 });
await page.getByRole("button", { name: "Add to constellation" }).click();
await page.screenshot({ path: "/workspace/screenshots/lab-recovered.png", fullPage: true });

await page.getByRole("link", { name: "Sky" }).click();
await page.getByText("Group marks so one file can be in two lists").waitFor();
await page.getByRole("button", { name: "Inscribe constellation" }).click();
await page.getByText("Folder seal", { exact: true }).waitFor({ timeout: 20000 });
await page.getByRole("button", { name: "Erase half" }).click();
await page.getByRole("button", { name: "De-scribe members" }).click();
await page.getByText("intact", { exact: true }).waitFor({ timeout: 20000 });
await page.screenshot({ path: "/workspace/screenshots/graph.png", fullPage: true });

await page.getByRole("link", { name: "Grimoire" }).click();
await page.getByRole("heading", { name: "The grimoire" }).waitFor();
await page.getByText("What Sigil is for").waitFor();
await page.getByText("Fingerprint").first().waitFor();
await page.getByRole("button", { name: "Run battery" }).click();
await page.getByText("constellation: packed").waitFor({ timeout: 40000 });
await page.screenshot({ path: "/workspace/screenshots/protocol-test.png", fullPage: true });

await page.getByRole("link", { name: "Scry" }).click();
await page.getByText("Look at a mark without opening it").waitFor();
await page.screenshot({ path: "/workspace/screenshots/scry.png", fullPage: true });

if (errors.length) {
  console.error("CONSOLE", errors);
  process.exit(1);
}
console.log("LAB+GRAPH+PROTOCOL QA OK");
await browser.close();
