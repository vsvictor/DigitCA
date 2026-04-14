/**
 * OCSP client example for digitca-ocsp — Node.js (ESM, no dependencies)
 *
 * Usage:
 *   node index.mjs --ocsp-base http://localhost:8082 \
 *                  --request-der ./request.der \
 *                  --response-der ./response.der
 *
 * Environment variable overrides:
 *   OCSP_BASE, OCSP_REQUEST_DER, OCSP_RESPONSE_DER
 */
import fs from "node:fs/promises";

function argValue(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

const ocspBase    = argValue("--ocsp-base",    process.env.OCSP_BASE         ?? "http://localhost:8082");
const requestDer  = argValue("--request-der",  process.env.OCSP_REQUEST_DER  ?? "./request.der");
const responseDer = argValue("--response-der", process.env.OCSP_RESPONSE_DER ?? "./response.der");

async function main() {
  // 1) Health check
  console.log(`[nodejs] GET ${ocspBase}/health`);
  const health = await fetch(`${ocspBase}/health`);
  if (!health.ok) throw new Error(`health failed: ${health.status}`);
  console.log(await health.text());

  // 2) Read request DER
  const requestBytes = await fs.readFile(requestDer);

  // 3) POST OCSP request
  console.log(`[nodejs] POST ${ocspBase}/ocsp  (${requestBytes.length} bytes)`);
  const ocsp = await fetch(`${ocspBase}/ocsp`, {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request" },
    body: requestBytes,
  });
  if (!ocsp.ok) throw new Error(`ocsp failed: ${ocsp.status}`);

  // 4) Save DER response
  const responseBytes = Buffer.from(await ocsp.arrayBuffer());
  await fs.writeFile(responseDer, responseBytes);
  console.log(`[nodejs] OCSP response saved: ${responseDer}  (${responseBytes.length} bytes)`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

