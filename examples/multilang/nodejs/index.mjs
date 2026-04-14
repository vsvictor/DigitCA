const apiBase = process.env.API_BASE || "https://digitca.digit.com";
const username = process.env.USERNAME || "admin";
const password = process.env.PASSWORD || "secret";

const auth = Buffer.from(`${username}:${password}`).toString("base64");

async function call(path, withAuth = false) {
  const headers = withAuth ? { Authorization: `Basic ${auth}` } : {};
  const res = await fetch(`${apiBase}${path}`, { headers });
  const text = await res.text();
  console.log(`${path} -> ${res.status}`);
  if (text) console.log(text.slice(0, 200));
}

await call("/health");
await call("/docs");
await call("/api/v1/certificates?include_revoked=true&page=1&per_page=5", true);

