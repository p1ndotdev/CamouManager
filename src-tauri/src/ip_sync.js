function normalizeProxyIp(value) {
  if (typeof value !== 'string') throw new Error('Phản hồi IP không phải chuỗi');
  const ip = value.trim();
  if (ip.includes(':')) {
    const host = new URL(`http://[${ip}]/`).hostname;
    return host.slice(1, -1);
  }
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || new URL(`http://${ip}/`).hostname !== ip) {
    throw new Error('Phản hồi IP không hợp lệ');
  }
  return ip;
}

const PROBE_TOTAL_MS = 12000;
const PROBE_PER_ENDPOINT_MS = 4000;

async function probeIp(endpoint, budgetMs) {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), Math.min(PROBE_PER_ENDPOINT_MS, budgetMs));
  try {
    const response = await fetch(endpoint, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error(`Kiểm tra IP trả HTTP ${response.status}`);
    const text = await response.text();
    let raw = text;
    try {
      const data = JSON.parse(text);
      if (data && typeof data.ip === 'string') raw = data.ip;
    } catch (error) {
      // Plain-text endpoints (icanhazip) return the address directly.
    }
    return normalizeProxyIp(raw);
  } finally {
    clearTimeout(deadline);
  }
}

// Endpoints are ordered dual-stack, IPv4-only, IPv6-only: a tunnel with one family still reports its IP.
async function resolveEgressIp() {
  const startedAt = Date.now();
  let lastError = null;
  for (const endpoint of IP_SYNC_SETTINGS.endpoints) {
    const budget = PROBE_TOTAL_MS - (Date.now() - startedAt);
    if (budget <= 0) break;
    try {
      return await probeIp(endpoint, budget);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error('Không có endpoint IP nào để kiểm tra');
}

async function refreshProxyIp() {
  try {
    const ip = await resolveEgressIp();
    await browser.ipSync.confirm(ip);
  } catch (error) {
    await browser.ipSync.fail(String(error));
  } finally {
    setTimeout(refreshProxyIp, 10000);
  }
}
refreshProxyIp();
