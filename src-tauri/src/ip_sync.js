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

async function probeIp(endpoint) {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 8000);
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
  let lastError = null;
  for (const endpoint of IP_SYNC_SETTINGS.endpoints) {
    try {
      return await probeIp(endpoint);
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
