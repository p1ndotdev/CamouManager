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

async function refreshProxyIp() {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(IP_SYNC_SETTINGS.endpoint, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error(`Kiểm tra IP trả HTTP ${response.status}`);
    const ip = normalizeProxyIp((await response.json()).ip);
    await browser.ipSync.confirm(ip);
  } catch (error) {
    await browser.ipSync.fail(String(error));
  } finally {
    clearTimeout(deadline);
    setTimeout(refreshProxyIp, 10000);
  }
}
refreshProxyIp();
