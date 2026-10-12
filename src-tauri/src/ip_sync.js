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

let lastIp;
async function refreshProxyIp() {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(IP_SYNC_SETTINGS.endpoint, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error(`Kiểm tra IP trả HTTP ${response.status}`);
    const ip = normalizeProxyIp((await response.json()).ip);
    if (ip !== lastIp) {
      await browser.ipSync.update(ip);
      // Verify native candidates, including cross-process cache updates, before accepting the IP.
      const probe = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:3478' }] });
      let gatherDeadline;
      try {
        const addresses = [];
        const gathered = new Promise(resolve => {
          gatherDeadline = setTimeout(resolve, 3000);
          probe.onicecandidate = event => {
            if (!event.candidate) return resolve();
            const fields = event.candidate.candidate.split(/\s+/);
            if (fields[fields.indexOf('typ') + 1] === 'srflx') addresses.push(fields[4]);
          };
        });
        probe.createDataChannel('ip-sync');
        await probe.setLocalDescription(await probe.createOffer());
        await gathered;
        if (!addresses.length || addresses.some(address => address !== ip)) {
          throw new Error('Camoufox không áp dụng đúng IP WebRTC mới');
        }
      } finally {
        clearTimeout(gatherDeadline);
        probe.close();
      }
      lastIp = ip;
    }
    await browser.ipSync.confirm(ip);
  } catch (error) {
    await browser.ipSync.fail(String(error));
    return;
  } finally {
    clearTimeout(deadline);
  }
  setTimeout(refreshProxyIp, 10000);
}
refreshProxyIp();
