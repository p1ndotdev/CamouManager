var { ExtensionCommon } = ChromeUtils.importESModule('resource://gre/modules/ExtensionCommon.sys.mjs');

this.ipSync = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    let sequence = 0;
    const routingPrefs = {
      ...IP_SYNC_NATIVE.proxyPrefs,
      'media.peerconnection.enabled': true,
      'media.peerconnection.ice.proxy_only': true,
      'media.peerconnection.ice.relay_only': true,
      'media.peerconnection.ice.default_address_only': false,
      'network.proxy.failover_direct': false,
      'network.proxy.allow_bypass': false,
      'network.proxy.socks5_remote_dns': true,
      'media.webrtc.tls_tunnel_for_all_proxy': true,
    };
    // Lock the default branch: user prefs and privacy extensions cannot re-enable direct ICE.
    const defaults = Services.prefs.getDefaultBranch(null);
    for (const [key, value] of Object.entries(routingPrefs)) {
      if (typeof value === 'boolean') defaults.setBoolPref(key, value);
      else if (typeof value === 'number') defaults.setIntPref(key, value);
      else defaults.setStringPref(key, value);
      Services.prefs.lockPref(key);
    }
    const writeState = (ip, error) => {
      for (const [key, value] of Object.entries(routingPrefs)) {
        const actual = typeof value === 'boolean' ? Services.prefs.getBoolPref(key)
          : typeof value === 'number' ? Services.prefs.getIntPref(key) : Services.prefs.getStringPref(key);
        if (!Services.prefs.prefIsLocked(key) || actual !== value) {
          // A broken routing policy is fatal; an unavailable proxy is not.
          Services.startup.quit(Ci.nsIAppStartup.eForceQuit);
          throw new Error(`Proxy routing policy changed: ${key}`);
        }
      }
      return IOUtils.writeJSON(IP_SYNC_NATIVE.statePath, {
        token: IP_SYNC_NATIVE.token, sequence: ++sequence, ip, error,
      }, { tmpPath: IP_SYNC_NATIVE.tmpPath });
    };
    return {
      ipSync: {
        async confirm(ip) {
          await writeState(ip, '');
        },
        async fail(message) {
          await writeState('', message.slice(0, 2048));
        },
      },
    };
  }
};
