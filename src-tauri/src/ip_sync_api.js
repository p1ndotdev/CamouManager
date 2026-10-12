var { ExtensionCommon } = ChromeUtils.importESModule('resource://gre/modules/ExtensionCommon.sys.mjs');

this.ipSync = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    let sequence = 0;
    const prefs = Services.prefs.getDefaultBranch(null);
    const writeState = (ip, error) => IOUtils.writeJSON(IP_SYNC_NATIVE.statePath, {
      token: IP_SYNC_NATIVE.token, sequence: ++sequence, ip, error,
    }, { tmpPath: IP_SYNC_NATIVE.tmpPath });
    return {
      ipSync: {
        async update(ip) {
          const ipv6 = ip.includes(':');
          prefs.setStringPref('roverfox.s.webrtc_ipv4_0', ipv6 ? '' : ip);
          prefs.setStringPref('roverfox.s.webrtc_ipv6_0', ipv6 ? ip : '');
          prefs.setStringPref('roverfox.s.webrtc_v4_d_0', '1');
          prefs.setStringPref('roverfox.s.webrtc_v6_d_0', '1');
        },
        async confirm(ip) {
          await writeState(ip, '');
        },
        async fail(message) {
          try {
            await writeState('', message.slice(0, 2048));
          } finally {
            // Native quit flushes the profile; do not leave an unverified IP active.
            Services.startup.quit(Ci.nsIAppStartup.eForceQuit);
          }
        },
      },
    };
  }
};
