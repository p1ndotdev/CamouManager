import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  request,
  subscribeChanged,
  subscribeNotice,
  subscribeStatus,
} from './api';
import Backups from './Backups';
import { Button } from './components';
import { useI18n } from './i18n';
import Profiles from './Profiles';
import Proxies from './Proxies';
import Settings from './Settings';
import type {
  AppSnapshot,
  AppUpdateStatus,
  BackupState,
  MessageLevel,
  Profile,
  Proxy,
  Status,
  StatusEvent,
  Version,
} from './types';

const appIcon = new URL('../src-tauri/icons/icon.svg', import.meta.url).href;

type Section = 'profiles' | 'proxies' | 'backups' | 'settings';

interface NoticeItem {
  id: number;
  level: MessageLevel;
  message: string;
}

function isSameProfileData(a: Profile, b: Profile): boolean {
  if (
    a.id !== b.id ||
    a.updated_at !== b.updated_at ||
    a.name !== b.name ||
    a.group !== b.group ||
    a.note !== b.note ||
    a.os !== b.os ||
    a.browser_version !== b.browser_version ||
    a.proxy_id !== b.proxy_id ||
    a.proxy_name !== b.proxy_name
  ) {
    return false;
  }
  if ((a.tags?.length || 0) !== (b.tags?.length || 0)) return false;
  for (let i = 0; i < (a.tags?.length || 0); i++) {
    if (a.tags[i] !== b.tags[i]) return false;
  }
  if ((a.extensions?.length || 0) !== (b.extensions?.length || 0)) return false;
  for (let i = 0; i < (a.extensions?.length || 0); i++) {
    if (a.extensions[i] !== b.extensions[i]) return false;
  }
  if ((a.startup_urls?.length || 0) !== (b.startup_urls?.length || 0)) return false;
  for (let i = 0; i < (a.startup_urls?.length || 0); i++) {
    if (a.startup_urls[i] !== b.startup_urls[i]) return false;
  }
  if ((a.bookmarks?.length || 0) !== (b.bookmarks?.length || 0)) return false;
  for (let i = 0; i < (a.bookmarks?.length || 0); i++) {
    if (a.bookmarks[i].title !== b.bookmarks[i].title || a.bookmarks[i].url !== b.bookmarks[i].url) {
      return false;
    }
  }
  return true;
}

function isSameProxyData(a: Proxy, b: Proxy): boolean {
  return (
    a.id === b.id &&
    a.updated_at === b.updated_at &&
    a.name === b.name &&
    a.server === b.server &&
    a.enabled === b.enabled &&
    a.has_password === b.has_password &&
    a.has_credentials === b.has_credentials &&
    a.last_check?.checked_at === b.last_check?.checked_at &&
    a.last_check?.ok === b.last_check?.ok &&
    a.last_check?.ip === b.last_check?.ip &&
    a.last_check?.latency_ms === b.last_check?.latency_ms &&
    a.last_check?.error === b.last_check?.error
  );
}

function isSameVersionData(a: Version, b: Version): boolean {
  return (
    a.id === b.id &&
    a.name === b.name &&
    a.path === b.path &&
    a.installed_at === b.installed_at &&
    a.status === b.status
  );
}

export default function App() {
  const { t } = useI18n();
  const [activeSection, setActiveSection] = useState<Section>('profiles');
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [statuses, setStatuses] = useState<Record<string, Status>>({});
  const [runningCount, setRunningCount] = useState(0);
  const [backupState, setBackupState] = useState<BackupState>({
    state: 'disabled',
    message: '',
    last_at: '',
  });
  const [busyCount, setBusyCount] = useState(0);
  const [appUpdate, setAppUpdate] = useState<AppUpdateStatus | null>(null);
  const [updatingApp, setUpdatingApp] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<NoticeItem | null>(null);

  const statusesRef = useRef<Record<string, Status>>({});
  const noticeTimerRef = useRef<number | null>(null);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const refreshQueuedRef = useRef(false);

  const showMessage = useCallback((message: string, level: MessageLevel = 'info') => {
    if (noticeTimerRef.current !== null) {
      window.clearTimeout(noticeTimerRef.current);
      noticeTimerRef.current = null;
    }
    setNotice({ id: Date.now(), level, message });
    if (level !== 'error') {
      noticeTimerRef.current = window.setTimeout(() => {
        setNotice(null);
        noticeTimerRef.current = null;
      }, 6000);
    }
  }, []);

  const applyStatuses = useCallback((incoming: Record<string, Status>) => {
    const prev = statusesRef.current;
    const prevKeys = Object.keys(prev);
    const nextKeys = Object.keys(incoming);
    let changed = prevKeys.length !== nextKeys.length;
    const merged: Record<string, Status> = {};

    for (const id of nextKeys) {
      const nextSt = incoming[id];
      const oldSt = prev[id];
      if (
        oldSt &&
        oldSt.state === nextSt.state &&
        oldSt.pid === nextSt.pid &&
        oldSt.cpu_percent === nextSt.cpu_percent &&
        oldSt.memory_mb === nextSt.memory_mb &&
        oldSt.error === nextSt.error &&
        oldSt.egress_ip === nextSt.egress_ip
      ) {
        merged[id] = oldSt;
      } else {
        merged[id] = nextSt;
        changed = true;
      }
    }

    if (changed) {
      statusesRef.current = merged;
      setStatuses(merged);
    }
  }, []);

  const applyStatusEvent = useCallback(
    (evt: StatusEvent) => {
      if (evt.statuses) {
        applyStatuses(evt.statuses);
      }
      if (typeof evt.running_count === 'number') {
        setRunningCount((prev) => (prev === evt.running_count ? prev : evt.running_count));
      }
      if (typeof evt.busy === 'number') {
        setBusyCount((prev) => (prev === evt.busy ? prev : evt.busy));
      }
      if (evt.backup) {
        setBackupState((prev) => {
          if (
            prev.state === evt.backup.state &&
            prev.message === evt.backup.message &&
            prev.last_at === evt.backup.last_at
          ) {
            return prev;
          }
          return evt.backup;
        });
      }
      if (evt.app_update) {
        setAppUpdate((prev) =>
          prev &&
          prev.state === evt.app_update?.state &&
          prev.latest_version === evt.app_update?.latest_version &&
          prev.error === evt.app_update?.error
            ? prev
            : evt.app_update || null
        );
      }
    },
    [applyStatuses]
  );

  const refreshSnapshot = useCallback(async (): Promise<void> => {
    if (refreshInFlightRef.current) {
      refreshQueuedRef.current = true;
      return refreshInFlightRef.current;
    }

    const run = (async () => {
      try {
        const next = await request<AppSnapshot>('app.snapshot');
        setLoadError(null);

        // Extract statuses from snapshot profiles
        const snapStatuses: Record<string, Status> = {};
        let running = 0;
        for (const p of next.profiles || []) {
          const st: Status = {
            state: p.state || 'stopped',
            pid: p.pid ?? null,
            cpu_percent: p.cpu_percent ?? 0,
            memory_mb: p.memory_mb ?? 0,
            error: p.error ?? '',
            egress_ip: p.location.ip,
          };
          snapStatuses[p.id] = st;
          if (st.state === 'running') running += 1;
        }
        applyStatuses(snapStatuses);
        setRunningCount(running);

        if (next.backup) {
          setBackupState((prev) =>
            prev.state === next.backup.state &&
            prev.message === next.backup.message &&
            prev.last_at === next.backup.last_at
              ? prev
              : next.backup
          );
        }
        if (next.app_update) {
          setAppUpdate(next.app_update);
        }

        // Reconcile snapshot reusing unchanged object references to prevent render churn
        setSnapshot((prev) => {
          if (!prev) return next;

          const prevProfileById = new Map<string, Profile>();
          for (const p of prev.profiles) prevProfileById.set(p.id, p);
          let profilesSame = prev.profiles.length === next.profiles.length;
          const mergedProfiles = next.profiles.map((np, i) => {
            const old = prevProfileById.get(np.id);
            if (old && isSameProfileData(old, np)) {
              if (prev.profiles[i] !== old) profilesSame = false;
              return old;
            }
            profilesSame = false;
            return np;
          });

          const prevProxyById = new Map<string, Proxy>();
          for (const px of prev.proxies) prevProxyById.set(px.id, px);
          let proxiesSame = prev.proxies.length === next.proxies.length;
          const mergedProxies = next.proxies.map((npx, i) => {
            const old = prevProxyById.get(npx.id);
            if (old && isSameProxyData(old, npx)) {
              if (prev.proxies[i] !== old) proxiesSame = false;
              return old;
            }
            proxiesSame = false;
            return npx;
          });

          const prevVerById = new Map<string, Version>();
          for (const v of prev.versions) prevVerById.set(v.id, v);
          let versionsSame = prev.versions.length === next.versions.length;
          const mergedVersions = next.versions.map((nv, i) => {
            const old = prevVerById.get(nv.id);
            if (old && isSameVersionData(old, nv)) {
              if (prev.versions[i] !== old) versionsSame = false;
              return old;
            }
            versionsSame = false;
            return nv;
          });

          return {
            ...next,
            profiles: profilesSame ? prev.profiles : mergedProfiles,
            proxies: proxiesSame ? prev.proxies : mergedProxies,
            versions: versionsSame ? prev.versions : mergedVersions,
          };
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setLoadError(msg);
        showMessage(`${t('Không thể tải dữ liệu: ', 'Failed to load data: ')}${msg}`, 'error');
      } finally {
        setLoading(false);
        refreshInFlightRef.current = null;
        if (refreshQueuedRef.current) {
          refreshQueuedRef.current = false;
          void refreshSnapshot();
        }
      }
    })();

    refreshInFlightRef.current = run;
    return run;
  }, [applyStatuses, showMessage, t]);

  useEffect(() => {
    let disposed = false;
    const unlisteners: (() => void)[] = [];

    const register = (promise: Promise<() => void>) => {
      promise
        .then((unlisten) => {
          if (disposed) {
            unlisten();
          } else {
            unlisteners.push(unlisten);
          }
        })
        .catch((error) => {
          if (!disposed) showMessage(`${t('Không nhận được cập nhật từ backend: ', 'Could not receive updates from backend: ')}${String(error)}`, 'error');
        });
    };

    register(
      subscribeStatus((data) => {
        if (!disposed) applyStatusEvent(data);
      })
    );

    register(
      subscribeChanged(() => {
        if (!disposed) {
          void refreshSnapshot();
        }
      })
    );

    register(
      subscribeNotice((data) => {
        if (!disposed && data?.message) {
          showMessage(data.message, data.level || 'info');
        }
      })
    );

    void refreshSnapshot();

    return () => {
      disposed = true;
      if (noticeTimerRef.current !== null) {
        window.clearTimeout(noticeTimerRef.current);
      }
      for (const unlisten of unlisteners) {
        try {
          unlisten();
        } catch {
          // Ignore cleanup errors
        }
      }
    };
  }, [applyStatusEvent, refreshSnapshot, showMessage]);

  const effectiveSnapshot = useMemo<AppSnapshot | null>(() => {
    if (!snapshot) return null;
    if (snapshot.backup === backupState && snapshot.app_update === (appUpdate || undefined)) return snapshot;
    return {
      ...snapshot,
      backup: backupState,
      app_update: appUpdate || snapshot.app_update,
    };
  }, [snapshot, backupState, appUpdate]);

  const handleAppUpdate = useCallback(async () => {
    setUpdatingApp(true);
    try {
      const res = await request<AppUpdateStatus>('app.update');
      setAppUpdate(res);
      if (res.state === 'ready') {
        showMessage(
          t(
            `Đã tải và cài đặt CamouManager ${res.latest_version}. Tắt và mở lại ứng dụng để hoàn tất cập nhật.`,
            `Downloaded and installed CamouManager ${res.latest_version}. Close and reopen the app to finish updating.`
          ),
          'info'
        );
      } else {
        showMessage(
          t(
            `CamouManager đã ở phiên bản mới nhất (v${res.current_version}).`,
            `CamouManager is already up to date (v${res.current_version}).`
          ),
          'info'
        );
      }
    } catch (err) {
      showMessage(
        `${t('Lỗi cập nhật ứng dụng: ', 'App update failed: ')}${err instanceof Error ? err.message : String(err)}`,
        'error'
      );
    } finally {
      setUpdatingApp(false);
    }
  }, [showMessage, t]);

  const handleToggleAutoUpdate = useCallback(
    async (checked: boolean) => {
      try {
        await request('settings.save', { data: { auto_update_app: checked } });
        await refreshSnapshot();
        if (checked && appUpdate?.state !== 'ready') {
          void handleAppUpdate();
        }
      } catch (err) {
        showMessage(
          `${t('Lỗi lưu cấu hình tự động cập nhật: ', 'Failed to save auto-update setting: ')}${
            err instanceof Error ? err.message : String(err)
          }`,
          'error'
        );
      }
    },
    [appUpdate?.state, handleAppUpdate, refreshSnapshot, showMessage, t]
  );

  return (
    <div className="cm-app">
      <aside className="cm-sidebar" aria-label={t('Điều hướng chính', 'Main navigation')}>
        <div className="cm-sidebar-brand"><img src={appIcon} width="48" height="48" alt="CamouManager" /></div>
        <button
          type="button"
          className={`cm-nav-btn ${activeSection === 'profiles' ? 'cm-nav-btn-active' : ''}`}
          aria-current={activeSection === 'profiles' ? 'page' : undefined}
          onClick={() => setActiveSection('profiles')}
        >
          {t('Hồ sơ', 'Profiles')}
        </button>
        <button
          type="button"
          className={`cm-nav-btn ${activeSection === 'proxies' ? 'cm-nav-btn-active' : ''}`}
          aria-current={activeSection === 'proxies' ? 'page' : undefined}
          onClick={() => setActiveSection('proxies')}
        >
          {t('Proxy', 'Proxies')}
        </button>
        <button
          type="button"
          className={`cm-nav-btn ${activeSection === 'backups' ? 'cm-nav-btn-active' : ''}`}
          aria-current={activeSection === 'backups' ? 'page' : undefined}
          onClick={() => setActiveSection('backups')}
        >
          {t('Sao lưu', 'Backups')}
        </button>
        <button
          type="button"
          className={`cm-nav-btn ${activeSection === 'settings' ? 'cm-nav-btn-active' : ''}`}
          aria-current={activeSection === 'settings' ? 'page' : undefined}
          onClick={() => setActiveSection('settings')}
        >
          {t('Cài đặt', 'Settings')}
        </button>

        <div className="cm-sidebar-footer">
          <div>v{appUpdate?.current_version || '1.0.6'}</div>
          {appUpdate?.state === 'ready' ? (
            <div style={{ color: 'var(--success)', fontWeight: 600 }}>
              {t(`Chờ mở lại (${appUpdate.latest_version})`, `Restart (${appUpdate.latest_version})`)}
            </div>
          ) : null}
          <Button
            variant={appUpdate?.state === 'ready' ? 'secondary' : 'primary'}
            size="sm"
            loading={updatingApp || appUpdate?.state === 'checking' || appUpdate?.state === 'downloading'}
            disabled={updatingApp || appUpdate?.state === 'checking' || appUpdate?.state === 'downloading'}
            onClick={handleAppUpdate}
            style={{ width: '100%', padding: '4px 6px', fontSize: 11 }}
          >
            {appUpdate?.state === 'ready'
              ? t('Đã cài update', 'Update ready')
              : t('Cập nhật', 'Update')}
          </Button>
          <label
            style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', color: 'var(--text-primary)' }}
            title={t(
              'Tự động tải và cài đặt bản cập nhật ứng dụng từ GitHub, áp dụng khi tắt và mở lại app',
              'Automatically download and install app updates from GitHub, applied on restart'
            )}
          >
            <input
              type="checkbox"
              className="cm-checkbox"
              checked={Boolean(snapshot?.settings?.auto_update_app)}
              onChange={(e) => handleToggleAutoUpdate(e.target.checked)}
            />
            <span>{t('Auto update', 'Auto update')}</span>
          </label>
          <div style={{ marginTop: 2 }}>{t('Đang chạy: ', 'Running: ')}{runningCount}</div>
          {busyCount > 0 ? <div>{t('Tác vụ nền: ', 'Background tasks: ')}{busyCount}</div> : null}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="cm-main">
        {notice ? (
          <div
            className={`cm-notice-bar cm-notice-${notice.level}`}
            role={notice.level === 'error' ? 'alert' : 'status'}
            aria-live="polite"
          >
            <span>{notice.message}</span>
            <Button variant="ghost" size="sm" onClick={() => setNotice(null)}>
              {t('Đóng', 'Close')}
            </Button>
          </div>
        ) : null}

        {!effectiveSnapshot ? (
          <div className="cm-empty-state">
            <div className="cm-empty-card">
              <h2 className="cm-empty-title">
                {loading ? t('Đang khởi tạo CamouManager...', 'Initializing CamouManager...') : t('Không thể tải dữ liệu', 'Failed to load data')}
              </h2>
              <p className="cm-empty-desc">
                {loading
                  ? t('Đang kết nối với dịch vụ quản lý dữ liệu và trình duyệt...', 'Connecting to data management and browser services...')
                  : loadError || t('Đã xảy ra lỗi khi tải trạng thái ban đầu.', 'An error occurred while loading initial state.')}
              </p>
              {!loading ? (
                <div className="cm-empty-actions">
                  <Button variant="primary" onClick={() => refreshSnapshot()}>
                    {t('Tải lại dữ liệu', 'Reload data')}
                  </Button>
                </div>
              ) : null}
            </div>
          </div>
        ) : activeSection === 'profiles' ? (
          <Profiles
            snapshot={effectiveSnapshot}
            statuses={statuses}
            runningCount={runningCount}
            onRefresh={refreshSnapshot}
            onMessage={showMessage}
            onNavigate={setActiveSection}
          />
        ) : activeSection === 'proxies' ? (
          <Proxies
            snapshot={effectiveSnapshot}
            onRefresh={refreshSnapshot}
            onMessage={showMessage}
          />
        ) : activeSection === 'backups' ? (
          <Backups
            snapshot={effectiveSnapshot}
            backupState={backupState}
            onRefresh={refreshSnapshot}
            onMessage={showMessage}
          />
        ) : (
          <Settings
            snapshot={effectiveSnapshot}
            onRefresh={refreshSnapshot}
            onMessage={showMessage}
          />
        )}
      </main>
    </div>
  );
}
