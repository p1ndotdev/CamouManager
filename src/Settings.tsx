import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import type { PageProps, Version, LogRow, InstallationStatus, InstallationAction, StatusEvent } from './types';
import { request, savePath, subscribeStatus } from './api';
import {
  Button,
  Field,
  ConfirmDialog,
  VirtualTable,
  Column,
  formatDate,
  formatBytes,
} from './components';
import { useI18n, type Language } from './i18n';

type TabKey = 'versions' | 'limits' | 'diagnostics';

export default function Settings({ snapshot, onRefresh, onMessage }: PageProps) {
  const { language, setLanguage, t } = useI18n();
  const [activeTab, setActiveTab] = useState<TabKey>('versions');

  // Tab 1: Versions & Fingerprint state
  const [availableVersions, setAvailableVersions] = useState<Version[]>([]);
  const [selectedAvailableId, setSelectedAvailableId] = useState<string | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [installingVersionId, setInstallingVersionId] = useState<string | null>(null);
  const [deleteVersion, setDeleteVersion] = useState<Version | null>(null);
  const [deletingVersion, setDeletingVersion] = useState(false);
  const [installation, setInstallation] = useState<InstallationStatus | null>(null);
  const [controlPending, setControlPending] = useState<InstallationAction | null>(null);
  const lastStatusTimestampRef = useRef<number>(0);
  const [updatingFingerprint, setUpdatingFingerprint] = useState(false);
  // Tab 2: Runtime Limits & Defaults state
  const [maxRunning, setMaxRunning] = useState<number>(snapshot.settings?.max_running ?? 4);
  const [autoCheckUpdates, setAutoCheckUpdates] = useState<boolean>(
    snapshot.settings?.auto_check_updates ?? true
  );
  const [updateCheckHours, setUpdateCheckHours] = useState<number>(
    snapshot.settings?.update_check_hours ?? 24
  );
  const [autoDownloadUpdates, setAutoDownloadUpdates] = useState<boolean>(
    snapshot.settings?.auto_download_updates ?? false
  );
  const [defaultProxyId, setDefaultProxyId] = useState<string>(
    snapshot.settings?.default_proxy_id ?? ''
  );
  const [autoAssignProxy, setAutoAssignProxy] = useState<boolean>(
    snapshot.settings?.auto_assign_proxy ?? false
  );
  const [defaultStartupUrl, setDefaultStartupUrl] = useState<string>(
    snapshot.settings?.default_startup_url || 'https://duckduckgo.com'
  );
  const [defaultSearchEngine, setDefaultSearchEngine] = useState<string>(
    snapshot.settings?.default_search_engine || 'DuckDuckGo'
  );
  const [savingSettings, setSavingSettings] = useState(false);

  // Sync settings when snapshot updates
  useEffect(() => {
    if (snapshot.settings) {
      if (snapshot.settings.max_running !== undefined) setMaxRunning(snapshot.settings.max_running);
      if (snapshot.settings.auto_check_updates !== undefined)
        setAutoCheckUpdates(snapshot.settings.auto_check_updates);
      if (snapshot.settings.update_check_hours !== undefined)
        setUpdateCheckHours(snapshot.settings.update_check_hours);
      if (snapshot.settings.auto_download_updates !== undefined)
        setAutoDownloadUpdates(snapshot.settings.auto_download_updates);
      if (snapshot.settings.default_proxy_id !== undefined)
        setDefaultProxyId(snapshot.settings.default_proxy_id);
      if (snapshot.settings.auto_assign_proxy !== undefined)
        setAutoAssignProxy(snapshot.settings.auto_assign_proxy);
      if (snapshot.settings.default_startup_url !== undefined)
        setDefaultStartupUrl(snapshot.settings.default_startup_url || 'https://duckduckgo.com');
      if (snapshot.settings.default_search_engine !== undefined)
        setDefaultSearchEngine(snapshot.settings.default_search_engine || 'DuckDuckGo');
    }
  }, [snapshot.settings]);

  // Tab 3: Diagnostics & Logs state
  const [logs, setLogs] = useState<LogRow[]>([]);
  const [logFilter, setLogFilter] = useState('');
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [exportingLogs, setExportingLogs] = useState(false);
  const [stopAllOpen, setStopAllOpen] = useState(false);
  const [stoppingAll, setStoppingAll] = useState(false);

  // Fetch logs
  const fetchLogs = useCallback(async () => {
    setLoadingLogs(true);
    try {
      const res = await request<LogRow[]>('logs.list');
      setLogs(res || []);
    } catch (err: unknown) {
      onMessage(`${t('Lỗi tải nhật ký: ', 'Failed to load logs: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setLoadingLogs(false);
    }
  }, [onMessage, t]);

  useEffect(() => {
    if (activeTab === 'diagnostics') {
      fetchLogs();
    }
  }, [activeTab, fetchLogs]);

  // Subscribe to live status and fetch on mount
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    const mountTime = Date.now();

    const applyInstallation = (inst?: InstallationStatus | null, timestamp?: number) => {
      if (!inst) return;
      if (timestamp !== undefined && timestamp < lastStatusTimestampRef.current) {
        return;
      }
      if (timestamp !== undefined) {
        lastStatusTimestampRef.current = timestamp;
      }

      setInstallation(inst);
    };

    subscribeStatus((data) => {
      if (!disposed && data?.installation) {
        applyInstallation(data.installation, Date.now());
      }
    })
      .then((fn) => {
        if (disposed) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch(() => {});

    request<StatusEvent>('app.status')
      .then((res) => {
        if (!disposed && res?.installation) {
          applyInstallation(res.installation, mountTime);
        }
      })
      .catch(() => {});

    return () => {
      disposed = true;
      if (unlisten) unlisten();
    };
  }, []);

  const isBackendActive =
    installation !== null &&
    (installation.state === 'downloading' ||
      installation.state === 'paused' ||
      installation.state === 'verifying' ||
      installation.state === 'extracting' ||
      installation.state === 'installing');

  const canPause = isBackendActive && installation?.state === 'downloading';
  const canResume = isBackendActive && installation?.state === 'paused';
  const canCancel =
    isBackendActive &&
    (installation?.state === 'downloading' ||
      installation?.state === 'paused' ||
      installation?.state === 'verifying' ||
      installation?.state === 'extracting');
  const installationPercent = installation?.state === 'completed' ? 100
    : installation?.total_bytes ? Math.min(100, Math.round(installation.downloaded_bytes / installation.total_bytes * 100)) : undefined;
  const installationLabels: Record<string, string> = {
    idle: '',
    downloading: t('Đang tải xuống', 'Downloading'),
    paused: t('Đã tạm dừng', 'Paused'),
    verifying: t('Đang kiểm tra SHA-256', 'Verifying SHA-256'),
    extracting: t('Đang giải nén', 'Extracting'),
    installing: t('Đang hoàn tất cài đặt', 'Finalizing installation'),
    completed: t('Cài đặt hoàn tất', 'Installation complete'),
    cancelled: t('Đã hủy', 'Cancelled'),
    error: t('Lỗi cài đặt', 'Installation error'),
  };

  const handleControl = async (action: InstallationAction) => {
    const targetId = installation?.version_id || installingVersionId || selectedAvailableId;
    if (!targetId) return;
    setControlPending(action);
    try {
      const updated = await request<InstallationStatus>('versions.control', {
        id: targetId,
        action,
      });
      if (updated) {
        lastStatusTimestampRef.current = Date.now();
        setInstallation(updated);
      }
    } catch (err: unknown) {
      onMessage(`${t('Lỗi thực hiện lệnh: ', 'Failed to execute command: ')}${action}: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setControlPending(null);
    }
  };

  // Handle checking updates from GitHub
  const handleCheckUpdates = async () => {
    setCheckingUpdates(true);
    try {
      // Check updates and get available versions
      const releases = await request<Version[]>('versions.available');
      setAvailableVersions(releases || []);
      if (!releases || releases.length === 0) {
        onMessage(t('Không tìm thấy phiên bản mới hoặc kết nối mạng bị gián đoạn.', 'No new versions found or network connection interrupted.'), 'info');
      } else {
        onMessage(t(`Đã kiểm tra xong. Tìm thấy ${releases.length} bản phát hành khả dụng từ GitHub.`, `Check completed. Found ${releases.length} available releases on GitHub.`), 'info');
      }
    } catch (err: unknown) {
      onMessage(`${t('Lỗi kiểm tra bản cập nhật: ', 'Failed to check for updates: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setCheckingUpdates(false);
    }
  };

  // Handle installing a selected version
  const handleInstallVersion = async () => {
    const selectedRelease = availableVersions.find((v) => (v.id || v.name) === selectedAvailableId);
    if (!selectedRelease) {
      onMessage(t('Vui lòng chọn một phiên bản từ bảng khả dụng để cài đặt.', 'Please select a version from the available list to install.'), 'warning');
      return;
    }

    const relId = selectedRelease.id || selectedRelease.name;
    setInstallingVersionId(relId);
    lastStatusTimestampRef.current = Date.now();
    setInstallation({
      version_id: relId,
      name: selectedRelease.name || relId,
      state: 'downloading',
      downloaded_bytes: 0,
      total_bytes: typeof selectedRelease.size === 'number' ? selectedRelease.size : null,
      error: '',
    });

    try {
      onMessage(t(`Đang tải và cài đặt phiên bản ${selectedRelease.name || relId}... Quá trình có thể mất ít phút.`, `Downloading and installing version ${selectedRelease.name || relId}... This may take a few minutes.`), 'info');
      const installed = await request<Version | null>('versions.install', { id: relId });
      if (installed) {
        lastStatusTimestampRef.current = Date.now();
        setInstallation((prev) =>
          prev && prev.version_id === relId
            ? { ...prev, state: 'completed' }
            : {
                version_id: relId,
                name: installed.name || relId,
                state: 'completed',
                downloaded_bytes: prev?.downloaded_bytes || 0,
                total_bytes: prev?.total_bytes ?? null,
                error: '',
              }
        );
        await onRefresh();
        onMessage(t(`Đã cài đặt thành công Camoufox phiên bản: ${installed.name || installed.id}`, `Successfully installed Camoufox version: ${installed.name || installed.id}`), 'info');
      } else {
        lastStatusTimestampRef.current = Date.now();
        setInstallation((prev) =>
          prev && prev.version_id === relId ? { ...prev, state: 'cancelled' } : prev
        );
        onMessage(t(`Quá trình cài đặt phiên bản ${selectedRelease.name || relId} đã bị hủy.`, `Installation of version ${selectedRelease.name || relId} was cancelled.`), 'info');
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      lastStatusTimestampRef.current = Date.now();
      setInstallation((prev) =>
        prev && prev.version_id === relId ? { ...prev, state: 'error', error: errMsg } : prev
      );
      onMessage(`${t('Lỗi cài đặt phiên bản: ', 'Failed to install version: ')}${errMsg}`, 'error');
    } finally {
      setInstallingVersionId(null);
    }
  };

  // Handle fingerprint data update
  const handleUpdateFingerprintData = async () => {
    setUpdatingFingerprint(true);
    try {
      const meta = await request<{ updated_at: string; files: { count?: number }[] }>(
        'fingerprint_data.update'
      );
      await onRefresh();
      const total = (meta?.files || []).reduce((acc, f) => acc + (f.count || 0), 0);
      onMessage(t(`Đã cập nhật thành công ${total} bộ dữ liệu fingerprint mẫu từ kho chính thức.`, `Successfully updated ${total} fingerprint sample presets from official repository.`), 'info');
    } catch (err: unknown) {
      onMessage(`${t('Lỗi cập nhật dữ liệu fingerprint: ', 'Failed to update fingerprint data: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setUpdatingFingerprint(false);
    }
  };

  // Handle saving runtime & proxy settings
  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    try {
      await request('settings.save', {
        data: {
          max_running: maxRunning,
          auto_check_updates: autoCheckUpdates,
          update_check_hours: updateCheckHours,
          auto_download_updates: autoDownloadUpdates,
          default_proxy_id: defaultProxyId,
          auto_assign_proxy: autoAssignProxy,
          default_startup_url: defaultStartupUrl.trim(),
          default_search_engine: defaultSearchEngine.trim(),
        },
      });
      await onRefresh();
      onMessage(t('Đã lưu cấu hình chung thành công.', 'General settings saved successfully.'), 'info');
    } catch (err: unknown) {
      onMessage(`${t('Lỗi lưu cấu hình: ', 'Failed to save settings: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setSavingSettings(false);
    }
  };

  // Handle exporting diagnostic logs
  const handleExportLogs = async () => {
    try {
      const path = await savePath({
        defaultPath: 'camoumanager_logs.txt',
        filters: [
          { name: t('Nhật ký văn bản (*.txt)', 'Text Logs (*.txt)'), extensions: ['txt'] },
          { name: t('Tất cả tệp (*)', 'All Files (*)'), extensions: ['*'] },
        ],
      });
      if (!path) return;

      setExportingLogs(true);
      await request('logs.export', { path });
      onMessage(t(`Đã xuất file nhật ký thành công tại: ${path}`, `Logs exported successfully to: ${path}`), 'info');
    } catch (err: unknown) {
      onMessage(`${t('Lỗi xuất nhật ký: ', 'Failed to export logs: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setExportingLogs(false);
    }
  };

  // Handle emergency stop all profiles
  const handleEmergencyStopAll = async () => {
    setStoppingAll(true);
    try {
      await request('profile.stop_all');
      setStopAllOpen(false);
      await onRefresh();
      onMessage(t('Đã gửi lệnh dừng khẩn cấp tới toàn bộ profile đang chạy.', 'Sent emergency stop command to all running profiles.'), 'warning');
    } catch (err: unknown) {
      onMessage(`${t('Lỗi dừng khẩn cấp: ', 'Failed to emergency stop: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setStoppingAll(false);
    }
  };

  // Filtered log rows
  const filteredLogs = useMemo(() => {
    const q = logFilter.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter(
      (l) =>
        l.message.toLowerCase().includes(q) ||
        (l.profile_id && l.profile_id.toLowerCase().includes(q)) ||
        l.level.toLowerCase().includes(q)
    );
  }, [logs, logFilter]);

  // Fingerprint presets summary
  const totalPresets = useMemo(() => {
    const files = snapshot.fingerprint_data?.files || [];
    return files.reduce((acc, f) => acc + (f.count || 0), 0);
  }, [snapshot.fingerprint_data]);

  const handleDeleteVersion = async () => {
    if (!deleteVersion) return;
    setDeletingVersion(true);
    try {
      await request('versions.delete', { id: deleteVersion.id });
      setDeleteVersion(null);
      await onRefresh();
      onMessage(t(`Đã xóa Camoufox ${deleteVersion.name || deleteVersion.id}.`, `Deleted Camoufox ${deleteVersion.name || deleteVersion.id}.`), 'info');
    } catch (err) {
      onMessage(`${t('Không thể xóa phiên bản: ', 'Could not delete version: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setDeletingVersion(false);
    }
  };

  // Installed versions columns
  const installedColumns: Column<Version>[] = useMemo(
    () => [
      {
        key: 'id',
        header: t('ID / Release Tag', 'ID / Release Tag'),
        width: 140,
        render: (v) => <span style={{ fontWeight: 600 }}>{v.id || v.name}</span>,
      },
      {
        key: 'name',
        header: t('Tên phiên bản', 'Version Name'),
        flex: 1.5,
        render: (v) => <span>{v.name || v.id}</span>,
      },
      {
        key: 'path',
        header: t('Đường dẫn thực thi', 'Executable Path'),
        flex: 2,
        render: (v) => (
          <span style={{ fontFamily: 'Consolas, monospace', fontSize: '12px' }} title={v.path}>
            {v.path || '-'}
          </span>
        ),
      },
      {
        key: 'installed_at',
        header: t('Ngày cài đặt', 'Installed Date'),
        width: 150,
        render: (v) => <span style={{ color: 'var(--text-secondary)' }}>{formatDate(v.installed_at)}</span>,
      },
      {
        key: 'actions', header: t('Thao tác', 'Actions'), width: 110,
        render: (v) => {
          const users = snapshot.profiles.filter(p => p.browser_version === v.id);
          return <Button variant="danger" size="sm"
            disabled={deletingVersion || isBackendActive || users.length > 0}
            title={users.length ? t(`Hãy đổi phiên bản của hồ sơ trước: ${users.map(p => p.name).join(', ')}`, `Change profile version first: ${users.map(p => p.name).join(', ')}`) : t('Xóa phiên bản khỏi máy', 'Delete version from disk')}
            aria-label={t(`Xóa phiên bản ${v.id}`, `Delete version ${v.id}`)} onClick={() => setDeleteVersion(v)}>
            {t('Xóa', 'Delete')}
          </Button>;
        },
      },
    ],
    [snapshot.profiles, deletingVersion, isBackendActive, t]
  );

  // Available versions columns
  const availableColumns: Column<Version>[] = useMemo(
    () => [
      {
        key: 'select',
        header: t('Chọn', 'Select'),
        width: 60,
        align: 'center',
        render: (v, _index, selected) => {
          const verId = v.id || v.name;
          return (
            <input
              type="checkbox"
              className="cm-checkbox"
              checked={Boolean(selected)}
              onChange={() => setSelectedAvailableId((prev) => (prev === verId ? null : verId))}
              onClick={(e) => e.stopPropagation()}
              aria-label={t(`Chọn phiên bản ${verId}`, `Select version ${verId}`)}
              style={{ cursor: 'pointer', width: 16, height: 16 }}
            />
          );
        },
      },
      {
        key: 'id',
        header: t('Phiên bản', 'Version'),
        flex: 2,
        render: (v) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
            <strong style={{ fontFamily: 'Consolas, monospace', fontSize: '13px' }}>
              {v.id || v.name}
            </strong>
            {v.prerelease ? (
              <span
                className="cm-pill-counter"
                style={{ fontSize: 10, background: 'rgba(237, 118, 58, 0.2)', color: '#ed763a' }}
              >
                {t('Thử nghiệm', 'Pre-release')}
              </span>
            ) : null}
          </div>
        ),
      },
      {
        key: 'name',
        header: t('Tên bản phát hành', 'Release Name'),
        flex: 1.5,
        render: (v) => <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>{v.name}</span>,
      },
      {
        key: 'size',
        header: t('Kích thước', 'Size'),
        width: 100,
        align: 'right',
        render: (v) => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{v.size ? formatBytes(v.size) : '-'}</span>,
      },
    ],
    [t]
  );

  // Logs table columns
  const logColumns: Column<LogRow>[] = useMemo(
    () => [
      {
        key: 'time',
        header: t('Thời gian', 'Time'),
        width: 150,
        render: (l) => <span style={{ color: 'var(--text-secondary)' }}>{formatDate(l.time)}</span>,
      },
      {
        key: 'level',
        header: t('Cấp độ', 'Level'),
        width: 90,
        render: (l) => {
          const lvl = l.level.toUpperCase();
          if (lvl === 'ERROR') {
            return <span style={{ color: 'var(--danger)', fontWeight: 700 }}>ERROR</span>;
          }
          if (lvl === 'WARNING' || lvl === 'WARN') {
            return <span style={{ color: 'var(--warning)', fontWeight: 700 }}>WARN</span>;
          }
          return <span style={{ color: 'var(--text-secondary)' }}>INFO</span>;
        },
      },
      {
        key: 'profile_id',
        header: t('ID Profile', 'Profile ID'),
        width: 100,
        render: (l) => (
          <span style={{ fontFamily: 'Consolas, monospace', fontSize: '11px' }}>
            {l.profile_id ? l.profile_id.slice(0, 8) : '-'}
          </span>
        ),
      },
      {
        key: 'message',
        header: t('Nội dung thông điệp', 'Message Content'),
        flex: 3,
        render: (l) => (
          <span style={{ fontFamily: 'Consolas, monospace', fontSize: '12px', whiteSpace: 'pre-wrap' }}>
            {l.message}
          </span>
        ),
      },
    ],
    [t]
  );

  return (
    <div className="cm-page">
      {/* Top Bar */}
      <div className="cm-topbar">
        <div className="cm-topbar-left">
          <h1 className="cm-topbar-title">{t('Cài đặt hệ thống & Chẩn đoán', 'System Settings & Diagnostics')}</h1>
        </div>
      </div>

      {/* Language Preference Card */}
      <div style={{ padding: '16px 20px 0 20px', backgroundColor: 'var(--bg-main)' }}>
        <div className="cm-card" style={{ marginBottom: 0, padding: '12px 16px' }}>
          <Field
            label={t('Ngôn ngữ giao diện', 'Interface language')}
            hint={t('Lựa chọn ngôn ngữ được ghi nhớ trên thiết bị này.', 'Language preference is remembered on this device.')}
          >
            <select
              className="cm-select"
              style={{ minWidth: '180px' }}
              value={language}
              aria-label={t('Ngôn ngữ giao diện', 'Interface language')}
              onChange={(e) => {
                const val = e.target.value;
                if (val === 'vi' || val === 'en') {
                  setLanguage(val);
                }
              }}
            >
              <option value="vi">Tiếng Việt</option>
              <option value="en">English</option>
            </select>
          </Field>
        </div>
      </div>

      {/* Tabs Bar */}
      <div style={{ padding: '12px 20px 0 20px', borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-main)' }}>
        <div className="cm-tabs" style={{ marginBottom: 0 }}>
          <button
            type="button"
            className={`cm-tab ${activeTab === 'versions' ? 'cm-tab-active' : ''}`}
            onClick={() => setActiveTab('versions')}
          >
            {t('Phiên bản & Dữ liệu Fingerprint', 'Versions & Fingerprint Data')}
          </button>
          <button
            type="button"
            className={`cm-tab ${activeTab === 'limits' ? 'cm-tab-active' : ''}`}
            onClick={() => setActiveTab('limits')}
          >
            {t('Giới hạn & Mặc định', 'Limits & Defaults')}
          </button>
          <button
            type="button"
            className={`cm-tab ${activeTab === 'diagnostics' ? 'cm-tab-active' : ''}`}
            onClick={() => setActiveTab('diagnostics')}
          >
            {t('Chẩn đoán & Nhật ký', 'Diagnostics & Logs')}
          </button>
        </div>
      </div>

      {/* Main Tab Content */}
      <div className="cm-content">
        {/* =================================================================== */}
        {/* TAB 1: VERSIONS & FINGERPRINT DATASETS */}
        {/* =================================================================== */}
        {activeTab === 'versions' && (
          <div className="cm-content-padded" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Installed Versions */}
            <div className="cm-card">
              <h2 className="cm-card-title">{t('Phiên bản Camoufox đã cài đặt trên máy', 'Installed Camoufox Versions')}</h2>
              {(snapshot.versions || []).length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', padding: '12px 0' }}>
                  {t(
                    'Chưa có phiên bản Camoufox nào được cài đặt. Vui lòng tải phiên bản từ danh sách GitHub bên dưới.',
                    'No Camoufox version installed. Please download a version from the GitHub releases below.'
                  )}
                </div>
              ) : (
                <div style={{ height: '180px' }}>
                  <VirtualTable<Version>
                    data={snapshot.versions || []}
                    columns={installedColumns}
                    rowHeight={40}
                    rowKey="id"
                  />
                </div>
              )}
            </div>

            {/* Active / Ongoing Installation Card */}
            {installation && installation.state !== 'idle' && (
              <div className="cm-card" role="region" aria-label={t('Tiến trình cài đặt Camoufox', 'Camoufox installation progress')}>
                <h2 className="cm-card-title">{t('Tiến trình cài đặt: ', 'Installation progress: ')}{installation.name || installation.version_id}</h2>
                <div role="status" style={{ marginBottom: '8px' }}>
                  {installationLabels[installation.state] || ''}
                  {installationPercent !== undefined && ` · ${installationPercent}% ${t('tải xuống', 'downloaded')}`}
                </div>
                <progress
                  aria-label={t('Tiến độ tải Camoufox', 'Camoufox download progress')}
                  max={100}
                  value={installation.state === 'downloading' || installation.state === 'paused' || installation.state === 'completed'
                    || installation.state === 'cancelled' || installation.state === 'error' ? installationPercent : undefined}
                  style={{ width: '100%', height: '10px', accentColor: 'var(--accent)', marginBottom: '8px' }}
                />
                <div style={{ color: 'var(--text-secondary)', marginBottom: '12px' }}>
                  {formatBytes(installation.downloaded_bytes)}
                  {installation.total_bytes ? ` / ${formatBytes(installation.total_bytes)}` : ` · ${t('Dung lượng chưa xác định', 'Size unknown')}`}
                  {installation.error && <div style={{ color: 'var(--danger)' }}>{installation.error}</div>}
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <Button variant="secondary" size="sm" disabled={!canPause || controlPending !== null}
                    loading={controlPending === 'pause'} onClick={() => handleControl('pause')} aria-label={t('Tạm dừng tải', 'Pause download')}>
                    {t('Tạm dừng', 'Pause')}
                  </Button>
                  <Button variant="secondary" size="sm" disabled={!canResume || controlPending !== null}
                    loading={controlPending === 'resume'} onClick={() => handleControl('resume')} aria-label={t('Tiếp tục tải', 'Resume download')}>
                    {t('Tiếp tục', 'Resume')}
                  </Button>
                  <Button variant="danger" size="sm" disabled={!canCancel || controlPending !== null}
                    loading={controlPending === 'cancel'} onClick={() => handleControl('cancel')} aria-label={t('Hủy tải', 'Cancel download')}>
                    {t('Hủy', 'Cancel')}
                  </Button>
                </div>
              </div>
            )}

            {/* Available Releases on GitHub */}
            <div className="cm-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <h2 className="cm-card-title" style={{ margin: 0 }}>
                  {t('Các bản phát hành khả dụng từ GitHub (Chính thức)', 'Available Releases on GitHub (Official)')}
                </h2>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <Button
                    variant="secondary"
                    loading={checkingUpdates}
                    disabled={checkingUpdates}
                    onClick={handleCheckUpdates}
                  >
                    {checkingUpdates ? t('Đang kiểm tra...', 'Checking...') : t('Kiểm tra bản cập nhật', 'Check for updates')}
                  </Button>
                  <Button
                    variant="primary"
                    loading={installingVersionId !== null && !isBackendActive}
                    disabled={isBackendActive || installingVersionId !== null || !selectedAvailableId}
                    onClick={handleInstallVersion}
                  >
                    {isBackendActive || installingVersionId !== null
                      ? t('Đang tải & cài đặt...', 'Downloading & installing...')
                      : t('Tải & Cài đặt phiên bản', 'Download & Install version')}
                  </Button>
                </div>
              </div>

              {availableVersions.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', padding: '16px 0', textAlign: 'center' }}>
                  {t(
                    'Bấm “Kiểm tra bản cập nhật” để kiểm tra các bản phát hành mới nhất từ GitHub.',
                    'Click “Check for updates” to inspect latest releases from GitHub.'
                  )}
                </div>
              ) : (
                <div style={{ height: '220px' }}>
                  <VirtualTable<Version>
                    data={availableVersions}
                    columns={availableColumns}
                    rowHeight={40}
                    rowKey={(v) => v.id || v.name}
                    selectedKeys={selectedAvailableId ? new Set([selectedAvailableId]) : undefined}
                    onRowClick={(v) => {
                      const verId = v.id || v.name;
                      setSelectedAvailableId((prev) => (prev === verId ? null : verId));
                    }}
                  />
                </div>
              )}
            </div>

            {/* Fingerprint Presets Dataset Group */}
            <div className="cm-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <h2 className="cm-card-title" style={{ margin: '0 0 6px 0' }}>
                    {t('Dữ liệu Fingerprint mẫu Camoufox (Presets Dataset)', 'Camoufox Fingerprint Presets Dataset')}
                  </h2>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {totalPresets > 0
                      ? t(
                          `Dữ liệu mẫu: ${totalPresets} bản ghi (Cập nhật lúc: ${formatDate(snapshot.fingerprint_data?.updated_at)})`,
                          `Sample presets: ${totalPresets} records (Updated: ${formatDate(snapshot.fingerprint_data?.updated_at)})`
                        )
                      : t('Chưa tải bộ dữ liệu fingerprint mẫu chính thức.', 'Official fingerprint presets dataset not downloaded yet.')}
                  </div>
                </div>

                <Button
                  variant="secondary"
                  loading={updatingFingerprint}
                  disabled={updatingFingerprint}
                  onClick={handleUpdateFingerprintData}
                >
                  {updatingFingerprint ? t('Đang cập nhật...', 'Updating...') : t('Cập nhật dữ liệu fingerprint', 'Update fingerprint data')}
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* =================================================================== */}
        {/* TAB 2: LIMITS & DEFAULTS */}
        {/* =================================================================== */}
        {activeTab === 'limits' && (
          <div className="cm-content-padded" style={{ maxWidth: '680px' }}>
            <form onSubmit={handleSaveSettings}>
              {/* Group: Giới hạn tài nguyên */}
              <div className="cm-card" style={{ marginBottom: '16px' }}>
                <h2 className="cm-card-title">{t('Giới hạn tài nguyên & Khởi chạy', 'Resource Limits & Startup')}</h2>

                <Field
                  label={t('Số profile tối đa chạy đồng thời', 'Maximum concurrent running profiles')}
                  hint={t('Giới hạn số lượng trình duyệt mở cùng lúc để tránh quá tải CPU và RAM (từ 1 đến 64).', 'Limit the number of browser instances open simultaneously to avoid CPU and RAM overload (1 to 64).')}
                >
                  <input
                    type="number"
                    min={1}
                    max={64}
                    className="cm-input"
                    style={{ width: '100px' }}
                    aria-label={t('Số profile tối đa chạy đồng thời', 'Maximum concurrent running profiles')}
                    value={maxRunning}
                    onChange={(e) => setMaxRunning(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  />
                </Field>

                <div style={{ marginTop: '14px' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      className="cm-checkbox"
                      checked={autoCheckUpdates}
                      onChange={(e) => setAutoCheckUpdates(e.target.checked)}
                    />
                    {t('Tự động kiểm tra bản cập nhật Camoufox khi khởi động', 'Automatically check for Camoufox updates on startup')}
                  </label>
                </div>
                <div style={{ marginTop: '12px' }}>
                  <Field
                    label={t('Chu kỳ kiểm tra cập nhật (giờ)', 'Update check interval (hours)')}
                    hint={t('Khoảng thời gian giữa các lần tự động kiểm tra bản phát hành mới (1 - 168 giờ).', 'Time interval between automatic checks for new releases (1 - 168 hours).')}
                  >
                    <input
                      type="number"
                      min={1}
                      max={168}
                      className="cm-input"
                      style={{ width: '100px' }}
                      aria-label={t('Chu kỳ kiểm tra cập nhật (giờ)', 'Update check interval (hours)')}
                      value={updateCheckHours}
                      onChange={(e) => setUpdateCheckHours(Math.max(1, parseInt(e.target.value, 10) || 1))}
                    />
                  </Field>
                </div>

                <div style={{ marginTop: '12px' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      className="cm-checkbox"
                      checked={autoDownloadUpdates}
                      onChange={(e) => setAutoDownloadUpdates(e.target.checked)}
                    />
                    {t('Tự động tải bản cập nhật khi phát hiện phiên bản mới', 'Automatically download updates when a new version is detected')}
                  </label>
                </div>
              </div>

              {/* Group: Cấu hình mặc định trình duyệt */}
              <div className="cm-card" style={{ marginBottom: '16px' }}>
                <h2 className="cm-card-title">{t('Khởi động & Tìm kiếm mặc định', 'Startup & Default Search Engine')}</h2>

                <Field
                  label={t('Trang khởi động mặc định', 'Default Startup URL')}
                  hint={t('Trang web mặc định mở khi tạo profile mới.', 'Default webpage opened when creating a new profile.')}
                >
                  <input
                    type="text"
                    className="cm-input"
                    aria-label={t('Trang khởi động mặc định', 'Default Startup URL')}
                    value={defaultStartupUrl}
                    onChange={(e) => setDefaultStartupUrl(e.target.value)}
                    placeholder="https://duckduckgo.com"
                  />
                </Field>

                <div style={{ marginTop: '12px' }}>
                  <Field
                    label={t('Công cụ tìm kiếm mặc định', 'Default Search Engine')}
                    hint={t('Công cụ tìm kiếm mặc định được gán cho profile mới.', 'Default search engine assigned to new profiles.')}
                  >
                    <select
                      className="cm-select"
                      style={{ minWidth: '220px' }}
                      aria-label={t('Công cụ tìm kiếm mặc định', 'Default Search Engine')}
                      value={defaultSearchEngine}
                      onChange={(e) => setDefaultSearchEngine(e.target.value)}
                    >
                      <option value="DuckDuckGo">DuckDuckGo</option>
                      <option value="Google">Google</option>
                      <option value="Bing">Bing</option>
                    </select>
                  </Field>
                </div>
              </div>

              {/* Group: Chính sách Proxy mặc định */}
              <div className="cm-card" style={{ marginBottom: '20px' }}>
                <h2 className="cm-card-title">{t('Chính sách Proxy mặc định', 'Default Proxy Policy')}</h2>

                <Field label={t('Proxy mặc định cho profile mới:', 'Default proxy for new profiles:')}>
                  <select
                    className="cm-select"
                    style={{ minWidth: '220px' }}
                    aria-label={t('Proxy mặc định cho profile mới', 'Default proxy for new profiles')}
                    value={defaultProxyId}
                    onChange={(e) => setDefaultProxyId(e.target.value)}
                  >
                    <option value="">{t('Không (Trực tiếp)', 'None (Direct)')}</option>
                    {(snapshot.proxies || []).map((px) => (
                      <option key={px.id} value={px.id}>
                        {px.name || px.server}
                      </option>
                    ))}
                  </select>
                </Field>

                <div style={{ marginTop: '12px' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      className="cm-checkbox"
                      checked={autoAssignProxy}
                      onChange={(e) => setAutoAssignProxy(e.target.checked)}
                    />
                    {t('Tự động phân bổ proxy khả dụng trong kho cho profile mới', 'Automatically assign an available proxy from pool to new profiles')}
                  </label>
                </div>
              </div>

              <Button
                variant="primary"
                type="submit"
                loading={savingSettings}
                disabled={savingSettings}
              >
                {savingSettings ? t('Đang lưu...', 'Saving...') : t('Lưu cấu hình chung', 'Save General Settings')}
              </Button>
            </form>
          </div>
        )}

        {/* =================================================================== */}
        {/* TAB 3: DIAGNOSTICS & REDACTED LOGS */}
        {/* =================================================================== */}
        {activeTab === 'diagnostics' && (
          <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
            {/* Logs Action Bar */}
            <div className="cm-subbar">
              <div className="cm-subbar-left">
                <input
                  type="search"
                  className="cm-input"
                  style={{ width: '220px' }}
                  placeholder={t('Lọc nhật ký...', 'Filter logs...')}
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                />
                <Button
                  variant="secondary"
                  loading={loadingLogs}
                  disabled={loadingLogs}
                  onClick={fetchLogs}
                >
                  {loadingLogs ? t('Đang tải...', 'Loading...') : t('Làm mới', 'Refresh')}
                </Button>
                <Button
                  variant="secondary"
                  loading={exportingLogs}
                  disabled={exportingLogs}
                  onClick={handleExportLogs}
                >
                  {exportingLogs ? t('Đang xuất...', 'Exporting...') : t('Xuất nhật ký (Đã che nhạy cảm)', 'Export Logs (Redacted)')}
                </Button>
              </div>

              <div className="cm-subbar-right">
                <Button
                  variant="danger"
                  onClick={() => setStopAllOpen(true)}
                >
                  {t('Dừng khẩn cấp toàn bộ profile', 'Emergency Stop All Profiles')}
                </Button>
              </div>
            </div>

            {/* Logs Table Area */}
            <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
              {filteredLogs.length === 0 ? (
                <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  {loadingLogs ? t('Đang tải danh sách nhật ký...', 'Loading logs...') : t('Không có dòng nhật ký nào.', 'No logs recorded.')}
                </div>
              ) : (
                <VirtualTable<LogRow>
                  data={filteredLogs}
                  columns={logColumns}
                  rowHeight={36}
                  rowKey="id"
                />
              )}
            </div>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={deleteVersion !== null}
        title={t('Xóa phiên bản Camoufox', 'Delete Camoufox Version')}
        message={t(`Xóa ${deleteVersion?.name || deleteVersion?.id || ''} và toàn bộ file trình duyệt của phiên bản này? Hồ sơ, cookie và fingerprint không bị xóa.`, `Delete ${deleteVersion?.name || deleteVersion?.id || ''} and all its browser files? Profiles, cookies, and fingerprints will remain intact.`)}
        confirmText={t('Xóa phiên bản', 'Delete Version')}
        cancelText={t('Hủy bỏ', 'Cancel')}
        loading={deletingVersion}
        onConfirm={handleDeleteVersion}
        onCancel={() => setDeleteVersion(null)}
      />

      {/* Emergency Stop All Confirmation Dialog */}
      <ConfirmDialog
        open={stopAllOpen}
        title={t('Dừng khẩn cấp toàn bộ profile', 'Emergency Stop All Profiles')}
        message={t('Bạn có chắc chắn muốn dừng toàn bộ profile đang chạy? Tất cả các tiến trình trình duyệt sẽ nhận lệnh đóng ngay lập tức.', 'Are you sure you want to stop all running profiles? All browser processes will receive a termination signal immediately.')}
        confirmText={t('Dừng khẩn cấp', 'Emergency Stop')}
        cancelText={t('Hủy bỏ', 'Cancel')}
        variant="danger"
        loading={stoppingAll}
        onConfirm={handleEmergencyStopAll}
        onCancel={() => setStopAllOpen(false)}
      />
    </div>
  );
}
