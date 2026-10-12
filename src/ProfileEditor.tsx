import React, { useEffect, useState } from 'react';
import { openPath, request } from './api';
import { Button, Field, Modal } from './components';
import { useI18n } from './i18n';
import type { AppSnapshot, Location, MessageLevel, Profile, ProxyCheck } from './types';

export interface ProfileEditorProps {
  open?: boolean;
  profile: Profile | null;
  snapshot: AppSnapshot;
  onClose: () => void;
  onSaved: (saved: Profile) => Promise<void> | void;
  onMessage: (message: string, level?: MessageLevel) => void;
}

type ProxyMode = 'default' | 'direct' | 'specific' | 'auto';
type EditorTab = 'general' | 'proxy' | 'location' | 'startup' | 'extensions';

export default function ProfileEditor({
  open = true,
  profile,
  snapshot,
  onClose,
  onSaved,
  onMessage,
}: ProfileEditorProps) {
  const { t } = useI18n();
  const [activeTab, setActiveTab] = useState<EditorTab>('general');
  const [savedProfile, setSavedProfile] = useState<Profile | null>(profile);
  const [loadingFull, setLoadingFull] = useState(false);

  // Tab 1: General
  const [name, setName] = useState('');
  const [group, setGroup] = useState('');
  const [tagsText, setTagsText] = useState('');
  const [os, setOs] = useState('windows');
  const [browserVersion, setBrowserVersion] = useState('');
  const [usePreset, setUsePreset] = useState(true);
  const [note, setNote] = useState('');
  const [versionNotice, setVersionNotice] = useState(false);
  const [presetNotice, setPresetNotice] = useState(false);

  // Tab 2: Proxy & Network
  const [proxyMode, setProxyMode] = useState<ProxyMode>('default');
  const [selectedProxyId, setSelectedProxyId] = useState('');
  const [testingProxy, setTestingProxy] = useState(false);
  const [proxyTestResult, setProxyTestResult] = useState<{ ok: boolean; vi: string; en: string } | null>(null);

  // Tab 3: Location & GeoIP
  const [locIp, setLocIp] = useState('');
  const [locCountry, setLocCountry] = useState('');
  const [locTimezone, setLocTimezone] = useState('');
  const [locLocale, setLocLocale] = useState('');
  const [locLat, setLocLat] = useState('');
  const [locLng, setLocLng] = useState('');
  const [locLocked, setLocLocked] = useState(false);
  const [detectingLoc, setDetectingLoc] = useState(false);

  // Tab 4: Startup URLs & Bookmarks
  const [startupUrls, setStartupUrls] = useState<string[]>([]);
  const [newStartupUrl, setNewStartupUrl] = useState('');
  const [bookmarks, setBookmarks] = useState<{ title: string; url: string }[]>([]);
  const [newBmTitle, setNewBmTitle] = useState('');
  const [newBmUrl, setNewBmUrl] = useState('');

  // Tab 5: Extensions
  const [extensions, setExtensions] = useState<string[]>([]);
  const [busyExt, setBusyExt] = useState(false);

  const [saving, setSaving] = useState(false);

  const populateFromProfile = (p: Profile) => {
    setSavedProfile(p);
    setName(p.name || '');
    setGroup(p.group || '');
    setTagsText((p.tags || []).join(', '));
    setOs(p.os || 'windows');
    setBrowserVersion(p.browser_version || '');
    setUsePreset(Boolean(p.fingerprint_meta?.use_preset));
    setNote(p.note || '');
    setVersionNotice(false);
    setPresetNotice(false);

    if (p.proxy_id) {
      setProxyMode('specific');
      setSelectedProxyId(p.proxy_id);
    } else {
      setProxyMode('direct');
      setSelectedProxyId(snapshot.proxies[0]?.id || '');
    }
    setProxyTestResult(null);

    const loc = p.location || {};
    setLocIp(loc.ip || '');
    setLocCountry(loc.country || '');
    setLocTimezone(loc.timezone || '');
    setLocLocale(loc.locale || '');
    setLocLat(loc.latitude !== undefined && loc.latitude !== null ? String(loc.latitude) : '');
    setLocLng(loc.longitude !== undefined && loc.longitude !== null ? String(loc.longitude) : '');
    setLocLocked(Boolean(loc.locked));

    setStartupUrls([...(p.startup_urls || [])]);
    setBookmarks((p.bookmarks || []).map((b) => ({ title: b.title || '', url: b.url || '' })));
    setExtensions([...(p.extensions || [])]);
  };

  useEffect(() => {
    if (!open) return;
    setActiveTab('general');
    if (!profile) {
      setSavedProfile(null);
      setName('');
      setGroup('');
      setTagsText('');
      setOs('windows');
      setBrowserVersion('');
      setUsePreset(true);
      setNote('');
      setVersionNotice(false);
      setPresetNotice(false);
      setProxyMode('default');
      setSelectedProxyId(snapshot.proxies[0]?.id || '');
      setProxyTestResult(null);
      setLocIp('');
      setLocCountry('');
      setLocTimezone('');
      setLocLocale('');
      setLocLat('');
      setLocLng('');
      setLocLocked(false);
      setStartupUrls([]);
      setNewStartupUrl('');
      setBookmarks([]);
      setNewBmTitle('');
      setNewBmUrl('');
      setExtensions([]);
      return;
    }

    populateFromProfile(profile);
    let cancelled = false;
    setLoadingFull(true);
    request<Profile>('profile.get', { id: profile.id })
      .then((full) => {
        if (!cancelled && full) {
          populateFromProfile(full);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          onMessage(`${t('Không thể tải chi tiết profile: ', 'Failed to load profile details: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingFull(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, profile?.id, t]);

  if (!open) return null;

  const isEdit = Boolean(savedProfile?.id);

  const resolveLeastUsedProxyId = (): string => {
    const enabledProxies = snapshot.proxies.filter((px) => px.enabled !== false);
    if (enabledProxies.length === 0) return '';
    const counts: Record<string, number> = {};
    for (const px of enabledProxies) counts[px.id] = 0;
    for (const prof of snapshot.profiles) {
      if (prof.id === savedProfile?.id) continue;
      if (prof.proxy_id && prof.proxy_id in counts) {
        counts[prof.proxy_id] += 1;
      }
    }
    let best = enabledProxies[0];
    for (const px of enabledProxies) {
      if (counts[px.id] < counts[best.id]) {
        best = px;
      }
    }
    return best.id;
  };

  const resolveEffectiveProxyId = (): string => {
    if (proxyMode === 'specific') return selectedProxyId;
    if (proxyMode === 'default') return snapshot.settings.default_proxy_id || '';
    if (proxyMode === 'auto') return resolveLeastUsedProxyId();
    return '';
  };

  const buildPayload = (): Record<string, unknown> | null => {
    const cleanName = name.trim();
    if (!cleanName) {
      onMessage(t('Vui lòng nhập tên cho profile.', 'Please enter a profile name.'), 'warning');
      setActiveTab('general');
      return null;
    }

    const proxyParam = resolveEffectiveProxyId();
    if (proxyMode === 'specific' && !proxyParam) {
      onMessage(t('Vui lòng chọn một proxy từ danh sách hoặc đổi sang chế độ khác.', 'Please select a proxy from the list or switch to another mode.'), 'warning');
      setActiveTab('proxy');
      return null;
    }
    if (proxyMode === 'auto' && !proxyParam) {
      onMessage(t('Kho proxy không có proxy nào đang được kích hoạt để tự động gán.', 'No enabled proxies available in the proxy pool for automatic assignment.'), 'warning');
      setActiveTab('proxy');
      return null;
    }

    let latVal: number | null = null;
    let lngVal: number | null = null;
    if (locLat.trim() !== '') {
      const parsedLat = Number(locLat.trim());
      if (Number.isNaN(parsedLat) || parsedLat < -90 || parsedLat > 90) {
        onMessage(t('Vĩ độ (Latitude) phải nằm trong khoảng -90 đến 90.', 'Latitude must be between -90 and 90.'), 'warning');
        setActiveTab('location');
        return null;
      }
      latVal = parsedLat;
    }
    if (locLng.trim() !== '') {
      const parsedLng = Number(locLng.trim());
      if (Number.isNaN(parsedLng) || parsedLng < -180 || parsedLng > 180) {
        onMessage(t('Kinh độ (Longitude) phải nằm trong khoảng -180 đến 180.', 'Longitude must be between -180 and 180.'), 'warning');
        setActiveTab('location');
        return null;
      }
      lngVal = parsedLng;
    }

    const tags = tagsText
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    const pendingStartupUrls = newStartupUrl.trim()
      ? [...startupUrls, newStartupUrl.trim()]
      : [...startupUrls];

    const pendingBookmarks =
      newBmTitle.trim() && newBmUrl.trim()
        ? [...bookmarks, { title: newBmTitle.trim(), url: newBmUrl.trim() }]
        : [...bookmarks];

    const meta = {
      ...(savedProfile?.fingerprint_meta || {}),
      use_preset: usePreset,
    };

    const payload: Record<string, unknown> = {
      name: cleanName,
      group: group.trim(),
      tags,
      note: note.trim(),
      os,
      browser_version: browserVersion,
      proxy_id: proxyParam,
      location: {
        ip: locIp.trim(),
        country: locCountry.trim(),
        timezone: locTimezone.trim(),
        locale: locLocale.trim(),
        latitude: latVal,
        longitude: lngVal,
        locked: locLocked,
      },
      startup_urls: pendingStartupUrls,
      bookmarks: pendingBookmarks,
      extensions,
      fingerprint_meta: meta,
    };

    return payload;
  };

  const persistProfile = async (closeAfterSave: boolean): Promise<Profile | null> => {
    const payload = buildPayload();
    if (!payload) return null;

    setSaving(true);
    try {
      const saved = savedProfile?.id
        ? await request<Profile>('profile.update', { id: savedProfile.id, data: payload })
        : await request<Profile>('profile.create', { data: payload });
      populateFromProfile(saved);
      setNewStartupUrl('');
      setNewBmTitle('');
      setNewBmUrl('');
      await onSaved(saved);
      if (closeAfterSave) {
        onClose();
      }
      return saved;
    } catch (err) {
      onMessage(`${t('Lỗi lưu profile: ', 'Failed to save profile: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
      return null;
    } finally {
      setSaving(false);
    }
  };

  const handleTestProxy = async () => {
    const pxId = resolveEffectiveProxyId();
    setTestingProxy(true);
    setProxyTestResult(null);
    try {
      if (pxId) {
        const res = await request<ProxyCheck>('proxy.check', { id: pxId });
        const ok = Boolean(res.ok ?? res.status === 'ok');
        const ip = String(res.ip || res.egress_ip || '');
        const country = String(res.country || '');
        const latency = Number(res.latency_ms || 0);
        if (ok) {
          setProxyTestResult({
            ok: true,
            vi: `Kết nối tốt: IP ${ip} (${country}), độ trễ ${latency.toFixed(0)}ms`,
            en: `Good connection: IP ${ip} (${country}), latency ${latency.toFixed(0)}ms`,
          });
        } else {
          const errDetail = String(res.error || '');
          setProxyTestResult({
            ok: false,
            vi: `Lỗi kết nối: ${errDetail || 'Không phản hồi'}`,
            en: `Connection error: ${errDetail || 'No response'}`,
          });
        }
      } else {
        const loc = await request<Location>('location.detect', {});
        setProxyTestResult({
          ok: true,
          vi: `Kết nối trực tiếp tốt: IP ${loc.ip || '-'} (${loc.country || '-'})`,
          en: `Direct connection successful: IP ${loc.ip || '-'} (${loc.country || '-'})`,
        });
      }
    } catch (err) {
      const errStr = err instanceof Error ? err.message : String(err);
      setProxyTestResult({
        ok: false,
        vi: `Lỗi kiểm tra: ${errStr}`,
        en: `Check error: ${errStr}`,
      });
    } finally {
      setTestingProxy(false);
    }
  };
  const handleDetectLocation = async () => {
    const pxId = resolveEffectiveProxyId();
    setDetectingLoc(true);
    try {
      const loc = await request<Location>('location.detect', pxId ? { proxy_id: pxId } : {});
      if (loc) {
        setLocIp(loc.ip || '');
        setLocCountry(loc.country || '');
        setLocTimezone(loc.timezone || '');
        setLocLocale(loc.locale || '');
        setLocLat(loc.latitude !== undefined && loc.latitude !== null ? String(loc.latitude) : '');
        setLocLng(loc.longitude !== undefined && loc.longitude !== null ? String(loc.longitude) : '');
        onMessage(t('Đã cập nhật thông tin vị trí từ IP/Proxy.', 'Updated location information from IP/Proxy.'), 'info');
      }
    } catch (err) {
      onMessage(
        `${t('Tra cứu vị trí thất bại: ', 'Location lookup failed: ')}${err instanceof Error ? err.message : String(err)}. ${t('Hệ thống không áp đặt vị trí giả định; vui lòng nhập thủ công.', 'System does not enforce assumed location; please enter manually.')}`,
        'warning'
      );
    } finally {
      setDetectingLoc(false);
    }
  };
  const handleImportExtension = async (directory: boolean) => {
    const path = await openPath(
      directory
        ? { directory: true }
        : {
            directory: false,
            filters: [{ name: t('Tệp nén tiện ích', 'Extension Archive'), extensions: ['xpi', 'zip'] }],
          }
    );
    if (!path) return;

    // Save profile before importing extension so unsaved changes are never dropped and profile ID exists.
    const current = await persistProfile(false);
    if (!current) return;

    setBusyExt(true);
    try {
      const extName = await request<string>('profile.import_extension', {
        id: current.id,
        path,
      });
      setExtensions((prev) => (prev.includes(extName) ? prev : [...prev, extName]));
      await onSaved({ ...current, extensions: current.extensions.includes(extName) ? current.extensions : [...current.extensions, extName] });
      onMessage(`${t('Đã thêm tiện ích: ', 'Added extension: ')}${extName}`, 'info');
    } catch (err) {
      onMessage(`${t('Lỗi thêm tiện ích: ', 'Failed to add extension: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setBusyExt(false);
    }
  };
  const handleRemoveExtension = async (extName: string) => {
    if (!savedProfile?.id) {
      setExtensions((prev) => prev.filter((e) => e !== extName));
      return;
    }
    setBusyExt(true);
    try {
      await request<null>('profile.remove_extension', {
        id: savedProfile.id,
        name: extName,
      });
      const next = extensions.filter((e) => e !== extName);
      setExtensions(next);
      await onSaved({ ...savedProfile, extensions: next });
      onMessage(`${t('Đã xóa tiện ích: ', 'Removed extension: ')}${extName}`, 'info');
    } catch (err) {
      onMessage(`${t('Lỗi xóa tiện ích: ', 'Failed to remove extension: ')}${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setBusyExt(false);
    }
  };

  return (
    <Modal
      open={open}
      busy={saving || busyExt}
      title={isEdit ? `${t('Chỉnh sửa Profile: ', 'Edit Profile: ')}${savedProfile?.name || ''}` : t('Tạo Profile Mới', 'Create New Profile')}
      onClose={onClose}
      width={720}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={saving || busyExt}>
            {t('Hủy bỏ', 'Cancel')}
          </Button>
          <Button variant="primary" onClick={() => persistProfile(true)} loading={saving}>
            {saving ? t('Đang lưu profile...', 'Saving profile...') : t('Lưu profile', 'Save profile')}
          </Button>
        </>
      }
    >
      {loadingFull ? (
        <div className="cm-banner cm-banner-info" style={{ marginBottom: 12 }}>
          {t('Đang tải dữ liệu chi tiết của profile...', 'Loading detailed profile data...')}
        </div>
      ) : null}

      <div className="cm-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'general'}
          className={`cm-tab ${activeTab === 'general' ? 'cm-tab-active' : ''}`}
          onClick={() => setActiveTab('general')}
        >
          {t('Tổng quan', 'General')}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'proxy'}
          className={`cm-tab ${activeTab === 'proxy' ? 'cm-tab-active' : ''}`}
          onClick={() => setActiveTab('proxy')}
        >
          {t('Proxy & Mạng', 'Proxy & Network')}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'location'}
          className={`cm-tab ${activeTab === 'location' ? 'cm-tab-active' : ''}`}
          onClick={() => setActiveTab('location')}
        >
          {t('Vị trí & GeoIP', 'Location & GeoIP')}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'startup'}
          className={`cm-tab ${activeTab === 'startup' ? 'cm-tab-active' : ''}`}
          onClick={() => setActiveTab('startup')}
        >
          {t('Trang mở đầu & Bookmark', 'Startup URLs & Bookmarks')}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'extensions'}
          className={`cm-tab ${activeTab === 'extensions' ? 'cm-tab-active' : ''}`}
          onClick={() => setActiveTab('extensions')}
        >
          {t('Tiện ích mở rộng', 'Extensions')} ({extensions.length})
        </button>
      </div>

      {activeTab === 'general' ? (
        <div>
          <Field label={t('Tên profile (*):', 'Profile Name (*):')} htmlFor="profile-name">
            <input
              id="profile-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('Ví dụ: Tài khoản chính, Nuôi nick 01...', 'e.g. Main Account, Farming 01...')}
            />
          </Field>

          <div className="cm-grid-2">
            <Field label={t('Nhóm:', 'Group:')} htmlFor="profile-group">
              <input
                id="profile-group"
                type="text"
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                placeholder={t('Ví dụ: Facebook, E-commerce, Marketing...', 'e.g. Facebook, E-commerce, Marketing...')}
              />
            </Field>
            <Field label={t('Thẻ (phân cách bởi dấu phẩy):', 'Tags (comma separated):')} htmlFor="profile-tags">
              <input
                id="profile-tags"
                type="text"
                value={tagsText}
                onChange={(e) => setTagsText(e.target.value)}
                placeholder="tag1, tag2, proxy_us..."
              />
            </Field>
          </div>

          <div className="cm-grid-2">
            <Field label={t('Hệ điều hành (OS):', 'Operating System (OS):')} htmlFor="profile-os">
              <select id="profile-os" value={os} onChange={(e) => setOs(e.target.value)}>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
                <option value="linux">Linux</option>
              </select>
            </Field>
            <Field label={t('Phiên bản Camoufox ghim:', 'Pinned Camoufox Version:')} htmlFor="profile-version">
              <select
                id="profile-version"
                value={browserVersion}
                onChange={(e) => {
                  const nextVer = e.target.value;
                  setBrowserVersion(nextVer);
                  setVersionNotice(isEdit && nextVer !== (savedProfile?.browser_version || ''));
                }}
              >
                <option value="">{t('Mặc định hệ thống', 'System default')}</option>
                {snapshot.versions.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.id} {v.name ? `(${v.name})` : ''}
                  </option>
                ))}
              </select>
            </Field>
          </div>

          {versionNotice ? (
            <div className="cm-banner cm-banner-warning" style={{ marginBottom: 12 }}>
              {t(
                'Lưu ý: Thay đổi phiên bản trình duyệt Camoufox có thể cập nhật User-Agent đối với các website đã truy cập.',
                'Note: Changing the Camoufox browser version may update User-Agent for previously visited websites.'
              )}
            </div>
          ) : null}

          <div className="cm-field">
            <label className="cm-row" style={{ cursor: 'pointer', fontWeight: 500 }}>
              <input
                type="checkbox"
                checked={usePreset}
                onChange={(e) => {
                  const checked = e.target.checked;
                  setUsePreset(checked);
                  setPresetNotice(isEdit && checked !== Boolean(savedProfile?.fingerprint_meta?.use_preset));
                }}
              />
              <span>{t('Fingerprint mẫu Camoufox (dữ liệu mới nhất)', 'Camoufox Preset Fingerprint (latest data)')}</span>
            </label>
          </div>

          {presetNotice ? (
            <div className="cm-banner cm-banner-info" style={{ marginBottom: 12 }}>
              {t(
                'Lưu ý: Lưu thay đổi chế độ fingerprint mẫu sẽ sinh fingerprint mới và thay đổi danh tính của profile hiện tại.',
                'Note: Saving changes to fingerprint preset mode will generate a new fingerprint and alter the identity of the current profile.'
              )}
            </div>
          ) : null}

          <Field label={t('Ghi chú:', 'Notes:')} htmlFor="profile-note">
            <textarea
              id="profile-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={t('Ghi chú thông tin tài khoản hoặc mục đích sử dụng...', 'Account notes or intended usage...')}
              rows={4}
            />
          </Field>
        </div>
      ) : null}

      {activeTab === 'proxy' ? (
        <div>
          <Field label={t('Chế độ mạng & Proxy:', 'Network & Proxy Mode:')} htmlFor="profile-proxy-mode">
            <select
              id="profile-proxy-mode"
              value={proxyMode}
              onChange={(e) => {
                setProxyMode(e.target.value as ProxyMode);
                setProxyTestResult(null);
              }}
            >
              <option value="default">{t('Dùng proxy mặc định hệ thống', 'Use system default proxy')}</option>
              <option value="direct">{t('Không dùng proxy (Trực tiếp)', 'No proxy (Direct)')}</option>
              <option value="specific">{t('Chọn proxy cụ thể từ kho', 'Select specific proxy from pool')}</option>
              <option value="auto">{t('Tự động gán proxy khả dụng', 'Auto-assign available proxy')}</option>
            </select>
          </Field>

          {proxyMode === 'specific' ? (
            <Field label={t('Proxy đã chọn:', 'Selected Proxy:')} htmlFor="profile-proxy-select">
              <select
                id="profile-proxy-select"
                value={selectedProxyId}
                onChange={(e) => {
                  setSelectedProxyId(e.target.value);
                  setProxyTestResult(null);
                }}
              >
                <option value="">{t('-- Chọn proxy --', '-- Select proxy --')}</option>
                {snapshot.proxies.map((px) => (
                  <option key={px.id} value={px.id}>
                    {px.name || px.id} ({px.server})
                  </option>
                ))}
              </select>
            </Field>
          ) : null}

          <div className="cm-row" style={{ marginTop: 8, marginBottom: 12 }}>
            <Button variant="secondary" onClick={handleTestProxy} loading={testingProxy}>
              {testingProxy ? t('Đang kiểm tra kết nối...', 'Testing connection...') : t('Kiểm tra kết nối', 'Test connection')}
            </Button>
          </div>

          {proxyTestResult ? (
            <div className={`cm-banner ${proxyTestResult.ok ? 'cm-banner-info' : 'cm-banner-danger'}`}>
              {t(proxyTestResult.vi, proxyTestResult.en)}
            </div>
          ) : null}
        </div>
      ) : null}

      {activeTab === 'location' ? (
        <div>
          <div className="cm-row" style={{ marginBottom: 14, flexWrap: 'wrap', justifyContent: 'space-between' }}>
            <Button variant="secondary" onClick={handleDetectLocation} loading={detectingLoc}>
              {detectingLoc ? t('Đang phát hiện...', 'Detecting...') : t('Tự động phát hiện vị trí từ IP/Proxy', 'Auto-detect location from IP/Proxy')}
            </Button>
            <label className="cm-row" style={{ cursor: 'pointer', fontWeight: 500 }}>
              <input
                type="checkbox"
                checked={locLocked}
                onChange={(e) => setLocLocked(e.target.checked)}
              />
              <span>{t('Khóa thông tin vị trí (Không tự động thay đổi)', 'Lock location info (Do not auto-update)')}</span>
            </label>
          </div>

          <div className="cm-grid-2">
            <Field label={t('Địa chỉ IP:', 'IP Address:')} htmlFor="loc-ip">
              <input id="loc-ip" type="text" value={locIp} onChange={(e) => setLocIp(e.target.value)} />
            </Field>
            <Field label={t('Quốc gia (Country code):', 'Country (Country code):')} htmlFor="loc-country">
              <input
                id="loc-country"
                type="text"
                value={locCountry}
                onChange={(e) => setLocCountry(e.target.value)}
                placeholder="VN, US, JP..."
              />
            </Field>
          </div>

          <div className="cm-grid-2">
            <Field label={t('Múi giờ (Timezone):', 'Timezone:')} htmlFor="loc-timezone">
              <input
                id="loc-timezone"
                type="text"
                value={locTimezone}
                onChange={(e) => setLocTimezone(e.target.value)}
                placeholder="Asia/Ho_Chi_Minh, America/New_York..."
              />
            </Field>
            <Field label={t('Ngôn ngữ (Locale):', 'Language (Locale):')} htmlFor="loc-locale">
              <input
                id="loc-locale"
                type="text"
                value={locLocale}
                onChange={(e) => setLocLocale(e.target.value)}
                placeholder="vi-VN, en-US..."
              />
            </Field>
          </div>

          <div className="cm-grid-2">
            <Field label={t('Vĩ độ (Latitude):', 'Latitude:')} htmlFor="loc-lat">
              <input
                id="loc-lat"
                type="text"
                value={locLat}
                onChange={(e) => setLocLat(e.target.value)}
                placeholder={t('Ví dụ: 10.7769', 'e.g. 10.7769')}
              />
            </Field>
            <Field label={t('Kinh độ (Longitude):', 'Longitude:')} htmlFor="loc-lng">
              <input
                id="loc-lng"
                type="text"
                value={locLng}
                onChange={(e) => setLocLng(e.target.value)}
                placeholder={t('Ví dụ: 106.7009', 'e.g. 106.7009')}
              />
            </Field>
          </div>
        </div>
      ) : null}

      {activeTab === 'startup' ? (
        <div>
          <Field label={t('Trang khởi động (Startup URLs):', 'Startup URLs:')}>
            <div className="cm-list-box" style={{ marginBottom: 8 }}>
              {startupUrls.length === 0 ? (
                <div className="cm-list-item cm-muted-text">{t('Chưa có URL khởi động nào.', 'No startup URLs configured.')}</div>
              ) : (
                startupUrls.map((u, idx) => (
                  <div key={`${u}-${idx}`} className="cm-list-item">
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{u}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setStartupUrls((prev) => prev.filter((_, i) => i !== idx))}
                    >
                      {t('Xóa', 'Delete')}
                    </Button>
                  </div>
                ))
              )}
            </div>
            <div className="cm-row">
              <input
                type="text"
                style={{ flex: 1 }}
                value={newStartupUrl}
                onChange={(e) => setNewStartupUrl(e.target.value)}
                placeholder="https://example.com..."
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && newStartupUrl.trim()) {
                    e.preventDefault();
                    setStartupUrls((prev) => [...prev, newStartupUrl.trim()]);
                    setNewStartupUrl('');
                  }
                }}
              />
              <Button
                variant="secondary"
                onClick={() => {
                  if (!newStartupUrl.trim()) return;
                  setStartupUrls((prev) => [...prev, newStartupUrl.trim()]);
                  setNewStartupUrl('');
                }}
              >
                {t('Thêm URL', 'Add URL')}
              </Button>
            </div>
          </Field>

          <Field label={t('Dấu trang (Bookmarks):', 'Bookmarks:')}>
            <div className="cm-list-box" style={{ marginBottom: 8 }}>
              {bookmarks.length === 0 ? (
                <div className="cm-list-item cm-muted-text">{t('Chưa có dấu trang nào.', 'No bookmarks configured.')}</div>
              ) : (
                bookmarks.map((bm, idx) => (
                  <div key={`${bm.url}-${idx}`} className="cm-list-item">
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <strong>{bm.title}</strong> — <span className="cm-muted-text">{bm.url}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setBookmarks((prev) => prev.filter((_, i) => i !== idx))}
                    >
                      {t('Xóa', 'Delete')}
                    </Button>
                  </div>
                ))
              )}
            </div>
            <div className="cm-row" style={{ flexWrap: 'wrap' }}>
              <input
                type="text"
                style={{ flex: 1, minWidth: 140 }}
                value={newBmTitle}
                onChange={(e) => setNewBmTitle(e.target.value)}
                placeholder={t('Tiêu đề...', 'Title...')}
              />
              <input
                type="text"
                style={{ flex: 2, minWidth: 180 }}
                value={newBmUrl}
                onChange={(e) => setNewBmUrl(e.target.value)}
                placeholder="https://..."
              />
              <Button
                variant="secondary"
                onClick={() => {
                  if (!newBmTitle.trim() || !newBmUrl.trim()) return;
                  setBookmarks((prev) => [...prev, { title: newBmTitle.trim(), url: newBmUrl.trim() }]);
                  setNewBmTitle('');
                  setNewBmUrl('');
                }}
              >
                {t('Thêm Bookmark', 'Add Bookmark')}
              </Button>
            </div>
          </Field>
        </div>
      ) : null}

      {activeTab === 'extensions' ? (
        <div>
          <div className="cm-banner cm-banner-info" style={{ marginBottom: 12 }}>
            {isEdit
              ? t(
                  'Các thay đổi thông tin profile sẽ được lưu tự động trước khi cài đặt thêm tiện ích mở rộng.',
                  'Profile changes will be automatically saved before installing extensions.'
                )
              : t(
                  'Profile mới sẽ được lưu tự động trước khi thêm tiện ích mở rộng.',
                  'New profile will be automatically saved before adding extensions.'
                )}
          </div>

          <Field label={t('Tiện ích mở rộng đã cài (Extensions / Addons):', 'Installed Extensions (Addons):')}>
            <div className="cm-list-box" style={{ marginBottom: 10 }}>
              {extensions.length === 0 ? (
                <div className="cm-list-item cm-muted-text">{t('Chưa cài đặt tiện ích mở rộng nào.', 'No extensions installed.')}</div>
              ) : (
                extensions.map((ext) => (
                  <div key={ext} className="cm-list-item">
                    <span>{ext}</span>
                    <Button
                      variant="danger"
                      size="sm"
                      disabled={busyExt || saving}
                      onClick={() => handleRemoveExtension(ext)}
                    >
                      {t('Xóa tiện ích', 'Remove extension')}
                    </Button>
                  </div>
                ))
              )}
            </div>
            <div className="cm-row" style={{ flexWrap: 'wrap' }}>
              <Button
                variant="secondary"
                disabled={busyExt || saving}
                onClick={() => handleImportExtension(false)}
              >
                {t('Thêm file tiện ích (.xpi / .zip)', 'Add extension archive (.xpi / .zip)')}
              </Button>
              <Button
                variant="secondary"
                disabled={busyExt || saving}
                onClick={() => handleImportExtension(true)}
              >
                {t('Thêm thư mục tiện ích', 'Add extension directory')}
              </Button>
            </div>
          </Field>
        </div>
      ) : null}
    </Modal>
  );
}
