import React, { useState, useMemo, useId, useCallback } from 'react';
import type { PageProps, Proxy, ProxyCheck } from './types';
import { request } from './api';
import {
  Button,
  Modal,
  Field,
  ConfirmDialog,
  VirtualTable,
  Column,
  EmptyState,
} from './components';
import { useI18n } from './i18n';

export default function Proxies({ snapshot, onRefresh, onMessage }: PageProps) {
  const { t } = useI18n();
  const [search, setSearch] = useState('');
  const [editProxy, setEditProxy] = useState<Proxy | null | undefined>(undefined);
  const [importOpen, setImportOpen] = useState(false);
  const [deleteProxyId, setDeleteProxyId] = useState<string | null>(null);
  const [checkingAll, setCheckingAll] = useState(false);
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [updatingSetting, setUpdatingSetting] = useState(false);

  // Map of profile usage count per proxy id
  const usageMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const p of snapshot.profiles || []) {
      if (p.proxy_id) {
        map.set(p.proxy_id, (map.get(p.proxy_id) || 0) + 1);
      }
    }
    return map;
  }, [snapshot.profiles]);

  // Filtered proxies based on search text
  const filteredProxies = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return snapshot.proxies || [];
    return (snapshot.proxies || []).filter(
      (px) =>
        px.name.toLowerCase().includes(q) ||
        px.server.toLowerCase().includes(q) ||
        (px.username && px.username.toLowerCase().includes(q))
    );
  }, [snapshot.proxies, search]);

  // Check all proxies sequentially
  const handleCheckAll = useCallback(async () => {
    if (checkingAll) return;
    setCheckingAll(true);
    try {
      const results = await request<{ id: string; result: ProxyCheck }[]>('proxy.check_all');
      await onRefresh();
      const passed = results.filter((r) => r.result?.ok).length;
      onMessage(
        t(
          `Đã kiểm tra ${results.length} proxy (${passed} thành công, ${results.length - passed} lỗi).`,
          `Checked ${results.length} proxies (${passed} passed, ${results.length - passed} failed).`
        ),
        'info'
      );
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi kiểm tra proxy: ${err instanceof Error ? err.message : String(err)}`,
          `Proxy check error: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setCheckingAll(false);
    }
  }, [checkingAll, onRefresh, onMessage, t]);

  // Check a single proxy
  const handleCheckSingle = useCallback(
    async (pxId: string) => {
      setCheckingId(pxId);
      try {
        const res = await request<ProxyCheck>('proxy.check', { id: pxId });
        await onRefresh();
        if (res.ok) {
          onMessage(
            t(
              `Proxy kết nối tốt: IP ${res.ip || '-'} (${res.latency_ms ? Math.round(res.latency_ms) : 0}ms)`,
              `Proxy connected: IP ${res.ip || '-'} (${res.latency_ms ? Math.round(res.latency_ms) : 0}ms)`
            ),
            'info'
          );
        } else {
          onMessage(
            t(
              `Proxy không kết nối được: ${res.error || 'Lỗi kết nối'}`,
              `Proxy connection failed: ${res.error || 'Connection error'}`
            ),
            'warning'
          );
        }
      } catch (err: unknown) {
        onMessage(
          t(
            `Lỗi kiểm tra proxy: ${err instanceof Error ? err.message : String(err)}`,
            `Proxy check error: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
      } finally {
        setCheckingId(null);
      }
    },
    [onRefresh, onMessage, t]
  );

  // Toggle enabled/disabled state (backend merges existing record so credentials are not lost)
  const handleToggleEnabled = useCallback(
    async (px: Proxy) => {
      try {
        await request('proxy.save', {
          data: {
            id: px.id,
            enabled: !px.enabled,
          },
        });
        await onRefresh();
      } catch (err: unknown) {
        onMessage(
          t(
            `Lỗi thay đổi trạng thái proxy: ${err instanceof Error ? err.message : String(err)}`,
            `Failed to update proxy status: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
      }
    },
    [onRefresh, onMessage, t]
  );

  // Delete proxy confirmation
  const handleConfirmDelete = useCallback(async () => {
    if (!deleteProxyId) return;
    try {
      await request('proxy.delete', { id: deleteProxyId });
      setDeleteProxyId(null);
      await onRefresh();
      onMessage(t('Đã xóa proxy khỏi kho.', 'Deleted proxy from pool.'), 'info');
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi xóa proxy: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to delete proxy: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    }
  }, [deleteProxyId, onRefresh, onMessage, t]);

  // Save default proxy id setting
  const handleSaveDefaultProxy = useCallback(
    async (defId: string) => {
      setUpdatingSetting(true);
      try {
        await request('settings.save', {
          data: {
            default_proxy_id: defId,
          },
        });
        await onRefresh();
        onMessage(t('Đã lưu cấu hình proxy mặc định.', 'Saved default proxy setting.'), 'info');
      } catch (err: unknown) {
        onMessage(
          t(
            `Lỗi lưu cấu hình: ${err instanceof Error ? err.message : String(err)}`,
            `Failed to save setting: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
      } finally {
        setUpdatingSetting(false);
      }
    },
    [onRefresh, onMessage, t]
  );

  // Save auto assign proxy setting
  const handleSaveAutoAssign = useCallback(
    async (autoAssign: boolean) => {
      setUpdatingSetting(true);
      try {
        await request('settings.save', {
          data: {
            auto_assign_proxy: autoAssign,
          },
        });
        await onRefresh();
        onMessage(t('Đã lưu cấu hình tự động phân bổ proxy.', 'Saved auto-assign proxy setting.'), 'info');
      } catch (err: unknown) {
        onMessage(
          t(
            `Lỗi lưu cấu hình: ${err instanceof Error ? err.message : String(err)}`,
            `Failed to save setting: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
      } finally {
        setUpdatingSetting(false);
      }
    },
    [onRefresh, onMessage, t]
  );

  // Helper to mask passwords in raw server strings (e.g. socks5://user:pass@host:port)
  const maskServerString = (server: string): string => {
    if (!server.includes('@')) return server;
    const parts = server.split('@');
    const authPart = parts[0];
    const hostPart = parts.slice(1).join('@');
    if (authPart.includes('://')) {
      const scheme = authPart.split('://')[0];
      return `${scheme}://***:***@${hostPart}`;
    }
    return `***:***@${hostPart}`;
  };

  // Helper to determine protocol label
  const getProtocolLabel = (server: string): string => {
    const s = server.toLowerCase();
    if (s.startsWith('socks5')) return 'SOCKS5';
    if (s.startsWith('socks4')) return 'SOCKS4';
    if (s.startsWith('http')) return 'HTTP';
    return 'PROXY';
  };

  // VirtualTable Columns
  const columns: Column<Proxy>[] = useMemo(
    () => [
      {
        key: 'name',
        header: t('Tên proxy', 'Proxy Name'),
        width: 170,
        render: (px) => (
          <span style={{ fontWeight: 600 }} title={px.name}>
            {px.name || px.server}
          </span>
        ),
      },
      {
        key: 'server',
        header: t('Máy chủ', 'Server'),
        flex: 1.5,
        render: (px) => (
          <span title={px.server} style={{ fontFamily: 'Consolas, monospace', fontSize: '12px' }}>
            {maskServerString(px.server)}
          </span>
        ),
      },
      {
        key: 'type',
        header: t('Loại', 'Type'),
        width: 80,
        render: (px) => (
          <span style={{ color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 600 }}>
            {getProtocolLabel(px.server)}
          </span>
        ),
      },
      {
        key: 'last_check',
        header: t('Kết quả kiểm tra (Egress / Độ trễ)', 'Check Result (Egress / Latency)'),
        flex: 2,
        render: (px) => {
          const chk = px.last_check;
          if (!chk || (chk.ok === undefined && !chk.ip && !chk.error)) {
            return <span style={{ color: 'var(--text-muted)' }}>{t('Chưa kiểm tra', 'Not checked')}</span>;
          }
          if (chk.ok) {
            const ip = chk.ip || '';
            const country = chk.country ? `(${chk.country})` : '';
            const lat = chk.latency_ms !== undefined ? `${Math.round(chk.latency_ms)}ms` : '';
            return (
              <span style={{ color: 'var(--success)', fontWeight: 500 }}>
                [OK] {ip} {country} {lat ? `- ${lat}` : ''}
              </span>
            );
          }
          return (
            <span style={{ color: 'var(--danger)', fontWeight: 500 }} title={chk.error || t('Lỗi không xác định', 'Unknown error')}>
              [{t('Lỗi', 'Error')}] {chk.error || t('Không thể kết nối', 'Unable to connect')}
            </span>
          );
        },
      },
      {
        key: 'usage',
        header: t('Đang dùng', 'In Use'),
        width: 95,
        render: (px) => {
          const cnt = usageMap.get(px.id) || 0;
          return (
            <span style={{ color: 'var(--text-secondary)' }}>
              {t(`${cnt} profile`, `${cnt} profile${cnt === 1 ? '' : 's'}`)}
            </span>
          );
        },
      },
      {
        key: 'enabled',
        header: t('Kích hoạt', 'Enabled'),
        width: 85,
        align: 'center',
        render: (px) => (
          <input
            type="checkbox"
            className="cm-checkbox"
            checked={px.enabled !== false}
            onChange={() => handleToggleEnabled(px)}
            title={px.enabled ? t('Đang kích hoạt', 'Enabled') : t('Đã vô hiệu hóa', 'Disabled')}
            aria-label={px.enabled ? t('Đang kích hoạt', 'Enabled') : t('Đã vô hiệu hóa', 'Disabled')}
          />
        ),
      },
      {
        key: 'actions',
        header: t('Thao tác', 'Actions'),
        width: 170,
        align: 'right',
        render: (px) => (
          <div style={{ display: 'inline-flex', gap: '4px' }}>
            <Button
              size="sm"
              variant="secondary"
              loading={checkingId === px.id}
              disabled={checkingId === px.id}
              onClick={() => handleCheckSingle(px.id)}
            >
              {t('Test', 'Test')}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setEditProxy(px)}
            >
              {t('Sửa', 'Edit')}
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => setDeleteProxyId(px.id)}
            >
              {t('Xóa', 'Delete')}
            </Button>
          </div>
        ),
      },
    ],
    [usageMap, checkingId, handleCheckSingle, handleToggleEnabled, t]
  );

  const totalProxies = (snapshot.proxies || []).length;

  return (
    <div className="cm-page">
      {/* Top Bar */}
      <div className="cm-topbar">
        <div className="cm-topbar-left">
          <h1 className="cm-topbar-title">{t('Quản lý Proxy', 'Proxy Manager')}</h1>
          <span className="cm-pill-counter">
            {t(`${filteredProxies.length} / ${totalProxies} proxy`, `${filteredProxies.length} / ${totalProxies} proxies`)}
          </span>
        </div>

        <div className="cm-topbar-actions">
          <input
            type="search"
            className="cm-input"
            style={{ width: '220px' }}
            placeholder={t('Tìm kiếm proxy...', 'Search proxies...')}
            aria-label={t('Tìm kiếm proxy', 'Search proxies')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <Button variant="secondary" onClick={() => setImportOpen(true)}>
            {t('Nhập danh sách', 'Bulk Import')}
          </Button>
          <Button
            variant="secondary"
            loading={checkingAll}
            disabled={checkingAll || totalProxies === 0}
            onClick={handleCheckAll}
          >
            {checkingAll ? t('Đang kiểm tra...', 'Checking...') : t('Kiểm tra tất cả', 'Check All')}
          </Button>
          <Button variant="primary" onClick={() => setEditProxy(null)}>
            {t('+ Thêm proxy', '+ Add Proxy')}
          </Button>
        </div>
      </div>

      {/* Sub Bar (Defaults & Auto-assign) */}
      <div className="cm-subbar">
        <div className="cm-subbar-left">
          <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
            {t('Proxy mặc định cho profile mới:', 'Default proxy for new profiles:')}
          </label>
          <select
            className="cm-select"
            style={{ minWidth: '200px' }}
            disabled={updatingSetting}
            aria-label={t('Proxy mặc định cho profile mới', 'Default proxy for new profiles')}
            value={snapshot.settings?.default_proxy_id || ''}
            onChange={(e) => handleSaveDefaultProxy(e.target.value)}
          >
            <option value="">{t('Không (Trực tiếp)', 'None (Direct)')}</option>
            {(snapshot.proxies || []).map((px) => (
              <option key={px.id} value={px.id}>
                {px.name || px.server}
              </option>
            ))}
          </select>

          <label
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              marginLeft: '12px',
            }}
          >
            <input
              type="checkbox"
              className="cm-checkbox"
              disabled={updatingSetting}
              checked={!!snapshot.settings?.auto_assign_proxy}
              onChange={(e) => handleSaveAutoAssign(e.target.checked)}
            />
            {t('Tự động gán proxy khả dụng khi tạo profile', 'Auto-assign available proxy when creating profiles')}
          </label>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="cm-content">
        {totalProxies === 0 ? (
          <EmptyState
            title={t('Kho proxy đang trống', 'Proxy pool is empty')}
            description={t(
              'Thêm proxy mới hoặc nhập hàng loạt từ danh sách để sử dụng với các profile trình duyệt.',
              'Add a new proxy or bulk import from a list to use with browser profiles.'
            )}
            actionLabel={t('+ Thêm proxy', '+ Add Proxy')}
            onAction={() => setEditProxy(null)}
            secondaryLabel={t('Nhập danh sách', 'Bulk Import')}
            onSecondaryAction={() => setImportOpen(true)}
          />
        ) : filteredProxies.length === 0 ? (
          <div className="cm-vtable-no-rows">
            {t('Không tìm thấy proxy nào khớp với từ khóa', 'No proxies found matching')} &ldquo;{search}&rdquo;.
          </div>
        ) : (
          <VirtualTable<Proxy>
            data={filteredProxies}
            columns={columns}
            rowHeight={44}
            rowKey="id"
          />
        )}
      </div>

      {/* Proxy Create / Edit Modal */}
      {editProxy !== undefined && (
        <ProxyEditModal
          proxy={editProxy}
          onClose={() => setEditProxy(undefined)}
          onSaved={async () => {
            await onRefresh();
            setEditProxy(undefined);
          }}
          onMessage={onMessage}
        />
      )}

      {/* Proxy Import Modal */}
      {importOpen && (
        <ProxyImportModal
          onClose={() => setImportOpen(false)}
          onImported={async () => {
            await onRefresh();
            setImportOpen(false);
          }}
          onMessage={onMessage}
        />
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteProxyId !== null}
        title={t('Xác nhận xóa proxy', 'Confirm Proxy Deletion')}
        message={t(
          'Bạn có chắc chắn muốn xóa proxy này khỏi kho? Các profile đang gán proxy này sẽ tự động chuyển sang chế độ kết nối trực tiếp.',
          'Are you sure you want to delete this proxy from the pool? Profiles using this proxy will automatically switch to direct connection.'
        )}
        confirmText={t('Xóa proxy', 'Delete Proxy')}
        cancelText={t('Hủy bỏ', 'Cancel')}
        variant="danger"
        onConfirm={handleConfirmDelete}
        onCancel={() => setDeleteProxyId(null)}
      />
    </div>
  );
}
// -----------------------------------------------------------------------------
// ProxyEditModal
// -----------------------------------------------------------------------------
interface ProxyEditModalProps {
  proxy: Proxy | null;
  onClose: () => void;
  onSaved: () => void;
  onMessage: (message: string, level?: 'info' | 'warning' | 'error') => void;
}

function ProxyEditModal({ proxy, onClose, onSaved, onMessage }: ProxyEditModalProps) {
  const { t } = useI18n();
  const isEdit = proxy !== null;
  const nameId = useId();
  const serverId = useId();
  const userId = useId();
  const passId = useId();

  const [name, setName] = useState(proxy?.name || '');
  const [server, setServer] = useState(proxy?.server || '');
  const [username, setUsername] = useState(proxy?.username || '');
  const [password, setPassword] = useState('');
  const [clearPassword, setClearPassword] = useState(false);
  const [enabled, setEnabled] = useState(proxy ? proxy.enabled !== false : true);

  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  const hasExistingPassword = isEdit && (proxy?.has_password || proxy?.has_credentials);

  const handleTest = async () => {
    const srv = server.trim();
    if (!srv) {
      setTestResult({
        ok: false,
        message: t('Vui lòng nhập máy chủ trước khi kiểm tra.', 'Please enter a server before testing.'),
      });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      // Test proxy parameters
      const testPayload: Record<string, unknown> = {
        server: srv,
      };
      if (isEdit || username) testPayload.username = username;
      if (clearPassword) {
        testPayload.password = '';
      } else if (password) {
        testPayload.password = password;
      } else if (isEdit && proxy?.id) {
        testPayload.id = proxy.id;
      }

      const res = await request<ProxyCheck>('proxy.check', { proxy: testPayload });
      if (res.ok) {
        const ip = res.ip || '-';
        const country = res.country ? `(${res.country})` : '';
        const lat = res.latency_ms ? ` - ${Math.round(res.latency_ms)}ms` : '';
        setTestResult({
          ok: true,
          message: t(`Thành công: IP ${ip} ${country}${lat}`, `Success: IP ${ip} ${country}${lat}`),
        });
      } else {
        setTestResult({
          ok: false,
          message: t(
            `Thất bại: ${res.error || 'Không kết nối được'}`,
            `Failed: ${res.error || 'Unable to connect'}`
          ),
        });
      }
    } catch (err: unknown) {
      setTestResult({
        ok: false,
        message: t(
          `Lỗi: ${err instanceof Error ? err.message : String(err)}`,
          `Error: ${err instanceof Error ? err.message : String(err)}`
        ),
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const srv = server.trim();
    if (!srv) {
      onMessage(t('Vui lòng nhập địa chỉ máy chủ proxy.', 'Please enter the proxy server address.'), 'warning');
      return;
    }

    setSaving(true);
    try {
      const data: Record<string, unknown> = {
        name: name.trim() || srv,
        server: srv,
        enabled,
      };
      if (isEdit || username) data.username = username;

      if (isEdit && proxy) {
        data.id = proxy.id;
        // Password logic:
        // If explicit clear requested -> send empty string
        // If user typed a new password -> send new password
        // If left empty and not cleared -> omit password so backend preserves existing!
        if (clearPassword) {
          data.password = '';
        } else if (password) {
          data.password = password;
        }
      } else {
        if (password) {
          data.password = password;
        }
      }

      await request('proxy.save', { data });
      onMessage(
        isEdit
          ? t('Đã cập nhật proxy thành công.', 'Updated proxy successfully.')
          : t('Đã tạo proxy mới thành công.', 'Created new proxy successfully.'),
        'info'
      );
      onSaved();
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi lưu proxy: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to save proxy: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      busy={saving || testing}
      title={isEdit ? t('Chỉnh sửa Proxy', 'Edit Proxy') : t('Thêm Proxy Mới', 'Add New Proxy')}
      onClose={onClose}
      width={520}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
          <Button
            variant="secondary"
            loading={testing}
            disabled={testing || saving}
            onClick={handleTest}
          >
            {t('Kiểm tra kết nối', 'Test Connection')}
          </Button>

          <div style={{ display: 'flex', gap: '8px' }}>
            <Button variant="secondary" disabled={saving} onClick={onClose}>
              {t('Hủy bỏ', 'Cancel')}
            </Button>
            <Button variant="primary" loading={saving} disabled={saving} onClick={handleSave}>
              {t('Lưu proxy', 'Save Proxy')}
            </Button>
          </div>
        </div>
      }
    >
      <form onSubmit={handleSave}>
        <Field
          label={t('Tên gợi nhớ', 'Display Name')}
          htmlFor={nameId}
          hint={t('Ví dụ: Proxy US 01, SOCKS Residential...', 'E.g. Proxy US 01, SOCKS Residential...')}
        >
          <input
            id={nameId}
            type="text"
            className="cm-input"
            placeholder={t('Tên proxy...', 'Proxy name...')}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>

        <Field
          label={t('Máy chủ (*)', 'Server (*)')}
          htmlFor={serverId}
          hint={t(
            'Hỗ trợ scheme://host:port hoặc host:port (ví dụ socks5://127.0.0.1:1080)',
            'Supports scheme://host:port or host:port (e.g. socks5://127.0.0.1:1080)'
          )}
        >
          <input
            id={serverId}
            type="text"
            required
            className="cm-input"
            placeholder={t('host:port hoặc socks5://host:port', 'host:port or socks5://host:port')}
            value={server}
            onChange={(e) => setServer(e.target.value)}
          />
        </Field>

        <div className="cm-grid-2">
          <Field label={t('Tên người dùng (Tùy chọn)', 'Username (Optional)')} htmlFor={userId}>
            <input
              id={userId}
              type="text"
              className="cm-input"
              placeholder={t('Username...', 'Username...')}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>

          <Field
            label={t('Mật khẩu (Tùy chọn)', 'Password (Optional)')}
            htmlFor={passId}
            hint={
              hasExistingPassword
                ? clearPassword
                  ? t('Sẽ xóa mật khẩu cũ.', 'Existing password will be cleared.')
                  : t('Đang có mật khẩu. Để trống để giữ nguyên.', 'Password is set. Leave blank to keep unchanged.')
                : undefined
            }
          >
            <input
              id={passId}
              type="password"
              className="cm-input"
              placeholder={
                hasExistingPassword && !clearPassword
                  ? t('•••••••• (giữ nguyên)', '•••••••• (keep unchanged)')
                  : t('Password...', 'Password...')
              }
              disabled={clearPassword}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
        </div>

        {hasExistingPassword && (
          <div style={{ marginBottom: '12px' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                className="cm-checkbox"
                checked={clearPassword}
                onChange={(e) => {
                  setClearPassword(e.target.checked);
                  if (e.target.checked) setPassword('');
                }}
              />
              <span style={{ color: 'var(--danger)' }}>
                {t('Xóa mật khẩu đã lưu (đổi sang không dùng mật khẩu)', 'Clear saved password (switch to no password)')}
              </span>
            </label>
          </div>
        )}

        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              className="cm-checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            {t('Kích hoạt proxy này', 'Enable this proxy')}
          </label>
        </div>

        {testResult && (
          <div
            className={`cm-banner ${testResult.ok ? 'cm-banner-info' : 'cm-banner-danger'}`}
            style={{ marginTop: '8px' }}
          >
            {testResult.message}
          </div>
        )}
      </form>
    </Modal>
  );
}

// -----------------------------------------------------------------------------
// ProxyImportModal
// -----------------------------------------------------------------------------
interface ProxyImportModalProps {
  onClose: () => void;
  onImported: () => void;
  onMessage: (message: string, level?: 'info' | 'warning' | 'error') => void;
}

function ProxyImportModal({ onClose, onImported, onMessage }: ProxyImportModalProps) {
  const { t } = useI18n();
  const [text, setText] = useState('');
  const [importing, setImporting] = useState(false);

  const handleImport = async () => {
    const raw = text.trim();
    if (!raw) {
      onMessage(t('Vui lòng dán danh sách proxy cần nhập.', 'Please paste the proxy list to import.'), 'warning');
      return;
    }

    setImporting(true);
    try {
      const res = await request<Proxy[]>('proxy.import', { text: raw });
      onMessage(
        t(
          `Đã nhập thành công ${res.length} proxy vào kho.`,
          `Successfully imported ${res.length} proxies into the pool.`
        ),
        'info'
      );
      onImported();
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi nhập proxy: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to import proxies: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setImporting(false);
    }
  };

  return (
    <Modal
      busy={importing}
      title={t('Nhập danh sách Proxy', 'Bulk Import Proxies')}
      onClose={onClose}
      width={600}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', width: '100%' }}>
          <Button variant="secondary" disabled={importing} onClick={onClose}>
            {t('Hủy bỏ', 'Cancel')}
          </Button>
          <Button variant="primary" loading={importing} disabled={importing} onClick={handleImport}>
            {t('Phân tích & Thêm vào kho', 'Parse & Add to Pool')}
          </Button>
        </div>
      }
    >
      <div style={{ marginBottom: '12px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
        {t(
          'Nhập proxy mỗi dòng một địa chỉ. Hệ thống tự động nhận diện các định dạng sau:',
          'Enter one proxy per line. The system automatically recognizes these formats:'
        )}
        <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
          <li>host:port</li>
          <li>host:port:user:pass</li>
          <li>user:pass@host:port</li>
          <li>socks5://user:pass@host:port</li>
          <li>http://host:port</li>
        </ul>
      </div>

      <Field label={t('Danh sách proxy dạng văn bản:', 'Proxy list (plain text):')}>
        <textarea
          className="cm-textarea"
          style={{ minHeight: '180px', fontFamily: 'Consolas, monospace', fontSize: '12px' }}
          placeholder={"192.168.1.100:8080:username:password\nsocks5://127.0.0.1:1080\nproxy.example.com:3128"}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </Field>
    </Modal>
  );
}
