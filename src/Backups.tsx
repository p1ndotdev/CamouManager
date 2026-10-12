import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import type { PageProps, Backup, BackupState, BackupInspection, Profile } from './types';
import { request, savePath, openPath } from './api';
import {
  Button,
  Modal,
  Field,
  ConfirmDialog,
  VirtualTable,
  Column,
  EmptyState,
  formatDate,
  formatBytes,
} from './components';
import { useI18n } from './i18n';

export default function Backups({
  snapshot,
  onRefresh,
  onMessage,
  backupState: propBackupState,
}: PageProps & { backupState?: BackupState }) {
  const { t } = useI18n();
  const [backups, setBackups] = useState<Backup[]>([]);
  const [loadingBackups, setLoadingBackups] = useState(false);

  // Modals state
  const [createOpen, setCreateOpen] = useState(false);
  const [inspectModal, setInspectModal] = useState<{
    open: boolean;
    mode: 'inspect' | 'restore';
    initialPath?: string;
  }>({ open: false, mode: 'inspect' });
  const [deleteBackupPath, setDeleteBackupPath] = useState<string | null>(null);

  // Scheduler settings state
  const [intervalHours, setIntervalHours] = useState<number>(
    snapshot.settings?.backup_interval_hours ?? 0
  );
  const [retentionCount, setRetentionCount] = useState<number>(
    snapshot.settings?.backup_retention ?? 5
  );
  const [sessionPassword, setSessionPassword] = useState('');
  const [savingSchedule, setSavingSchedule] = useState(false);

  // Sync settings when snapshot updates
  useEffect(() => {
    if (snapshot.settings) {
      if (snapshot.settings.backup_interval_hours !== undefined) {
        setIntervalHours(snapshot.settings.backup_interval_hours);
      }
      if (snapshot.settings.backup_retention !== undefined) {
        setRetentionCount(snapshot.settings.backup_retention);
      }
    }
  }, [snapshot.settings]);

  // Current backup state
  const currentBackupState: BackupState = propBackupState ?? snapshot.backup ?? {
    state: 'disabled',
    message: '',
    last_at: '',
  };

  // Fetch backups list
  const fetchBackups = useCallback(async () => {
    setLoadingBackups(true);
    try {
      const list = await request<Backup[]>('backup.list');
      setBackups(list || []);
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi tải danh sách sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to load backup list: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setLoadingBackups(false);
    }
  }, [onMessage, t]);

  useEffect(() => {
    fetchBackups();
  }, [fetchBackups]);

  // Save schedule & session password
  const handleSaveSchedule = async () => {
    if (intervalHours > 0 && !sessionPassword && currentBackupState.state !== 'waiting' && currentBackupState.state !== 'running') {
      onMessage(
        t(
          'Lưu ý: Bạn đang bật lịch sao lưu tự động nhưng chưa nhập mật khẩu phiên RAM. Tiến trình sao lưu định kỳ yêu cầu mật khẩu để tự động mã hóa an toàn.',
          'Note: You enabled scheduled backups without entering a RAM session password. Scheduled backups require a password for automatic encryption.'
        ),
        'warning'
      );
    }

    setSavingSchedule(true);
    try {
      await request('settings.save', {
        data: {
          backup_interval_hours: intervalHours,
          backup_retention: retentionCount,
        },
      });

      if (sessionPassword) {
        await request('backup.set_password', { password: sessionPassword });
      }

      await onRefresh();
      await fetchBackups();
      onMessage(
        t(
          'Đã lưu cấu hình lịch sao lưu và mật khẩu phiên RAM.',
          'Saved backup schedule and RAM session password.'
        ),
        'info'
      );
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi lưu cấu hình sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to save backup settings: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setSavingSchedule(false);
    }
  };

  // Confirm delete backup
  const handleConfirmDelete = async () => {
    if (!deleteBackupPath) return;
    try {
      await request('backup.delete', { path: deleteBackupPath });
      setDeleteBackupPath(null);
      await fetchBackups();
      onMessage(t('Đã xóa bản sao lưu khỏi đĩa.', 'Deleted backup archive from disk.'), 'info');
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi xóa bản sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to delete backup: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    }
  };

  // Render scheduler banner text based on currentBackupState.state
  const renderStateBanner = () => {
    const { state, message, last_at } = currentBackupState;
    const lastStr = last_at ? formatDate(last_at) : t('Chưa có', 'None');

    if (state === 'disabled') {
      return (
        <div className="cm-banner cm-banner-info" style={{ marginBottom: '12px' }}>
          <strong>{t('[Đã tắt]', '[Disabled]')}</strong>{' '}
          {t(
            `Tự động sao lưu đang tắt (chu kỳ = 0 giờ). Lần sao lưu gần nhất: ${lastStr}.`,
            `Automatic backup is disabled (interval = 0 hours). Last backup: ${lastStr}.`
          )}
        </div>
      );
    }
    if (state === 'password_required') {
      return (
        <div className="cm-banner cm-banner-warning" style={{ marginBottom: '12px' }}>
          <strong>{t('[CẦN MẬT KHẨU PHIÊN]', '[SESSION PASSWORD REQUIRED]')}</strong>{' '}
          {t(
            `Lịch sao lưu tự động đang chờ bạn nhập mật khẩu phiên RAM để mã hóa AES-GCM an toàn. Hãy nhập mật khẩu ở ô bên dưới và bấm Lưu cấu hình. Lần sao lưu gần nhất: ${lastStr}.`,
            `Scheduled backup is waiting for a RAM session password for secure AES-GCM encryption. Enter a password below and click Save Settings. Last backup: ${lastStr}.`
          )}
        </div>
      );
    }
    if (state === 'waiting') {
      return (
        <div className="cm-banner cm-banner-info" style={{ marginBottom: '12px' }}>
          <strong>{t('[Đang chờ]', '[Waiting]')}</strong>{' '}
          {t(
            `Lịch tự động sao lưu đang hoạt động. Lần sao lưu gần nhất: ${lastStr}.`,
            `Automatic backup schedule is active. Last backup: ${lastStr}.`
          )}
        </div>
      );
    }
    if (state === 'running') {
      return (
        <div className="cm-banner cm-banner-info" style={{ marginBottom: '12px' }}>
          <strong>{t('[Đang chạy]', '[Running]')}</strong>{' '}
          {t('Tiến trình sao lưu định kỳ đang thực hiện...', 'Scheduled backup is currently in progress...')}
        </div>
      );
    }
    if (state === 'error') {
      return (
        <div className="cm-banner cm-banner-danger" style={{ marginBottom: '12px' }}>
          <strong>{t('[LỖI]', '[ERROR]')}</strong>{' '}
          {message || t('Có lỗi xảy ra trong quá trình tự động sao lưu.', 'An error occurred during automatic backup.')}{' '}
          ({t(`Lần thành công gần nhất: ${lastStr}`, `Last successful backup: ${lastStr}`)}).
        </div>
      );
    }
    return null;
  };

  // Table columns
  const columns: Column<Backup>[] = useMemo(
    () => [
      {
        key: 'filename',
        header: t('Tên file sao lưu', 'Backup File'),
        flex: 2,
        render: (b) => (
          <span style={{ fontWeight: 600, fontFamily: 'Consolas, monospace', fontSize: '12px' }} title={b.path}>
            {b.filename || b.path}
          </span>
        ),
      },
      {
        key: 'size',
        header: t('Dung lượng', 'Size'),
        width: 100,
        render: (b) => <span>{formatBytes(b.size)}</span>,
      },
      {
        key: 'created_at',
        header: t('Thời gian tạo', 'Created At'),
        width: 150,
        render: (b) => <span style={{ color: 'var(--text-secondary)' }}>{formatDate(b.created_at)}</span>,
      },
      {
        key: 'profiles_count',
        header: t('Số profile', 'Profiles'),
        width: 90,
        render: (b) => (
          <span>
            {b.profiles_count !== null
              ? t(`${b.profiles_count} profile`, `${b.profiles_count} profile${b.profiles_count === 1 ? '' : 's'}`)
              : '-'}
          </span>
        ),
      },
      {
        key: 'is_encrypted',
        header: t('Mã hóa', 'Encryption'),
        width: 130,
        render: (b) =>
          b.is_encrypted ? (
            <span style={{ color: 'var(--success)', fontWeight: 600 }}>{t('AES-GCM (Có)', 'AES-GCM (Yes)')}</span>
          ) : (
            <span style={{ color: 'var(--text-muted)' }}>{t('Không mã hóa', 'Unencrypted')}</span>
          ),
      },
      {
        key: 'is_scheduled',
        header: t('Loại', 'Type'),
        width: 90,
        render: (b) => (
          <span style={{ color: 'var(--text-secondary)' }}>
            {b.is_scheduled ? t('Tự động', 'Scheduled') : t('Thủ công', 'Manual')}
          </span>
        ),
      },
      {
        key: 'actions',
        header: t('Thao tác', 'Actions'),
        width: 190,
        align: 'right',
        render: (b) => (
          <div style={{ display: 'inline-flex', gap: '4px' }}>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setInspectModal({ open: true, mode: 'restore', initialPath: b.path })}
            >
              {t('Khôi phục', 'Restore')}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setInspectModal({ open: true, mode: 'inspect', initialPath: b.path })}
            >
              {t('Xem', 'Inspect')}
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => setDeleteBackupPath(b.path)}
            >
              {t('Xóa', 'Delete')}
            </Button>
          </div>
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
          <h1 className="cm-topbar-title">{t('Sao lưu & Khôi phục', 'Backup & Restore')}</h1>
          <span className="cm-pill-counter">
            {t(`${backups.length} bản sao lưu`, `${backups.length} backup${backups.length === 1 ? '' : 's'}`)}
          </span>
        </div>

        <div className="cm-topbar-actions">
          <Button
            variant="secondary"
            loading={loadingBackups}
            disabled={loadingBackups}
            onClick={fetchBackups}
          >
            {t('Làm mới', 'Refresh')}
          </Button>
          <Button
            variant="secondary"
            onClick={() => setInspectModal({ open: true, mode: 'inspect' })}
          >
            {t('Kiểm tra file sao lưu', 'Inspect Backup File')}
          </Button>
          <Button
            variant="secondary"
            onClick={() => setInspectModal({ open: true, mode: 'restore' })}
          >
            {t('Khôi phục từ file', 'Restore from File')}
          </Button>
          <Button variant="primary" onClick={() => setCreateOpen(true)}>
            {t('+ Tạo bản sao lưu', '+ Create Backup')}
          </Button>
        </div>
      </div>

      {/* Scheduler Configuration Card */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-card)' }}>
        {renderStateBanner()}

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600 }}>
              {t('Tự động sao lưu mỗi:', 'Auto-backup every:')}
            </label>
            <input
              type="number"
              min={0}
              max={168}
              className="cm-input"
              style={{ width: '70px' }}
              aria-label={t('Tự động sao lưu mỗi (giờ)', 'Auto-backup interval (hours)')}
              value={intervalHours}
              onChange={(e) => setIntervalHours(parseInt(e.target.value, 10) || 0)}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              {t('giờ (0 = tắt)', 'hours (0 = off)')}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600 }}>{t('Lưu giữ:', 'Retain:')}</label>
            <input
              type="number"
              min={1}
              max={50}
              className="cm-input"
              style={{ width: '60px' }}
              aria-label={t('Số bản sao lưu lưu giữ', 'Backup retention count')}
              value={retentionCount}
              onChange={(e) => setRetentionCount(parseInt(e.target.value, 10) || 5)}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              {t('bản gần nhất', 'latest backups')}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600 }}>
              {t('Mật khẩu phiên (RAM):', 'Session Password (RAM):')}
            </label>
            <input
              type="password"
              className="cm-input"
              style={{ width: '180px' }}
              aria-label={t('Mật khẩu phiên (RAM)', 'Session Password (RAM)')}
              placeholder={t('Bắt buộc để tự động mã hóa...', 'Required for auto-encryption...')}
              value={sessionPassword}
              onChange={(e) => setSessionPassword(e.target.value)}
            />
          </div>

          <Button
            variant="secondary"
            loading={savingSchedule}
            disabled={savingSchedule}
            onClick={handleSaveSchedule}
          >
            {t('Lưu cấu hình', 'Save Settings')}
          </Button>
          <Button
            variant="ghost"
            disabled={savingSchedule || currentBackupState.state === 'password_required' || currentBackupState.state === 'disabled'}
            onClick={async () => {
              setSavingSchedule(true);
              try {
                await request('backup.set_password', { password: '' });
                setSessionPassword('');
                await onRefresh();
                onMessage(
                  t(
                    'Đã quên mật khẩu phiên. Lịch sao lưu mã hóa sẽ chờ mật khẩu mới.',
                    'Cleared session password. Encrypted backup schedule will wait for a new password.'
                  ),
                  'info'
                );
              } catch (error) {
                onMessage(String(error), 'error');
              } finally {
                setSavingSchedule(false);
              }
            }}
          >
            {t('Quên mật khẩu phiên', 'Forget Session Password')}
          </Button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="cm-content">
        {backups.length === 0 ? (
          <EmptyState
            title={t('Chưa có bản sao lưu nào', 'No backups yet')}
            description={t(
              'Tạo bản sao lưu để bảo vệ cookie, tiện ích mở rộng và cấu hình fingerprint của các profile.',
              'Create a backup to protect cookies, extensions, and fingerprint settings of your profiles.'
            )}
            actionLabel={t('+ Tạo bản sao lưu', '+ Create Backup')}
            onAction={() => setCreateOpen(true)}
            secondaryLabel={t('Khôi phục từ file', 'Restore from File')}
            onSecondaryAction={() => setInspectModal({ open: true, mode: 'restore' })}
          />
        ) : (
          <VirtualTable<Backup>
            data={backups}
            columns={columns}
            rowHeight={44}
            rowKey="path"
          />
        )}
      </div>

      {/* Create Backup Modal */}
      {createOpen && (
        <BackupCreateModal
          profiles={snapshot.profiles || []}
          onClose={() => setCreateOpen(false)}
          onCreated={async () => {
            await fetchBackups();
            await onRefresh();
            setCreateOpen(false);
          }}
          onMessage={onMessage}
        />
      )}

      {/* Inspect & Restore Modal */}
      {inspectModal.open && (
        <BackupInspectRestoreModal
          mode={inspectModal.mode}
          initialPath={inspectModal.initialPath}
          onClose={() => setInspectModal({ open: false, mode: 'inspect' })}
          onRestored={async () => {
            await fetchBackups();
            await onRefresh();
            setInspectModal({ open: false, mode: 'inspect' });
          }}
          onMessage={onMessage}
        />
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteBackupPath !== null}
        title={t('Xác nhận xóa bản sao lưu', 'Confirm Backup Deletion')}
        message={t(
          `Bạn có chắc chắn muốn xóa vĩnh viễn file sao lưu này khỏi đĩa?\n\n${deleteBackupPath || ''}`,
          `Are you sure you want to permanently delete this backup file from disk?\n\n${deleteBackupPath || ''}`
        )}
        confirmText={t('Xóa file sao lưu', 'Delete Backup File')}
        cancelText={t('Hủy bỏ', 'Cancel')}
        variant="danger"
        onConfirm={handleConfirmDelete}
        onCancel={() => setDeleteBackupPath(null)}
      />
    </div>
  );
}
// -----------------------------------------------------------------------------
// BackupCreateModal
// -----------------------------------------------------------------------------
interface BackupCreateModalProps {
  profiles: Profile[];
  onClose: () => void;
  onCreated: () => void;
  onMessage: (message: string, level?: 'info' | 'warning' | 'error') => void;
}

function BackupCreateModal({ profiles, onClose, onCreated, onMessage }: BackupCreateModalProps) {
  const { t } = useI18n();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(
    () => new Set(profiles.map((p) => p.id))
  );
  const [destination, setDestination] = useState('');
  const [password, setPassword] = useState('');
  const [creating, setCreating] = useState(false);
  const [confirmUnencrypted, setConfirmUnencrypted] = useState(false);

  const toggleProfile = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleBrowseDestination = async () => {
    try {
      const selected = await savePath({
        defaultPath: 'camoumanager_backup.zip',
        filters: [
          {
            name: t('File sao lưu (*.zip, *.camoubak)', 'Backup Archives (*.zip, *.camoubak)'),
            extensions: ['zip', 'camoubak'],
          },
        ],
      });
      if (selected) {
        setDestination(selected);
      }
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi chọn đường dẫn: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to select destination: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    }
  };

  const executeCreate = async () => {
    setCreating(true);
    try {
      const outPath = await request<string>('backup.create', {
        ids: Array.from(selectedIds),
        destination: destination.trim() || undefined,
        password: password,
      });
      onMessage(
        t(
          `Đã tạo bản sao lưu thành công tại: ${outPath}`,
          `Created backup successfully at: ${outPath}`
        ),
        'info'
      );
      onCreated();
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi tạo bản sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to create backup: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setCreating(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedIds.size === 0) {
      onMessage(
        t('Vui lòng chọn ít nhất một profile để sao lưu.', 'Please select at least one profile to back up.'),
        'warning'
      );
      return;
    }

    // Unencrypted warning confirmation if password is empty
    if (!password) {
      setConfirmUnencrypted(true);
      return;
    }

    executeCreate();
  };

  return (
    <>
      <Modal
        busy={creating}
        title={t('Tạo bản sao lưu Profile', 'Create Profile Backup')}
        onClose={onClose}
        width={560}
        footer={
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', width: '100%' }}>
            <Button variant="secondary" disabled={creating} onClick={onClose}>
              {t('Hủy bỏ', 'Cancel')}
            </Button>
            <Button variant="primary" loading={creating} disabled={creating} onClick={handleSubmit}>
              {t('Tạo bản sao lưu', 'Create Backup')}
            </Button>
          </div>
        }
      >
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600 }}>
                {t(
                  `Chọn các profile cần sao lưu (${selectedIds.size} / ${profiles.length}):`,
                  `Select profiles to back up (${selectedIds.size} / ${profiles.length}):`
                )}
              </label>
              <div style={{ display: 'flex', gap: '6px' }}>
                <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set(profiles.map((p) => p.id)))}>
                  {t('Chọn tất cả', 'Select All')}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
                  {t('Bỏ chọn', 'Deselect All')}
                </Button>
              </div>
            </div>

            <div className="cm-list-box" style={{ maxHeight: '180px' }}>
              {profiles.length === 0 ? (
                <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  {t('Chưa có profile nào trong hệ thống.', 'No profiles in the system.')}
                </div>
              ) : (
                profiles.map((p) => {
                  const checked = selectedIds.has(p.id);
                  return (
                    <label
                      key={p.id}
                      className="cm-list-item"
                      style={{ cursor: 'pointer', userSelect: 'none' }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <input
                          type="checkbox"
                          className="cm-checkbox"
                          checked={checked}
                          onChange={() => toggleProfile(p.id)}
                        />
                        <span style={{ fontWeight: 600 }}>{p.name || p.id}</span>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'Consolas, monospace' }}>
                        ID: {p.id.slice(0, 8)}
                      </span>
                    </label>
                  );
                })
              )}
            </div>
          </div>

          <Field
            label={t('Thư mục / Tên file lưu trữ (Tùy chọn)', 'Destination Folder / File Name (Optional)')}
            hint={t(
              'Để trống sẽ tự động lưu vào thư mục backups mặc định của hệ thống.',
              'Leave blank to save automatically in the default system backups folder.'
            )}
          >
            <div style={{ display: 'flex', gap: '6px' }}>
              <input
                type="text"
                className="cm-input"
                style={{ flex: 1 }}
                placeholder={t('Mặc định...', 'Default...')}
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
              />
              <Button variant="secondary" onClick={handleBrowseDestination}>
                {t('Chọn vị trí...', 'Browse...')}
              </Button>
            </div>
          </Field>

          <Field
            label={t(
              'Mật khẩu mã hóa (Tùy chọn - Mã hóa AES-GCM an toàn)',
              'Encryption Password (Optional - Secure AES-GCM Encryption)'
            )}
            hint={t(
              'Nhập mật khẩu để bảo vệ toàn bộ cookie và thông tin phiên duyệt khỏi lộ lọt.',
              'Enter a password to protect all cookies and session data from unauthorized access.'
            )}
          >
            <input
              type="password"
              className="cm-input"
              placeholder={t('Nhập mật khẩu mã hóa...', 'Enter encryption password...')}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>

          <div className="cm-banner cm-banner-warning" style={{ marginTop: '12px' }}>
            {t(
              'Lưu ý bảo mật: Bản sao lưu chứa dữ liệu phiên duyệt web, cookie và thông tin proxy đã gán. Nếu đặt mật khẩu, file sẽ được mã hóa an toàn bằng AES-GCM. Nếu để trống mật khẩu, file sẽ được lưu ở dạng zip thông thường không mã hóa.',
              'Security notice: Backups contain browsing session data, cookies, and assigned proxy details. If a password is set, the archive is encrypted with AES-GCM. If left blank, it will be saved as an unencrypted standard zip file.'
            )}
          </div>
        </form>
      </Modal>

      {/* Explicit Unencrypted Confirmation Dialog */}
      <ConfirmDialog
        open={confirmUnencrypted}
        title={t('Cảnh báo sao lưu không mã hóa', 'Unencrypted Backup Warning')}
        variant="danger"
        confirmText={t('Xác nhận tạo không mã hóa', 'Create Unencrypted Backup')}
        cancelText={t('Quay lại đặt mật khẩu', 'Go Back & Set Password')}
        message={t(
          'CẢNH BÁO BẢO MẬT: Bạn chưa nhập mật khẩu cho bản sao lưu.\n\n' +
            'Toàn bộ cookie, phiên đăng nhập và proxy sẽ được lưu ở dạng zip thông thường không được bảo vệ.\n' +
            'Bất kỳ ai tiếp cận file này đều có thể trích xuất cookie và tài khoản của bạn.\n\n' +
            'Bạn có chắc chắn muốn tạo bản sao lưu KHÔNG MÃ HÓA?',
          'SECURITY WARNING: You have not set a password for this backup.\n\n' +
            'All cookies, login sessions, and proxy details will be stored in an unprotected standard zip archive.\n' +
            'Anyone with access to this file can extract your cookies and accounts.\n\n' +
            'Are you sure you want to create an UNENCRYPTED backup?'
        )}
        onConfirm={() => {
          setConfirmUnencrypted(false);
          executeCreate();
        }}
        onCancel={() => setConfirmUnencrypted(false)}
      />
    </>
  );
}

// -----------------------------------------------------------------------------
// BackupInspectRestoreModal
// -----------------------------------------------------------------------------
interface BackupInspectRestoreModalProps {
  mode: 'inspect' | 'restore';
  initialPath?: string;
  onClose: () => void;
  onRestored: () => void;
  onMessage: (message: string, level?: 'info' | 'warning' | 'error') => void;
}

function BackupInspectRestoreModal({
  mode,
  initialPath = '',
  onClose,
  onRestored,
  onMessage,
}: BackupInspectRestoreModalProps) {
  const { t } = useI18n();
  const [filePath, setFilePath] = useState(initialPath);
  const [password, setPassword] = useState('');
  const [inspecting, setInspecting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [inspection, setInspection] = useState<BackupInspection | null>(null);
  const [confirmMissingVersions, setConfirmMissingVersions] = useState(false);
  const reqRef = useRef(0);
  useEffect(() => () => {
    reqRef.current += 1;
  }, []);

  const handleBrowseFile = async () => {
    if (inspecting || restoring) return;
    try {
      const selected = await openPath({
        filters: [
          {
            name: t('File sao lưu (*.zip, *.camoubak)', 'Backup Archives (*.zip, *.camoubak)'),
            extensions: ['zip', 'camoubak'],
          },
          { name: t('Tất cả file (*)', 'All Files (*)'), extensions: ['*'] },
        ],
      });
      if (selected) {
        reqRef.current += 1;
        setFilePath(selected);
        setInspection(null);
        setConfirmMissingVersions(false);
      }
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi chọn file: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to select file: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    }
  };

  const handleInspect = async (): Promise<BackupInspection | null> => {
    if (inspecting || restoring) return null;
    const p = filePath.trim();
    if (!p) {
      onMessage(
        t('Vui lòng chọn hoặc nhập đường dẫn file sao lưu.', 'Please select or enter a backup file path.'),
        'warning'
      );
      return null;
    }

    const reqId = ++reqRef.current;
    setInspecting(true);
    setConfirmMissingVersions(false);
    try {
      const res = await request<BackupInspection>('backup.inspect', {
        path: p,
        password: password,
      });
      if (reqId !== reqRef.current) return null;
      setInspection(res);
      onMessage(t('Đã kiểm tra file sao lưu thành công.', 'Inspected backup file successfully.'), 'info');
      return res;
    } catch (err: unknown) {
      if (reqId !== reqRef.current) return null;
      setInspection(null);
      onMessage(
        t(
          `Lỗi kiểm tra file sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to inspect backup file: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
      return null;
    } finally {
      if (reqId === reqRef.current) setInspecting(false);
    }
  };

  const executeRestore = async () => {
    if (inspecting || restoring) return;
    const p = filePath.trim();
    if (!p) {
      onMessage(
        t('Vui lòng chọn file sao lưu cần khôi phục.', 'Please select a backup file to restore.'),
        'warning'
      );
      return;
    }

    setRestoring(true);
    try {
      const restored = await request<Profile[]>('backup.restore', {
        path: p,
        password: password,
      });
      const names = restored.map((p) => p.name || p.id).join(', ');
      onMessage(
        t(
          `Đã khôi phục an toàn ${restored.length} profile với ID mới: ${names}`,
          `Safely restored ${restored.length} profile(s) with new IDs: ${names}`
        ),
        'info'
      );
      onRestored();
    } catch (err: unknown) {
      onMessage(
        t(
          `Lỗi khôi phục sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to restore backup: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setRestoring(false);
    }
  };

  const handleRestoreClick = async () => {
    const info = await handleInspect();
    if (!info) return;
    if (info.missing_versions && info.missing_versions.length > 0) {
      setConfirmMissingVersions(true);
      return;
    }
    await executeRestore();
  };

  return (
    <>
      <Modal
        busy={inspecting || restoring}
        title={
          mode === 'restore'
            ? t('Khôi phục Profile từ Bản sao lưu', 'Restore Profiles from Backup')
            : t('Kiểm tra File Sao lưu', 'Inspect Backup File')
        }
        onClose={() => {
          if (!inspecting && !restoring) onClose();
        }}
        width={640}
        footer={
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
            <Button
              variant="secondary"
              loading={inspecting}
              disabled={inspecting || restoring}
              onClick={handleInspect}
            >
              {t('Kiểm tra nội dung file', 'Inspect Archive Contents')}
            </Button>

            <div style={{ display: 'flex', gap: '8px' }}>
              <Button variant="secondary" disabled={inspecting || restoring} onClick={onClose}>
                {t('Đóng', 'Close')}
              </Button>
              {mode === 'restore' && (
                <Button
                  variant="primary"
                  loading={restoring}
                  disabled={restoring || inspecting}
                  onClick={handleRestoreClick}
                >
                  {t('Khôi phục tất cả Profile', 'Restore All Profiles')}
                </Button>
              )}
            </div>
          </div>
        }
      >
        <Field label={t('Đường dẫn file sao lưu (.zip / .camoubak):', 'Backup file path (.zip / .camoubak):')}>
          <div style={{ display: 'flex', gap: '6px' }}>
            <input
              type="text"
              className="cm-input"
              style={{ flex: 1, fontFamily: 'Consolas, monospace', fontSize: '12px' }}
              placeholder={t('Chọn hoặc nhập đường dẫn file...', 'Select or enter file path...')}
              value={filePath}
              disabled={inspecting || restoring}
              onChange={(e) => {
                reqRef.current += 1;
                setFilePath(e.target.value);
                setInspection(null);
                setConfirmMissingVersions(false);
              }}
            />
            <Button variant="secondary" disabled={inspecting || restoring} onClick={handleBrowseFile}>
              {t('Chọn file...', 'Browse...')}
            </Button>
          </div>
        </Field>

        <Field
          label={t('Mật khẩu giải mã (nếu file có đặt mật khẩu):', 'Decryption password (if encrypted):')}
          hint={t(
            'Nếu file không đặt mật khẩu mã hóa, bạn có thể để trống trường này.',
            'Leave blank if the backup file is not password-protected.'
          )}
        >
          <input
            type="password"
            className="cm-input"
            placeholder={t('Mật khẩu giải mã...', 'Decryption password...')}
            value={password}
            disabled={inspecting || restoring}
            onChange={(e) => {
              reqRef.current += 1;
              setPassword(e.target.value);
              setInspection(null);
              setConfirmMissingVersions(false);
            }}
          />
        </Field>

        {/* Inspection Result Presentation */}
        {inspection && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, marginBottom: '8px' }}>
              {t('Thông tin chi tiết bản sao lưu:', 'Backup archive details:')}
            </div>

            {/* Warnings */}
            {(inspection.warning || inspection.compatibility_warning || (inspection.missing_versions && inspection.missing_versions.length > 0)) && (
              <div className="cm-banner cm-banner-danger" style={{ marginBottom: '12px' }}>
                {inspection.warning && <div>• {inspection.warning}</div>}
                {inspection.compatibility_warning && <div>• {inspection.compatibility_warning}</div>}
                {inspection.missing_versions && inspection.missing_versions.length > 0 && (
                  <div>
                    •{' '}
                    {t(
                      `Phiên bản Camoufox chưa cài đặt trên máy: ${inspection.missing_versions.join(', ')}. Khôi phục giữ nguyên phiên bản đã ghim; cần cài phiên bản tương ứng trước khi chạy profile.`,
                      `Camoufox versions not installed on this machine: ${inspection.missing_versions.join(', ')}. Restore preserves pinned versions; install the corresponding version before running the profile.`
                    )}
                  </div>
                )}
              </div>
            )}

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '8px',
                padding: '12px',
                backgroundColor: 'var(--hover)',
                borderRadius: '6px',
                fontSize: '12px',
                marginBottom: '12px',
              }}
            >
              <div>
                <strong>{t('Thời gian tạo:', 'Created at:')}</strong> {formatDate(inspection.created_at)}
              </div>
              <div>
                <strong>{t('Mã hóa:', 'Encryption:')}</strong>{' '}
                {inspection.is_encrypted ? (
                  <span style={{ color: 'var(--success)', fontWeight: 600 }}>{t('Có (AES-GCM)', 'Yes (AES-GCM)')}</span>
                ) : (
                  <span>{t('Không mã hóa', 'Unencrypted')}</span>
                )}
              </div>
              <div>
                <strong>{t('Số profile:', 'Profiles:')}</strong> {inspection.profiles_count ?? (inspection.profiles || []).length}
              </div>
              <div>
                <strong>{t('Dung lượng:', 'Total size:')}</strong> {formatBytes(inspection.total_size)}
              </div>
            </div>

            {/* Profiles preview list */}
            {inspection.profiles && inspection.profiles.length > 0 && (
              <div>
                <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '6px' }}>
                  {t('Danh sách profile đóng gói trong file:', 'Profiles included in archive:')}
                </div>
                <div className="cm-list-box" style={{ maxHeight: '140px' }}>
                  {inspection.profiles.map((p, idx) => (
                    <div key={p.id || idx} className="cm-list-item" style={{ fontSize: '12px' }}>
                      <span style={{ fontWeight: 600 }}>{p.name || p.id}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {p.browser_version ? `v${p.browser_version}` : 'Camoufox'} |{' '}
                        {p.proxy_name || (p.proxy_id ? t('Có Proxy', 'Has Proxy') : t('Trực tiếp', 'Direct'))}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Missing Versions Warning Confirmation */}
      <ConfirmDialog
        open={confirmMissingVersions && Boolean(inspection?.missing_versions?.length)}
        title={t('Cảnh báo thiếu phiên bản Camoufox', 'Missing Camoufox Versions Warning')}
        variant="primary"
        confirmText={t('Tiếp tục khôi phục', 'Continue Restore')}
        cancelText={t('Hủy bỏ', 'Cancel')}
        loading={restoring}
        message={t(
          `Bản sao lưu yêu cầu các phiên bản Camoufox chưa có trên máy này:\n` +
            `${(inspection?.missing_versions || []).join(', ')}\n\n` +
            `Khôi phục giữ nguyên phiên bản đã ghim. Bạn cần cài phiên bản tương ứng trước khi chạy profile. Bạn có muốn tiếp tục khôi phục?`,
          `This backup requires Camoufox versions not installed on this machine:\n` +
            `${(inspection?.missing_versions || []).join(', ')}\n\n` +
            `Restore preserves pinned versions. You must install the corresponding version before running the profile. Do you want to continue restoring?`
        )}
        onConfirm={() => {
          if (!inspection) return;
          setConfirmMissingVersions(false);
          executeRestore();
        }}
        onCancel={() => setConfirmMissingVersions(false)}
      />
    </>
  );
}
