import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { openPath, request, savePath } from './api';
import { Button, Column, ConfirmDialog, EmptyState, Field, Modal, StatusBadge, VirtualTable } from './components';
import ProfileEditor from './ProfileEditor';
import { useI18n } from './i18n';
import type {
  AppSnapshot,
  BackupInspection,
  BatchResult,
  MessageLevel,
  Profile,
  Status,
} from './types';

export interface ProfilesProps {
  snapshot: AppSnapshot;
  statuses: Record<string, Status>;
  runningCount: number;
  onRefresh: () => Promise<void>;
  onMessage: (message: string, level?: MessageLevel) => void;
  onNavigate?: (section: 'profiles' | 'proxies' | 'backups' | 'settings') => void;
}

type SortMode = 'name_asc' | 'name_desc' | 'newest' | 'oldest';

export default function Profiles({
  snapshot,
  statuses,
  runningCount,
  onRefresh,
  onMessage,
  onNavigate,
}: ProfilesProps) {
  const { t, locale } = useI18n();
  // Search & filter state (150ms debounce for text inputs)
  const [searchInput, setSearchInput] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [groupFilter, setGroupFilter] = useState('ALL');
  const [tagFilterInput, setTagFilterInput] = useState('');
  const [debouncedTagFilter, setDebouncedTagFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [proxyFilter, setProxyFilter] = useState('ALL');
  const [sortMode, setSortMode] = useState<SortMode>('name_asc');

  // Selection state preserved across filter/status updates
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [busyAction, setBusyAction] = useState(false);

  // Row / View menus
  const [rowMenu, setRowMenu] = useState<{ profileId: string; x: number; y: number } | null>(null);
  const [viewMenuPos, setViewMenuPos] = useState<{ x: number; y: number } | null>(null);

  // Dialog states
  const [editorState, setEditorState] = useState<{ open: boolean; profile: Profile | null }>({
    open: false,
    profile: null,
  });
  const [cloneTarget, setCloneTarget] = useState<Profile | null>(null);
  const [cloneName, setCloneName] = useState('');
  const [cloneFull, setCloneFull] = useState(false);
  const [cloning, setCloning] = useState(false);

  const [fpTarget, setFpTarget] = useState<Profile | null>(null);
  const [fpLoading, setFpLoading] = useState(false);
  const [fpConfirmRegen, setFpConfirmRegen] = useState(false);
  const [fpRegenerating, setFpRegenerating] = useState(false);

  const [deleteIds, setDeleteIds] = useState<string[] | null>(null);
  const [deleting, setDeleting] = useState(false);

  const [batchProxyOpen, setBatchProxyOpen] = useState(false);
  const [batchProxyId, setBatchProxyId] = useState('');
  const [batchProxySaving, setBatchProxySaving] = useState(false);

  const [batchTagsOpen, setBatchTagsOpen] = useState(false);
  const [batchTagsText, setBatchTagsText] = useState('');
  const [batchTagsSaving, setBatchTagsSaving] = useState(false);

  const [batchGroupOpen, setBatchGroupOpen] = useState(false);
  const [batchGroupText, setBatchGroupText] = useState('');
  const [batchGroupSaving, setBatchGroupSaving] = useState(false);

  const [backupModalIds, setBackupModalIds] = useState<string[] | null>(null);
  const [backupSelectedSet, setBackupSelectedSet] = useState<Set<string>>(() => new Set());
  const [backupDest, setBackupDest] = useState('');
  const [backupPassword, setBackupPassword] = useState('');
  const [backupUnencryptedConfirm, setBackupUnencryptedConfirm] = useState(false);
  const [backupCreating, setBackupCreating] = useState(false);

  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restorePath, setRestorePath] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [restoreInspection, setRestoreInspection] = useState<BackupInspection | null>(null);
  const [restoreInspecting, setRestoreInspecting] = useState(false);
  const [restoreConfirmMissing, setRestoreConfirmMissing] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const restoreReqRef = useRef(0);
  useEffect(() => () => {
    restoreReqRef.current += 1;
  }, []);

  const [helpOpen, setHelpOpen] = useState(false);

  // Debounce search query 150ms
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedSearch(searchInput.trim().toLowerCase());
    }, 150);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  // Debounce tag filter 150ms
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedTagFilter(tagFilterInput.trim().toLowerCase());
    }, 150);
    return () => window.clearTimeout(timer);
  }, [tagFilterInput]);

  // Prune deleted profile IDs from selection while preserving existing selections
  useEffect(() => {
    const validIds = new Set(snapshot.profiles.map((p) => p.id));
    setSelectedIds((prev) => {
      let changed = false;
      for (const id of prev) {
        if (!validIds.has(id)) {
          changed = true;
          break;
        }
      }
      if (!changed) return prev;
      const next = new Set<string>();
      for (const id of prev) {
        if (validIds.has(id)) next.add(id);
      }
      return next;
    });
  }, [snapshot.profiles]);

  // Memoized row cache so unchanged profiles keep exact object references across status ticks
  const rowCacheRef = useRef<Map<string, { base: Profile; status: Status | undefined; proxyName: string; merged: Profile }>>(
    new Map()
  );

  const proxyNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const px of snapshot.proxies) {
      map.set(px.id, px.name || px.server || px.id);
    }
    return map;
  }, [snapshot.proxies]);

  const profilesWithStatus = useMemo(() => {
    const nextCache = new Map<string, { base: Profile; status: Status | undefined; proxyName: string; merged: Profile }>();
    const result: Profile[] = [];

    for (const p of snapshot.profiles) {
      const st = statuses[p.id];
      const resolvedProxyName = p.proxy_id ? (proxyNameById.get(p.proxy_id) || p.proxy_name || '') : '';
      const cached = rowCacheRef.current.get(p.id);

      if (
        cached &&
        cached.base === p &&
        cached.status === st &&
        cached.proxyName === resolvedProxyName
      ) {
        nextCache.set(p.id, cached);
        result.push(cached.merged);
        continue;
      }

      const merged: Profile = {
        ...p,
        proxy_name: resolvedProxyName,
        state: st ? st.state : (p.state || 'stopped'),
        pid: st ? st.pid : (p.pid ?? null),
        cpu_percent: st ? st.cpu_percent : (p.cpu_percent ?? 0),
        memory_mb: st ? st.memory_mb : (p.memory_mb ?? 0),
        error: st ? st.error : (p.error ?? ''),
        location: st?.egress_ip !== undefined && st.egress_ip !== p.location.ip ? { ...p.location, ip: st.egress_ip } : p.location,
      };
      nextCache.set(p.id, { base: p, status: st, proxyName: resolvedProxyName, merged });
      result.push(merged);
    }

    rowCacheRef.current = nextCache;
    return result;
  }, [snapshot.profiles, statuses, proxyNameById]);

  // Global running count independent of filters
  const globalRunningCount = useMemo(() => {
    if (typeof runningCount === 'number' && runningCount >= 0) {
      return runningCount;
    }
    let count = 0;
    for (const p of profilesWithStatus) {
      if (p.state === 'running') count += 1;
    }
    return count;
  }, [runningCount, profilesWithStatus]);

  const availableGroups = useMemo(() => {
    const set = new Set<string>();
    for (const p of snapshot.profiles) {
      const g = (p.group || '').trim();
      if (g) set.add(g);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b, locale));
  }, [snapshot.profiles, locale]);

  // Filter and sort profiles (after live status overlay)
  const filteredProfiles = useMemo(() => {
    const rows: Profile[] = [];
    for (const p of profilesWithStatus) {
      const state = p.state || 'stopped';

      if (debouncedSearch) {
        const nameMatch = (p.name || '').toLowerCase().includes(debouncedSearch);
        const noteMatch = (p.note || '').toLowerCase().includes(debouncedSearch);
        const groupMatch = (p.group || '').toLowerCase().includes(debouncedSearch);
        const idMatch = p.id.slice(0, 8).toLowerCase().includes(debouncedSearch);
        const tagMatch = (p.tags || []).some((t) => t.toLowerCase().includes(debouncedSearch));
        if (!nameMatch && !noteMatch && !groupMatch && !idMatch && !tagMatch) {
          continue;
        }
      }

      if (debouncedTagFilter) {
        const hasTag = (p.tags || []).some((t) => t.toLowerCase().includes(debouncedTagFilter));
        if (!hasTag) continue;
      }

      if (groupFilter !== 'ALL' && (p.group || '') !== groupFilter) {
        continue;
      }

      if (statusFilter === 'running' && state !== 'running') continue;
      if (statusFilter === 'stopped' && state !== 'stopped') continue;
      if (statusFilter === 'error' && state !== 'error') continue;

      if (proxyFilter === 'with_proxy' && !p.proxy_id) continue;
      if (proxyFilter === 'direct' && p.proxy_id) continue;

      rows.push(p);
    }

    rows.sort((a, b) => {
      if (sortMode === 'name_asc') {
        return (a.name || '').localeCompare(b.name || '', locale, { sensitivity: 'base' });
      }
      if (sortMode === 'name_desc') {
        return (b.name || '').localeCompare(a.name || '', locale, { sensitivity: 'base' });
      }
      if (sortMode === 'newest') {
        return (b.created_at || '').localeCompare(a.created_at || '');
      }
      return (a.created_at || '').localeCompare(b.created_at || '');
    });

    return rows;
  }, [
    profilesWithStatus,
    debouncedSearch,
    debouncedTagFilter,
    groupFilter,
    statusFilter,
    proxyFilter,
    sortMode,
    locale,
  ]);

  const profileMapRef = useRef<Map<string, Profile>>(new Map());
  useEffect(() => {
    const map = new Map<string, Profile>();
    for (const p of profilesWithStatus) {
      map.set(p.id, p);
    }
    profileMapRef.current = map;
  }, [profilesWithStatus]);

  const handleBatchErrors = useCallback(
    (actionLabel: string, res: BatchResult) => {
      if (res?.errors && res.errors.length > 0) {
        const details = res.errors
          .map((e) => {
            const p = profileMapRef.current.get(e.id);
            return `${p ? p.name : e.id.slice(0, 8)}: ${e.message}`;
          })
          .join('; ');
        onMessage(
          t(
            `${actionLabel} có lỗi: ${details}`,
            `${actionLabel} encountered errors: ${details}`
          ),
          'error'
        );
      }
    },
    [onMessage, t]
  );

  const launchProfiles = useCallback(
    async (ids: string[], headless = false) => {
      if (ids.length === 0) return;
      setBusyAction(true);
      try {
        const res = await request<BatchResult>('profile.launch', { ids, headless });
        handleBatchErrors(t('Khởi chạy profile', 'Launch profile'), res);
        await onRefresh();
      } catch (err) {
        onMessage(
          t(
            `Lỗi khởi chạy: ${err instanceof Error ? err.message : String(err)}`,
            `Launch error: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
        await onRefresh();
      } finally {
        setBusyAction(false);
      }
    },
    [handleBatchErrors, onMessage, onRefresh, t]
  );

  const stopProfiles = useCallback(
    async (ids: string[]) => {
      if (ids.length === 0) return;
      setBusyAction(true);
      try {
        const res = await request<BatchResult>('profile.stop', { ids });
        handleBatchErrors(t('Dừng profile', 'Stop profile'), res);
        await onRefresh();
      } catch (err) {
        onMessage(
          t(
            `Lỗi dừng profile: ${err instanceof Error ? err.message : String(err)}`,
            `Stop error: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
        await onRefresh();
      } finally {
        setBusyAction(false);
      }
    },
    [handleBatchErrors, onMessage, onRefresh, t]
  );

  const toggleRowSelection = useCallback((id: string, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  }, []);

  const openEditModal = useCallback((p: Profile) => {
    setEditorState({ open: true, profile: p });
  }, []);

  const openCloneModal = useCallback((p: Profile) => {
    setCloneTarget(p);
    setCloneName(t(`${p.name} (Bản sao)`, `${p.name} (Copy)`));
    setCloneFull(false);
  }, [t]);

  const openFingerprintModal = useCallback(
    async (p: Profile) => {
      setFpTarget(p);
      setFpConfirmRegen(false);
      setFpLoading(true);
      try {
        const full = await request<Profile>('profile.get', { id: p.id });
        setFpTarget(full);
      } catch (err) {
        onMessage(
          t(
            `Không thể tải fingerprint: ${err instanceof Error ? err.message : String(err)}`,
            `Failed to load fingerprint: ${err instanceof Error ? err.message : String(err)}`
          ),
          'error'
        );
      } finally {
        setFpLoading(false);
      }
    },
    [onMessage, t]
  );

  const openBackupModal = useCallback((ids: string[]) => {
    setBackupModalIds(ids);
    setBackupSelectedSet(new Set(ids));
    setBackupDest('');
    setBackupPassword('');
    setBackupUnencryptedConfirm(false);
  }, []);

  const columns: Column<Profile>[] = useMemo(
    () => [
      {
        key: 'select',
        header: t('Chọn', 'Select'),
        width: 52,
        align: 'center',
        render: (row, _idx, selected) => (
          <input
            type="checkbox"
            aria-label={t(`Chọn profile ${row.name}`, `Select profile ${row.name}`)}
            checked={Boolean(selected)}
            onChange={(e) => toggleRowSelection(row.id, e.target.checked)}
            onClick={(e) => e.stopPropagation()}
          />
        ),
      },
      {
        key: 'name',
        header: sortMode === 'name_desc' ? t('Tên (Z-A)', 'Name (Z-A)') : t('Tên (A-Z)', 'Name (A-Z)'),
        flex: 2,
        render: (row) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
            <strong style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{row.name}</strong>
            {row.group ? <span className="cm-pill-counter">{row.group}</span> : null}
          </div>
        ),
      },
      {
        key: 'id',
        header: 'ID',
        width: 90,
        render: (row) => (
          <span className="cm-muted-text" title={row.id}>
            {row.id.slice(0, 8)}
          </span>
        ),
      },
      {
        key: 'tags',
        header: t('Thẻ', 'Tags'),
        flex: 1,
        render: (row) => (
          <span className="cm-muted-text" title={(row.tags || []).join(', ')}>
            {row.tags && row.tags.length > 0 ? row.tags.join(', ') : '-'}
          </span>
        ),
      },
      {
        key: 'note',
        header: t('Ghi chú', 'Notes'),
        flex: 1,
        render: (row) => (
          <span className="cm-muted-text" title={row.note || ''}>
            {row.note && row.note.trim() ? row.note.trim() : '-'}
          </span>
        ),
      },
      {
        key: 'proxy',
        header: t('Proxy / VPN', 'Proxy / VPN'),
        flex: 1,
        render: (row) => {
          const display = row.proxy_name || (!row.proxy_id ? t('Trực tiếp', 'Direct') : t('Proxy đã gán', 'Assigned proxy'));
          return (
            <span className={row.proxy_id ? '' : 'cm-muted-text'} title={display}>
              {display}
            </span>
          );
        },
      },
      {
        key: 'ext',
        header: 'EXT',
        width: 60,
        align: 'center',
        render: (row) => (
          <span className="cm-muted-text">
            {row.extensions && row.extensions.length > 0 ? String(row.extensions.length) : '-'}
          </span>
        ),
      },
      {
        key: 'status',
        header: t('Trạng thái', 'Status'),
        width: 215,
        render: (row) => {
          const st = row.state || 'stopped';
          const cpu = Number(row.cpu_percent || 0);
          const ram = Number(row.memory_mb || 0);
          return (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
              <StatusBadge state={st} error={row.error} />
              {st === 'running' ? (
                <span className="cm-muted-text" style={{ fontSize: 11 }}>
                  {cpu.toFixed(1)}% / {ram.toFixed(0)}MB
                </span>
              ) : row.error ? (
                <span
                  className="cm-muted-text"
                  style={{ fontSize: 11, color: 'var(--danger)', overflow: 'hidden', textOverflow: 'ellipsis' }}
                  title={row.error}
                >
                  {row.error}
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: 'actions',
        header: t('Thao tác', 'Actions'),
        width: 156,
        align: 'right',
        render: (row) => {
          const isRunning = row.state === 'running';
          return (
            <div className="cm-row" onClick={(e) => e.stopPropagation()}>
              {isRunning ? (
                <Button variant="danger" size="sm" onClick={() => stopProfiles([row.id])}>
                  {t('Dừng', 'Stop')}
                </Button>
              ) : (
                <Button variant="primary" size="sm" onClick={() => launchProfiles([row.id], false)}>
                  {t('Chạy', 'Launch')}
                </Button>
              )}
              <Button
                variant="secondary"
                size="sm"
                aria-label={t(`Thao tác khác cho ${row.name}`, `More actions for ${row.name}`)}
                onClick={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect();
                  setRowMenu({
                    profileId: row.id,
                    x: Math.min(rect.left, window.innerWidth - 220),
                    y: Math.min(rect.bottom + 4, window.innerHeight - 260),
                  });
                }}
              >
                {t('Menu', 'Menu')}
              </Button>
            </div>
          );
        },
      },
    ],
    [sortMode, toggleRowSelection, stopProfiles, launchProfiles, t]
  );

  const activeMenuProfile = rowMenu ? profileMapRef.current.get(rowMenu.profileId) || null : null;

  const handleConfirmClone = async () => {
    if (!cloneTarget) return;
    const cleanName = cloneName.trim();
    if (!cleanName) {
      onMessage(t('Vui lòng nhập tên cho profile mới.', 'Please enter a name for the new profile.'), 'warning');
      return;
    }
    setCloning(true);
    try {
      await request<Profile>('profile.duplicate', {
        id: cloneTarget.id,
        full: cloneFull,
        name: cleanName,
      });
      setCloneTarget(null);
      await onRefresh();
      onMessage(t(`Đã nhân bản profile "${cleanName}".`, `Duplicated profile "${cleanName}".`), 'info');
    } catch (err) {
      onMessage(
        t(
          `Lỗi nhân bản profile: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to duplicate profile: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setCloning(false);
    }
  };

  const handleRegenerateFingerprint = async () => {
    if (!fpTarget) return;
    setFpRegenerating(true);
    try {
      const updated = await request<Profile>('profile.regenerate', { id: fpTarget.id });
      setFpTarget(updated);
      setFpConfirmRegen(false);
      await onRefresh();
      onMessage(
        t(
          `Đã tái tạo fingerprint mới cho "${updated.name}".`,
          `Regenerated new fingerprint for "${updated.name}".`
        ),
        'info'
      );
    } catch (err) {
      onMessage(
        t(
          `Lỗi tái tạo fingerprint: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to regenerate fingerprint: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setFpRegenerating(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!deleteIds || deleteIds.length === 0) return;
    setDeleting(true);
    try {
      await request<null>('profile.delete', { ids: deleteIds });
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of deleteIds) next.delete(id);
        return next;
      });
      const count = deleteIds.length;
      setDeleteIds(null);
      await onRefresh();
      onMessage(
        t(
          `Đã xóa ${count} profile.`,
          `Deleted ${count} profile${count > 1 ? 's' : ''}.`
        ),
        'info'
      );
    } catch (err) {
      onMessage(
        t(
          `Lỗi xóa profile: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to delete profile: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setDeleting(false);
    }
  };

  const handleBatchAssignProxy = async () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBatchProxySaving(true);
    try {
      await request<null>('profile.assign_proxy', { ids, proxy_id: batchProxyId });
      setBatchProxyOpen(false);
      await onRefresh();
      onMessage(
        t(
          `Đã cập nhật proxy cho ${ids.length} profile.`,
          `Updated proxy for ${ids.length} profile${ids.length > 1 ? 's' : ''}.`
        ),
        'info'
      );
    } catch (err) {
      onMessage(
        t(
          `Lỗi gán proxy: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to assign proxy: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setBatchProxySaving(false);
    }
  };

  const handleBatchSetTags = async () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    const tags = batchTagsText
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    setBatchTagsSaving(true);
    try {
      await request<null>('profile.set_tags', { ids, tags });
      setBatchTagsOpen(false);
      await onRefresh();
      onMessage(
        t(
          `Đã cập nhật thẻ cho ${ids.length} profile.`,
          `Updated tags for ${ids.length} profile${ids.length > 1 ? 's' : ''}.`
        ),
        'info'
      );
    } catch (err) {
      onMessage(
        t(
          `Lỗi gán thẻ: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to assign tags: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setBatchTagsSaving(false);
    }
  };

  const handleBatchSetGroup = async () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBatchGroupSaving(true);
    try {
      await request<null>('profile.set_group', { ids, group: batchGroupText.trim() });
      setBatchGroupOpen(false);
      await onRefresh();
      onMessage(
        t(
          `Đã cập nhật nhóm cho ${ids.length} profile.`,
          `Updated group for ${ids.length} profile${ids.length > 1 ? 's' : ''}.`
        ),
        'info'
      );
    } catch (err) {
      onMessage(
        t(
          `Lỗi cập nhật nhóm: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to update group: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setBatchGroupSaving(false);
    }
  };

  const executeCreateBackup = async () => {
    const ids = Array.from(backupSelectedSet);
    if (ids.length === 0) {
      onMessage(t('Vui lòng chọn ít nhất một profile để sao lưu.', 'Please select at least one profile to back up.'), 'warning');
      return;
    }
    setBackupCreating(true);
    try {
      const outPath = await request<string>('backup.create', {
        ids,
        destination: backupDest.trim() || undefined,
        password: backupPassword,
      });
      setBackupUnencryptedConfirm(false);
      setBackupModalIds(null);
      await onRefresh();
      onMessage(t(`Đã tạo bản sao lưu thành công tại: ${outPath}`, `Backup created successfully at: ${outPath}`), 'info');
      if (onNavigate) onNavigate('backups');
    } catch (err) {
      onMessage(
        t(
          `Lỗi tạo sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to create backup: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
    } finally {
      setBackupCreating(false);
    }
  };

  const handleInspectRestoreFile = async (targetPath?: string): Promise<BackupInspection | null> => {
    if (restoreInspecting || restoring) return null;
    const p = (targetPath ?? restorePath).trim();
    if (!p) {
      onMessage(t('Vui lòng chọn file sao lưu.', 'Please select a backup file.'), 'warning');
      return null;
    }
    const reqId = ++restoreReqRef.current;
    setRestoreInspecting(true);
    setRestoreConfirmMissing(false);
    try {
      const info = await request<BackupInspection>('backup.inspect', {
        path: p,
        password: restorePassword,
      });
      if (reqId !== restoreReqRef.current) return null;
      setRestoreInspection(info);
      return info;
    } catch (err) {
      if (reqId !== restoreReqRef.current) return null;
      setRestoreInspection(null);
      onMessage(
        t(
          `Lỗi kiểm tra file sao lưu: ${err instanceof Error ? err.message : String(err)}`,
          `Failed to inspect backup file: ${err instanceof Error ? err.message : String(err)}`
        ),
        'error'
      );
      return null;
    } finally {
      if (reqId === restoreReqRef.current) setRestoreInspecting(false);
    }
  };

  const executeRestoreBackup = async () => {
    if (restoreInspecting || restoring) return;
    const p = restorePath.trim();
    if (!p) {
      onMessage(t('Vui lòng chọn file sao lưu.', 'Please select a backup file.'), 'warning');
      return;
    }
    setRestoring(true);
    try {
      const restored = await request<Profile[]>('backup.restore', {
        path: p,
        password: restorePassword,
      });
      setRestoreConfirmMissing(false);
      setRestoreOpen(false);
      await onRefresh();
      onMessage(
        t(
          `Đã khôi phục an toàn ${restored.length} profile với ID mới.`,
          `Safely restored ${restored.length} profile${restored.length > 1 ? 's' : ''} with new ID${restored.length > 1 ? 's' : ''}.`
        ),
        'info'
      );
    } catch (err) {
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

  const maxRunning = snapshot.settings.max_running || 4;
  const totalCount = snapshot.profiles.length;
  const selectedCount = selectedIds.size;

  return (
    <div className="cm-page">
      {/* 1. Top Bar */}
      <div className="cm-topbar">
        <div className="cm-topbar-left">
          <h1 className="cm-topbar-title">{t(`Tất cả ${totalCount}`, `All ${totalCount}`)}</h1>
          <span className="cm-pill-counter">
            {t('Đang chạy: ', 'Running: ')}{globalRunningCount}/{maxRunning}
          </span>
        </div>

        <div className="cm-topbar-actions">
          <input
            type="search"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder={t('Tìm kiếm profile...', 'Search profiles...')}
            aria-label={t('Tìm kiếm profile', 'Search profiles')}
            style={{ width: 220 }}
          />
          <Button variant="secondary" onClick={() => setHelpOpen(true)}>
            {t('Trợ giúp', 'Help')}
          </Button>
          <Button variant="secondary" onClick={() => onRefresh()}>
            {t('Làm mới', 'Refresh')}
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              restoreReqRef.current += 1;
              setRestorePath('');
              setRestorePassword('');
              setRestoreInspection(null);
              setRestoreConfirmMissing(false);
              setRestoreOpen(true);
            }}
          >
            {t('Nhập sao lưu', 'Import backup')}
          </Button>
          <Button variant="primary" onClick={() => setEditorState({ open: true, profile: null })}>
            {t('Tạo mới', 'New profile')}
          </Button>
        </div>
      </div>

      {/* 2. Sub Bar */}
      <div className="cm-subbar">
        <div className="cm-subbar-left">
          <Button
            variant="secondary"
            size="sm"
            active={showFilters}
            onClick={() => setShowFilters((v) => !v)}
          >
            {t('Bộ lọc', 'Filters')}
          </Button>
          <span className="cm-muted-text">
            {t(`${filteredProfiles.length} trên ${totalCount} dòng`, `${filteredProfiles.length} of ${totalCount} rows`)}
          </span>

          {selectedCount > 0 ? (
            <div className="cm-row" style={{ marginLeft: 8, flexWrap: 'wrap' }}>
              <strong>{t(`Đã chọn: ${selectedCount}`, `Selected: ${selectedCount}`)}</strong>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => launchProfiles(Array.from(selectedIds), false)}
              >
                {t('Khởi chạy', 'Launch')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => launchProfiles(Array.from(selectedIds), true)}
              >
                {t('Chạy Headless', 'Launch Headless')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => stopProfiles(Array.from(selectedIds))}
              >
                {t('Dừng', 'Stop')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => {
                  setBatchProxyId('');
                  setBatchProxyOpen(true);
                }}
              >
                {t('Gán proxy', 'Assign proxy')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => {
                  setBatchGroupText('');
                  setBatchGroupOpen(true);
                }}
              >
                {t('Đổi nhóm', 'Change group')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => {
                  setBatchTagsText('');
                  setBatchTagsOpen(true);
                }}
              >
                {t('Gán nhãn', 'Assign tags')}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction}
                onClick={() => openBackupModal(Array.from(selectedIds))}
              >
                {t('Sao lưu', 'Back up')}
              </Button>
              <Button
                variant="danger"
                size="sm"
                disabled={busyAction}
                onClick={() => setDeleteIds(Array.from(selectedIds))}
              >
                {t('Xóa', 'Delete')}
              </Button>
            </div>
          ) : null}
        </div>

        <div className="cm-subbar-right">
          <select
            aria-label={t('Sắp xếp profile', 'Sort profiles')}
            value={sortMode}
            onChange={(e) => setSortMode(e.target.value as SortMode)}
          >
            <option value="name_asc">{t('Tên (A-Z)', 'Name (A-Z)')}</option>
            <option value="name_desc">{t('Tên (Z-A)', 'Name (Z-A)')}</option>
            <option value="newest">{t('Mới nhất', 'Newest')}</option>
            <option value="oldest">{t('Cũ nhất', 'Oldest')}</option>
          </select>

          <Button
            variant="secondary"
            size="sm"
            onClick={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              setViewMenuPos({
                x: Math.min(rect.left, window.innerWidth - 200),
                y: rect.bottom + 4,
              });
            }}
          >
            {t('Chế độ xem', 'View options')}
          </Button>
        </div>
      </div>

      {/* 3. Collapsible Filter Panel */}
      {showFilters ? (
        <div className="cm-filter-panel">
          <div className="cm-filter-item">
            <label htmlFor="filter-group">{t('Nhóm:', 'Group:')}</label>
            <select
              id="filter-group"
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
            >
              <option value="ALL">{t('Tất cả nhóm', 'All groups')}</option>
              {availableGroups.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </div>

          <div className="cm-filter-item">
            <label htmlFor="filter-tag">{t('Thẻ:', 'Tag:')}</label>
            <input
              id="filter-tag"
              type="text"
              value={tagFilterInput}
              onChange={(e) => setTagFilterInput(e.target.value)}
              placeholder={t('Lọc thẻ...', 'Filter tags...')}
              style={{ width: 130 }}
            />
          </div>

          <div className="cm-filter-item">
            <label htmlFor="filter-status">{t('Trạng thái:', 'Status:')}</label>
            <select
              id="filter-status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">{t('Tất cả trạng thái', 'All statuses')}</option>
              <option value="running">{t('Đang chạy', 'Running')}</option>
              <option value="stopped">{t('Đã dừng', 'Stopped')}</option>
              <option value="error">{t('Lỗi', 'Error')}</option>
            </select>
          </div>

          <div className="cm-filter-item">
            <label htmlFor="filter-proxy">{t('Proxy:', 'Proxy:')}</label>
            <select
              id="filter-proxy"
              value={proxyFilter}
              onChange={(e) => setProxyFilter(e.target.value)}
            >
              <option value="ALL">{t('Tất cả proxy', 'All proxies')}</option>
              <option value="with_proxy">{t('Có proxy', 'With proxy')}</option>
              <option value="direct">{t('Trực tiếp', 'Direct')}</option>
            </select>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearchInput('');
              setDebouncedSearch('');
              setTagFilterInput('');
              setDebouncedTagFilter('');
              setGroupFilter('ALL');
              setStatusFilter('ALL');
              setProxyFilter('ALL');
            }}
          >
            {t('Đặt lại', 'Reset')}
          </Button>
        </div>
      ) : null}

      {/* 4. Virtualized Table or Empty State */}
      <div className="cm-content">
        {totalCount === 0 ? (
          <EmptyState
            title={t('Chưa có profile nào', 'No profiles yet')}
            description={t(
              'Tạo profile đầu tiên hoặc nhập bản sao lưu từ máy khác để bắt đầu.',
              'Create your first profile or import a backup from another computer to get started.'
            )}
            actionLabel={t('Tạo profile', 'Create profile')}
            onAction={() => setEditorState({ open: true, profile: null })}
            secondaryLabel={t('Nhập bản sao lưu', 'Import backup')}
            onSecondaryAction={() => {
              restoreReqRef.current += 1;
              setRestorePath('');
              setRestorePassword('');
              setRestoreInspection(null);
              setRestoreConfirmMissing(false);
              setRestoreOpen(true);
            }}
          />
        ) : (
          <VirtualTable
            rows={filteredProfiles}
            rowKey={(r) => r.id}
            columns={columns}
            rowHeight={44}
            selectedKeys={selectedIds}
            onRowDoubleClick={openEditModal}
            onRowContextMenu={(row, e) => {
              e.preventDefault();
              setRowMenu({
                profileId: row.id,
                x: Math.min(e.clientX, window.innerWidth - 220),
                y: Math.min(e.clientY, window.innerHeight - 260),
              });
            }}
          />
        )}
      </div>

      {/* View Options Menu */}
      {viewMenuPos ? (
        <>
          <div className="cm-menu-backdrop" onClick={() => setViewMenuPos(null)} />
          <div className="cm-menu" style={{ left: viewMenuPos.x, top: viewMenuPos.y }} role="menu">
            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                setViewMenuPos(null);
                onRefresh();
              }}
            >
              {t('Làm mới dữ liệu', 'Refresh data')}
            </button>
            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                setSelectedIds(new Set(filteredProfiles.map((p) => p.id)));
                setViewMenuPos(null);
              }}
            >
              {t(`Chọn tất cả (${filteredProfiles.length})`, `Select all (${filteredProfiles.length})`)}
            </button>
            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                setSelectedIds(new Set());
                setViewMenuPos(null);
              }}
            >
              {t('Bỏ chọn tất cả', 'Deselect all')}
            </button>
          </div>
        </>
      ) : null}

      {/* Row Context / Action Menu */}
      {rowMenu && activeMenuProfile ? (
        <>
          <div className="cm-menu-backdrop" onClick={() => setRowMenu(null)} />
          <div className="cm-menu" style={{ left: rowMenu.x, top: rowMenu.y }} role="menu">
            {activeMenuProfile.state === 'running' ? (
              <button
                type="button"
                className="cm-menu-item cm-menu-item-danger"
                onClick={() => {
                  const id = activeMenuProfile.id;
                  setRowMenu(null);
                  stopProfiles([id]);
                }}
              >
                {t('Dừng profile', 'Stop profile')}
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="cm-menu-item"
                  onClick={() => {
                    const id = activeMenuProfile.id;
                    setRowMenu(null);
                    launchProfiles([id], false);
                  }}
                >
                  {t('Khởi chạy bình thường', 'Launch normal')}
                </button>
                <button
                  type="button"
                  className="cm-menu-item"
                  onClick={() => {
                    const id = activeMenuProfile.id;
                    setRowMenu(null);
                    launchProfiles([id], true);
                  }}
                >
                  {t('Khởi chạy không đầu (Headless)', 'Launch Headless')}
                </button>
              </>
            )}

            <div className="cm-menu-sep" />

            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                const p = activeMenuProfile;
                setRowMenu(null);
                openEditModal(p);
              }}
            >
              {t('Chỉnh sửa cấu hình...', 'Edit configuration...')}
            </button>
            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                const p = activeMenuProfile;
                setRowMenu(null);
                openCloneModal(p);
              }}
            >
              {t('Nhân bản profile...', 'Duplicate profile...')}
            </button>
            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                const p = activeMenuProfile;
                setRowMenu(null);
                openFingerprintModal(p);
              }}
            >
              {t('Xem & Tái tạo Fingerprint...', 'View & Regenerate Fingerprint...')}
            </button>

            <div className="cm-menu-sep" />

            <button
              type="button"
              className="cm-menu-item"
              onClick={() => {
                const id = activeMenuProfile.id;
                setRowMenu(null);
                openBackupModal([id]);
              }}
            >
              {t('Sao lưu profile này...', 'Back up this profile...')}
            </button>
            <button
              type="button"
              className="cm-menu-item cm-menu-item-danger"
              onClick={() => {
                const id = activeMenuProfile.id;
                setRowMenu(null);
                setDeleteIds([id]);
              }}
            >
              {t('Xóa profile...', 'Delete profile...')}
            </button>
          </div>
        </>
      ) : null}

      {/* Profile Editor Modal */}
      {editorState.open ? (
        <ProfileEditor
          open={editorState.open}
          profile={editorState.profile}
          snapshot={snapshot}
          onClose={() => setEditorState({ open: false, profile: null })}
          onSaved={async () => {
            await onRefresh();
          }}
          onMessage={onMessage}
        />
      ) : null}

      {/* Clone Profile Dialog */}
      {cloneTarget ? (
        <Modal
          open={true}
          busy={cloning}
          title={t(`Nhân bản Profile: ${cloneTarget.name}`, `Duplicate Profile: ${cloneTarget.name}`)}
          onClose={() => setCloneTarget(null)}
          width={560}
          footer={
            <>
              <Button variant="secondary" onClick={() => setCloneTarget(null)} disabled={cloning}>
                {t('Hủy bỏ', 'Cancel')}
              </Button>
              <Button variant="primary" onClick={handleConfirmClone} loading={cloning}>
                {cloning ? t('Đang nhân bản...', 'Duplicating...') : t('Xác nhận nhân bản', 'Confirm clone')}
              </Button>
            </>
          }
        >
          <Field label={t('Tên cho profile mới:', 'Name for the new profile:')} htmlFor="clone-profile-name">
            <input
              id="clone-profile-name"
              type="text"
              value={cloneName}
              onChange={(e) => setCloneName(e.target.value)}
            />
          </Field>

          <div className="cm-card">
            <h4 className="cm-card-title">{t('Chọn phương thức nhân bản', 'Choose clone mode')}</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, cursor: 'pointer' }}>
                <span className="cm-row">
                  <input
                    type="radio"
                    name="clone-mode"
                    checked={!cloneFull}
                    onChange={() => setCloneFull(false)}
                  />
                  <strong>{t('Nhân bản cấu hình (Khuyên dùng)', 'Clone configuration (Recommended)')}</strong>
                </span>
                <span className="cm-muted-text" style={{ marginLeft: 22 }}>
                  {t(
                    'Tạo profile mới cùng cấu hình proxy, nhóm, nhãn nhưng sinh Fingerprint mới và xóa cookie. Tránh trùng lặp danh tính hoặc bị phát hiện dùng chung tài khoản.',
                    'Creates a new profile with the same proxy, group, and tags, but generates a fresh fingerprint and clears cookies. Prevents identity collision or detection.'
                  )}
                </span>
              </label>

              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, cursor: 'pointer' }}>
                <span className="cm-row">
                  <input
                    type="radio"
                    name="clone-mode"
                    checked={cloneFull}
                    onChange={() => setCloneFull(true)}
                  />
                  <strong>{t('Sao chép toàn bộ dữ liệu & phiên', 'Full copy of data & session')}</strong>
                </span>
                <span className="cm-muted-text" style={{ marginLeft: 22 }}>
                  {t(
                    'Giữ nguyên fingerprint và sao chép toàn bộ cookie, phiên duyệt web, tiện ích mở rộng. Yêu cầu profile gốc phải đang đóng hoàn toàn.',
                    'Keeps identical fingerprint and copies all cookies, browsing sessions, and extensions. Requires the original profile to be completely closed.'
                  )}
                </span>
              </label>
            </div>
          </div>
        </Modal>
      ) : null}

      {/* Fingerprint Viewer & Regenerate Dialog */}
      {fpTarget ? (
        <Modal
          open={true}
          busy={fpRegenerating}
          title={t(`Fingerprint: ${fpTarget.name}`, `Fingerprint: ${fpTarget.name}`)}
          onClose={() => {
            setFpTarget(null);
            setFpConfirmRegen(false);
          }}
          width={650}
          footer={
            <div style={{ display: 'flex', width: '100%', justifyContent: 'space-between', alignItems: 'center' }}>
              <Button
                variant="danger"
                disabled={fpLoading || fpRegenerating}
                onClick={() => setFpConfirmRegen(true)}
              >
                {fpRegenerating ? t('Đang tái tạo...', 'Regenerating...') : t('Tái tạo Fingerprint mới', 'Regenerate new Fingerprint')}
              </Button>
              <Button
                variant="secondary"
                disabled={fpRegenerating}
                onClick={() => {
                  setFpTarget(null);
                  setFpConfirmRegen(false);
                }}
              >
                {t('Đóng', 'Close')}
              </Button>
            </div>
          }
        >
          <div className="cm-banner cm-banner-info" style={{ marginBottom: 12 }}>
            <strong>{t('Fingerprint danh tính ổn định:', 'Stable identity fingerprint:')}</strong>{' '}
            {t(
              'Cấu hình fingerprint được sinh cố định theo từng profile và không tự thay đổi khi đổi IP hay khởi chạy lại. Điều này giúp duy trì phiên đăng nhập và tránh bị website nghi ngờ là thiết bị mới.',
              'Fingerprint config is fixed per profile and does not automatically change on IP change or restart. This maintains login sessions and prevents websites from suspecting a new device.'
            )}
          </div>

          {fpConfirmRegen ? (
            <div className="cm-banner cm-banner-danger" style={{ marginBottom: 12 }}>
              <div style={{ marginBottom: 8 }}>
                <strong>{t('CẢNH BÁO:', 'WARNING:')}</strong>{' '}
                {t(
                  'Việc tái tạo fingerprint sẽ thay đổi hoàn toàn danh tính thiết bị phần cứng, canvas, WebGL và user-agent của profile này. Các website bạn đã đăng nhập có thể coi đây là thiết bị lạ. Bạn có chắc chắn muốn tạo mới fingerprint không?',
                  'Regenerating the fingerprint completely changes the hardware identity, canvas, WebGL, and user-agent of this profile. Logged-in websites may treat this as an unfamiliar device. Are you sure you want to regenerate the fingerprint?'
                )}
              </div>
              <div className="cm-row">
                <Button variant="danger" size="sm" loading={fpRegenerating} onClick={handleRegenerateFingerprint}>
                  {t('Xác nhận tạo mới', 'Confirm regenerate')}
                </Button>
                <Button variant="secondary" size="sm" disabled={fpRegenerating} onClick={() => setFpConfirmRegen(false)}>
                  {t('Hủy', 'Cancel')}
                </Button>
              </div>
            </div>
          ) : null}

          <Field label={t('Chi tiết thông số Fingerprint JSON:', 'Fingerprint JSON parameters:')}>
            <pre className="cm-code">
              {fpLoading
                ? t('Đang tải thông số fingerprint...', 'Loading fingerprint parameters...')
                : fpTarget.fingerprint && Object.keys(fpTarget.fingerprint).length > 0
                  ? JSON.stringify(fpTarget.fingerprint, null, 2)
                  : t('Chưa khởi tạo fingerprint', 'Fingerprint not initialized')}
            </pre>
          </Field>
        </Modal>
      ) : null}

      {/* Named Delete Confirmation Dialog */}
      {deleteIds ? (
        <ConfirmDialog
          open={true}
          title={t('Xác nhận xóa profile', 'Confirm delete profile')}
          message={t(
            'CẢNH BÁO: Dữ liệu sẽ bị xóa vĩnh viễn!\nToàn bộ dữ liệu duyệt web, cookie, lịch sử và tiện ích mở rộng của các profile sau sẽ bị xóa hoàn toàn khỏi máy tính:',
            'WARNING: Data will be permanently deleted!\nAll browsing data, cookies, history, and extensions of the following profiles will be completely removed from the computer:'
          )}
          confirmText={deleting ? t('Đang xóa...', 'Deleting...') : t('Xác nhận xóa', 'Confirm delete')}
          cancelText={t('Hủy bỏ', 'Cancel')}
          variant="danger"
          loading={deleting}
          onConfirm={handleConfirmDelete}
          onCancel={() => setDeleteIds(null)}
        >
          <div className="cm-list-box">
            {deleteIds.map((id) => {
              const p = profileMapRef.current.get(id);
              return (
                <div key={id} className="cm-list-item">
                  <span>{p ? p.name : id}</span>
                  <span className="cm-muted-text">{id.slice(0, 8)}</span>
                </div>
              );
            })}
          </div>
        </ConfirmDialog>
      ) : null}

      {/* Batch Assign Proxy Dialog */}
      {batchProxyOpen ? (
        <Modal
          open={true}
          busy={batchProxySaving}
          title={t('Gán Proxy hàng loạt', 'Batch Assign Proxy')}
          onClose={() => setBatchProxyOpen(false)}
          width={440}
          footer={
            <>
              <Button variant="secondary" onClick={() => setBatchProxyOpen(false)} disabled={batchProxySaving}>
                {t('Hủy bỏ', 'Cancel')}
              </Button>
              <Button variant="primary" onClick={handleBatchAssignProxy} loading={batchProxySaving}>
                {t('Xác nhận gán', 'Confirm assign')}
              </Button>
            </>
          }
        >
          <Field
            label={t(
              `Chọn proxy để gán cho ${selectedIds.size} profile đã chọn:`,
              `Select proxy to assign to ${selectedIds.size} selected profile${selectedIds.size > 1 ? 's' : ''}:`
            )}
            htmlFor="batch-proxy-select"
          >
            <select
              id="batch-proxy-select"
              value={batchProxyId}
              onChange={(e) => setBatchProxyId(e.target.value)}
            >
              <option value="">{t('Không dùng proxy (Trực tiếp)', 'No proxy (Direct connection)')}</option>
              {snapshot.proxies.map((px) => (
                <option key={px.id} value={px.id}>
                  {px.name || px.id} ({px.server})
                </option>
              ))}
            </select>
          </Field>
        </Modal>
      ) : null}

      {/* Batch Set Group Dialog */}
      {batchGroupOpen ? (
        <Modal
          open={true}
          busy={batchGroupSaving}
          title={t('Đổi Nhóm hàng loạt', 'Batch Change Group')}
          onClose={() => setBatchGroupOpen(false)}
          width={440}
          footer={
            <>
              <Button variant="secondary" onClick={() => setBatchGroupOpen(false)} disabled={batchGroupSaving}>
                {t('Hủy bỏ', 'Cancel')}
              </Button>
              <Button variant="primary" onClick={handleBatchSetGroup} loading={batchGroupSaving}>
                {t('Lưu nhóm', 'Save group')}
              </Button>
            </>
          }
        >
          <Field
            label={t(
              `Nhập tên nhóm cho ${selectedIds.size} profile (để trống để xóa nhóm):`,
              `Enter group name for ${selectedIds.size} selected profile${selectedIds.size > 1 ? 's' : ''} (leave blank to clear group):`
            )}
            htmlFor="batch-group-input"
          >
            <input
              id="batch-group-input"
              type="text"
              value={batchGroupText}
              onChange={(e) => setBatchGroupText(e.target.value)}
              placeholder={t('Ví dụ: Facebook, Marketing...', 'e.g. Facebook, Marketing...')}
            />
          </Field>
        </Modal>
      ) : null}

      {/* Batch Set Tags Dialog */}
      {batchTagsOpen ? (
        <Modal
          open={true}
          busy={batchTagsSaving}
          title={t('Gán Thẻ (Tags) hàng loạt', 'Batch Assign Tags')}
          onClose={() => setBatchTagsOpen(false)}
          width={440}
          footer={
            <>
              <Button variant="secondary" onClick={() => setBatchTagsOpen(false)} disabled={batchTagsSaving}>
                {t('Hủy bỏ', 'Cancel')}
              </Button>
              <Button variant="primary" onClick={handleBatchSetTags} loading={batchTagsSaving}>
                {t('Lưu thẻ', 'Save tags')}
              </Button>
            </>
          }
        >
          <Field
            label={t(
              `Nhập danh sách thẻ cho ${selectedIds.size} profile (phân cách bởi dấu phẩy):`,
              `Enter tags for ${selectedIds.size} selected profile${selectedIds.size > 1 ? 's' : ''} (separated by commas):`
            )}
            htmlFor="batch-tags-input"
          >
            <input
              id="batch-tags-input"
              type="text"
              value={batchTagsText}
              onChange={(e) => setBatchTagsText(e.target.value)}
              placeholder={t('Ví dụ: clone, shop1, test...', 'e.g. clone, shop1, test...')}
            />
          </Field>
        </Modal>
      ) : null}

      {/* Backup Create Dialog */}
      {backupModalIds ? (
        <Modal
          open={true}
          busy={backupCreating}
          title={t('Tạo bản sao lưu Profile', 'Create Profile Backup')}
          onClose={() => {
            setBackupModalIds(null);
            setBackupUnencryptedConfirm(false);
          }}
          width={540}
          footer={
            <>
              <Button
                variant="secondary"
                onClick={() => {
                  setBackupModalIds(null);
                  setBackupUnencryptedConfirm(false);
                }}
                disabled={backupCreating}
              >
                {t('Hủy bỏ', 'Cancel')}
              </Button>
              <Button
                variant="primary"
                loading={backupCreating}
                onClick={() => {
                  if (backupSelectedSet.size === 0) {
                    onMessage(t('Vui lòng chọn ít nhất một profile để sao lưu.', 'Please select at least one profile to back up.'), 'warning');
                    return;
                  }
                  if (!backupPassword && !backupUnencryptedConfirm) {
                    setBackupUnencryptedConfirm(true);
                    return;
                  }
                  executeCreateBackup();
                }}
              >
                {backupCreating ? t('Đang tạo sao lưu...', 'Creating backup...') : t('Tạo bản sao lưu', 'Create backup')}
              </Button>
            </>
          }
        >
          <Field label={t('Chọn các profile cần sao lưu:', 'Select profiles to back up:')}>
            <div className="cm-list-box">
              {snapshot.profiles.map((p) => {
                const checked = backupSelectedSet.has(p.id);
                return (
                  <label key={p.id} className="cm-list-item" style={{ cursor: 'pointer' }}>
                    <span className="cm-row">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(e) => {
                          setBackupSelectedSet((prev) => {
                            const next = new Set(prev);
                            if (e.target.checked) next.add(p.id);
                            else next.delete(p.id);
                            return next;
                          });
                        }}
                      />
                      <span>{p.name}</span>
                    </span>
                    <span className="cm-muted-text">{p.id.slice(0, 8)}</span>
                  </label>
                );
              })}
            </div>
          </Field>

          <Field label={t('Thư mục / Tên file lưu trữ (Tùy chọn):', 'Target directory / File name (Optional):')} htmlFor="backup-dest-input">
            <div className="cm-row">
              <input
                id="backup-dest-input"
                type="text"
                style={{ flex: 1 }}
                value={backupDest}
                onChange={(e) => setBackupDest(e.target.value)}
                placeholder={t('Để trống sẽ lưu vào thư mục backups mặc định...', 'Leave empty to save into default backups folder...')}
              />
              <Button
                variant="secondary"
                onClick={async () => {
                  const chosen = await savePath({
                    filters: [{ name: t('Tệp sao lưu', 'Backup Files'), extensions: ['zip', 'camoubak'] }],
                  });
                  if (chosen) setBackupDest(chosen);
                }}
              >
                {t('Chọn...', 'Browse...')}
              </Button>
            </div>
          </Field>

          <Field label={t('Mật khẩu mã hóa (Tùy chọn - Mã hóa AES-GCM an toàn):', 'Encryption password (Optional - Secure AES-GCM encryption):')} htmlFor="backup-pwd-input">
            <input
              id="backup-pwd-input"
              type="password"
              value={backupPassword}
              onChange={(e) => {
                setBackupPassword(e.target.value);
                setBackupUnencryptedConfirm(false);
              }}
              placeholder={t('Nhập mật khẩu để bảo vệ cookie và phiên duyệt...', 'Enter password to protect cookies and sessions...')}
            />
          </Field>

          <div className="cm-banner cm-banner-info">
            <strong>{t('Lưu ý bảo mật:', 'Security note:')}</strong>{' '}
            {t(
              'Bản sao lưu chứa dữ liệu phiên duyệt web, cookie và thông tin proxy đã gán. Nếu đặt mật khẩu, file sẽ được mã hóa scrypt + AES-GCM an toàn. Nếu để trống mật khẩu, file sẽ được lưu ở dạng zip không mã hóa.',
              'Backups contain browsing session data, cookies, and assigned proxy info. If password is set, the file is securely encrypted with scrypt + AES-GCM. If left empty, it will be saved as an unencrypted zip.'
            )}
          </div>

          {backupUnencryptedConfirm ? (
            <div className="cm-banner cm-banner-danger" style={{ marginTop: 12 }}>
              <div style={{ marginBottom: 8 }}>
                <strong>{t('CẢNH BÁO SAO LƯU KHÔNG MÃ HÓA:', 'UNENCRYPTED BACKUP WARNING:')}</strong>{' '}
                {t(
                  'Bạn chưa nhập mật khẩu mã hóa. Toàn bộ cookie, phiên đăng nhập và proxy sẽ được lưu ở dạng zip thông thường không được bảo vệ. Bạn có chắc chắn muốn tiếp tục?',
                  'No encryption password entered. All cookies, login sessions, and proxies will be saved in an unprotected standard zip file. Are you sure you want to proceed?'
                )}
              </div>
              <div className="cm-row">
                <Button variant="danger" size="sm" loading={backupCreating} onClick={executeCreateBackup}>
                  {t('Xác nhận tạo không mã hóa', 'Confirm create unencrypted')}
                </Button>
                <Button variant="secondary" size="sm" onClick={() => setBackupUnencryptedConfirm(false)}>
                  {t('Quay lại nhập mật khẩu', 'Back to enter password')}
                </Button>
              </div>
            </div>
          ) : null}
        </Modal>
      ) : null}

      {/* Backup Inspect & Restore Dialog */}
      {restoreOpen ? (
        <Modal
          open={true}
          busy={restoring || restoreInspecting}
          title={t('Khôi phục Profile từ Sao lưu', 'Restore Profile from Backup')}
          onClose={() => {
            if (restoring || restoreInspecting) return;
            restoreReqRef.current += 1;
            setRestoreOpen(false);
            setRestoreConfirmMissing(false);
          }}
          width={620}
          footer={
            <>
              <Button
                variant="secondary"
                onClick={() => {
                  restoreReqRef.current += 1;
                  setRestoreOpen(false);
                  setRestoreConfirmMissing(false);
                }}
                disabled={restoring || restoreInspecting}
              >
                {t('Đóng', 'Close')}
              </Button>
              <Button
                variant="primary"
                loading={restoring}
                disabled={restoreInspecting}
                onClick={async () => {
                  const info = await handleInspectRestoreFile();
                  if (!info) return;
                  if (info.missing_versions && info.missing_versions.length > 0) {
                    setRestoreConfirmMissing(true);
                    return;
                  }
                  await executeRestoreBackup();
                }}
              >
                {restoring ? t('Đang khôi phục...', 'Restoring...') : t('Khôi phục tất cả Profile', 'Restore all profiles')}
              </Button>
            </>
          }
        >
          <Field label={t('Đường dẫn file sao lưu (.zip / .camoubak):', 'Backup file path (.zip / .camoubak):')} htmlFor="restore-path-input">
            <div className="cm-row">
              <input
                id="restore-path-input"
                type="text"
                style={{ flex: 1 }}
                value={restorePath}
                disabled={restoring || restoreInspecting}
                onChange={(e) => {
                  restoreReqRef.current += 1;
                  setRestorePath(e.target.value);
                  setRestoreInspection(null);
                  setRestoreConfirmMissing(false);
                }}
              />
              <Button
                variant="secondary"
                disabled={restoring || restoreInspecting}
                onClick={async () => {
                  if (restoring || restoreInspecting) return;
                  const chosen = await openPath({
                    filters: [{ name: t('Tệp sao lưu', 'Backup Files'), extensions: ['zip', 'camoubak'] }],
                  });
                  if (chosen) {
                    restoreReqRef.current += 1;
                    setRestorePath(chosen);
                    setRestoreInspection(null);
                    setRestoreConfirmMissing(false);
                    handleInspectRestoreFile(chosen);
                  }
                }}
              >
                {t('Chọn file...', 'Browse...')}
              </Button>
            </div>
          </Field>

          <Field label={t('Mật khẩu giải mã (nếu bản sao lưu có đặt mật khẩu):', 'Decryption password (if backup was password-protected):')} htmlFor="restore-pwd-input">
            <input
              id="restore-pwd-input"
              type="password"
              value={restorePassword}
              disabled={restoring || restoreInspecting}
              onChange={(e) => {
                restoreReqRef.current += 1;
                setRestorePassword(e.target.value);
                setRestoreInspection(null);
                setRestoreConfirmMissing(false);
              }}
              placeholder={t('Nhập mật khẩu nếu file đã được mã hóa...', 'Enter password if file is encrypted...')}
            />
          </Field>

          <div className="cm-row" style={{ marginBottom: 12 }}>
            <Button
              variant="secondary"
              loading={restoreInspecting}
              disabled={restoring || restoreInspecting}
              onClick={() => handleInspectRestoreFile()}
            >
              {restoreInspecting ? t('Đang kiểm tra...', 'Inspecting...') : t('Kiểm tra nội dung file', 'Inspect file contents')}
            </Button>
          </div>

          {restoreInspection &&
          (restoreInspection.warning ||
            restoreInspection.compatibility_warning ||
            (restoreInspection.missing_versions && restoreInspection.missing_versions.length > 0)) ? (
            <div className="cm-banner cm-banner-danger" style={{ marginBottom: 12 }}>
              {restoreInspection.warning ? <div>{restoreInspection.warning}</div> : null}
              {restoreInspection.compatibility_warning ? (
                <div>{restoreInspection.compatibility_warning}</div>
              ) : null}
              {restoreInspection.missing_versions && restoreInspection.missing_versions.length > 0 ? (
                <div>
                  {t('Phiên bản Camoufox chưa cài đặt trên máy: ', 'Camoufox versions not installed on this machine: ')}
                  {restoreInspection.missing_versions.join(', ')}
                </div>
              ) : null}
            </div>
          ) : null}

          {restoreConfirmMissing && restoreInspection?.missing_versions ? (
            <div className="cm-banner cm-banner-warning" style={{ marginBottom: 12 }}>
              <div style={{ marginBottom: 8 }}>
                {t('Bản sao lưu yêu cầu các phiên bản Camoufox chưa có trên máy này:', 'Backup requires Camoufox versions not yet present on this machine:')}{' '}
                <strong>{restoreInspection.missing_versions.join(', ')}</strong>.{' '}
                {t(
                  'Khôi phục giữ nguyên phiên bản đã ghim; cần cài phiên bản tương ứng trước khi chạy profile. Bạn có muốn tiếp tục khôi phục?',
                  'Restore preserves pinned versions; install the matching version before launching profiles. Do you want to continue restoring?'
                )}
              </div>
              <div className="cm-row">
                <Button
                  variant="primary"
                  size="sm"
                  loading={restoring}
                  disabled={restoreInspecting}
                  onClick={() => {
                    if (!restoreInspection) return;
                    executeRestoreBackup();
                  }}
                >
                  {t('Tiếp tục khôi phục', 'Continue restore')}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={restoring || restoreInspecting}
                  onClick={() => setRestoreConfirmMissing(false)}
                >
                  {t('Hủy', 'Cancel')}
                </Button>
              </div>
            </div>
          ) : null}

          <Field label={t('Thông tin chi tiết bản sao lưu:', 'Backup details:')}>
            <pre className="cm-code">
              {restoreInspection
                ? JSON.stringify(restoreInspection, null, 2)
                : t('Chọn file và nhấn "Kiểm tra nội dung file" để xem thông tin chi tiết.', 'Select file and click "Inspect file contents" to view details.')}
            </pre>
          </Field>
        </Modal>
      ) : null}

      {/* Quick Help Dialog */}
      {helpOpen ? (
        <Modal
          open={true}
          title={t('CamouManager - Hướng dẫn nhanh', 'CamouManager - Quick Help')}
          onClose={() => setHelpOpen(false)}
          width={600}
          footer={
            <Button variant="primary" onClick={() => setHelpOpen(false)}>
              {t('Đóng', 'Close')}
            </Button>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ margin: 0 }}>
              <strong>{t('Bắt đầu:', 'Getting started:')}</strong>{' '}
              {t(
                'Vào Cài đặt - Phiên bản, kiểm tra và cài Camoufox trước khi chạy profile.',
                'Go to Settings - Versions, check and install Camoufox before launching profiles.'
              )}
            </p>
            <div>
              <strong>{t('Các tính năng chính:', 'Key features:')}</strong>
              <ul style={{ margin: '6px 0', paddingLeft: 20 }}>
                <li>{t('Fingerprint ổn định: Cố định theo profile, không tự đổi khi khởi động lại.', 'Stable fingerprint: Fixed per profile, does not change on restart.')}</li>
                <li>
                  {t(
                    'Nhân bản profile: Lựa chọn giữa Nhân bản cấu hình (sinh fingerprint mới, xóa cookie) và Sao chép toàn bộ phiên (giữ nguyên fingerprint).',
                    'Profile cloning: Choose between Clone configuration (fresh fingerprint, clear cookies) and Full copy (keeps fingerprint & sessions).'
                  )}
                </li>
                <li>{t('Proxy an toàn: Kết nối fail-closed, không rò rỉ IP thật nếu proxy gặp sự cố.', 'Safe proxy: Fail-closed connection, no real IP leaks if proxy fails.')}</li>
                <li>{t('Sao lưu & Khôi phục: Đóng gói dữ liệu trình duyệt, mã hóa AES-GCM với mật khẩu.', 'Backup & Restore: Package browser data, AES-GCM encrypted with password.')}</li>
                <li>{t('Quản lý phiên bản: Ghim phiên bản Camoufox độc lập cho từng profile.', 'Version management: Pin Camoufox versions independently per profile.')}</li>
                <li>{t('Cập nhật dữ liệu fingerprint không thay đổi fingerprint đã lưu của profile cũ.', 'Updating fingerprint dataset does not alter existing profiles.')}</li>
              </ul>
            </div>
            <p style={{ margin: 0 }}>
              <strong>{t('Chuyển máy:', 'Migration:')}</strong>{' '}
              {t(
                'Đóng profile, tạo bản sao lưu có mật khẩu, chuyển file sang máy mới, cài đúng phiên bản Camoufox đã ghim rồi khôi phục. Bản sao lưu không chứa browser binary.',
                'Close profiles, create password-protected backup, move file to new machine, install matching pinned Camoufox version, then restore. Backups do not contain browser binaries.'
              )}
            </p>
            <p style={{ margin: 0 }}>
              <strong>{t('Sao lưu tự động:', 'Automatic backup:')}</strong>{' '}
              {t(
                'Chỉ chạy khi manager đang mở, bỏ qua profile đang chạy. Mật khẩu tự động chỉ giữ trong phiên ứng dụng và phải nhập lại sau khi mở lại manager.',
                'Only runs while manager is open, skips running profiles. Auto-backup password is only kept in the session memory and must be re-entered upon restart.'
              )}
            </p>
            <div className="cm-banner cm-banner-info">
              <div>
                <strong>{t('Thư mục dữ liệu:', 'Data directory:')}</strong> {snapshot.root}
              </div>
              <div>
                {t(
                  'Dữ liệu được giữ lại khi gỡ ứng dụng. Không chia sẻ backup hoặc thư mục profile vì chứa cookie và phiên đăng nhập.',
                  'Data is retained when uninstalling. Do not share backups or profile directories as they contain cookies and login sessions.'
                )}
              </div>
            </div>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}
