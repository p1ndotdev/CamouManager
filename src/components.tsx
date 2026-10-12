import React, { useEffect, useRef, useState } from 'react';
import { useI18n } from './i18n';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md';
  active?: boolean;
  loading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', active = false, loading = false, className = '', disabled, children, type = 'button', ...rest },
  ref
) {
  const classes = [
    'cm-btn',
    `cm-btn-${variant}`,
    `cm-btn-${size}`,
    active ? 'cm-btn-active' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <button ref={ref} type={type} className={classes} disabled={disabled || loading} {...rest}>
      {children}
    </button>
  );
});

export interface ModalProps {
  open?: boolean;
  busy?: boolean;
  title: string;
  onClose: () => void;
  width?: number | string;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

const FOCUSABLE_SELECTOR =
  'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';
const activeModalStack: HTMLDivElement[] = [];

export function Modal({ open = true, busy = false, title, onClose, width = 620, footer, children }: ModalProps) {
  const { t } = useI18n();
  const modalRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  const busyRef = useRef(busy);
  onCloseRef.current = onClose;
  busyRef.current = busy;

  useEffect(() => {
    if (!open) return;
    const modalEl = modalRef.current;
    if (!modalEl) return;
    activeModalStack.push(modalEl);
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!modalEl.contains(document.activeElement)) {
      const first = modalEl.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      (first ?? modalEl).focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (activeModalStack[activeModalStack.length - 1] !== modalEl) return;
      if (e.key === 'Escape') {
        e.stopPropagation();
        if (!busyRef.current) {
          onCloseRef.current();
        }
        return;
      }
      if (e.key === 'Tab') {
        const nodes = Array.from(modalEl.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
        if (nodes.length === 0) {
          e.preventDefault();
          modalEl.focus();
          return;
        }
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey) {
          if (!active || active === first || !modalEl.contains(active)) {
            e.preventDefault();
            last.focus();
          }
        } else if (!active || active === last || !modalEl.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      const idx = activeModalStack.lastIndexOf(modalEl);
      if (idx !== -1) activeModalStack.splice(idx, 1);
      if (previousFocus && typeof previousFocus.focus === 'function' && document.contains(previousFocus)) {
        previousFocus.focus();
      }
    };
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="cm-modal-backdrop"
      onMouseDown={(e) => {
        if (!busy && e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        tabIndex={-1}
        className="cm-modal"
        role="dialog"
        aria-modal="true"
        aria-busy={busy || undefined}
        aria-label={title}
        style={{ maxWidth: typeof width === 'number' ? `${width}px` : width }}
      >
        <div className="cm-modal-header">
          <h2 className="cm-modal-title">{title}</h2>
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            onClick={() => {
              if (!busy) onClose();
            }}
            aria-label={t('Đóng hộp thoại', 'Close dialog')}
          >
            {t('Đóng', 'Close')}
          </Button>
        </div>
        <div className="cm-modal-body">{children}</div>
        {footer ? <div className="cm-modal-footer">{footer}</div> : null}
      </div>
    </div>
  );
}

export interface FieldProps {
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  inline?: boolean;
  htmlFor?: string;
  children: React.ReactNode;
  className?: string;
}

export function Field({ label, hint, error, inline = false, htmlFor, children, className = '' }: FieldProps) {
  return (
    <div className={`cm-field ${inline ? 'cm-field-inline' : ''} ${className}`.trim()}>
      {label ? (
        <label className="cm-field-label" htmlFor={htmlFor}>
          {label}
        </label>
      ) : null}
      <div className="cm-field-control">
        {children}
        {hint ? <div className="cm-field-hint">{hint}</div> : null}
        {error ? <div className="cm-field-error">{error}</div> : null}
      </div>
    </div>
  );
}

export interface ConfirmDialogProps {
  open?: boolean;
  title: string;
  message: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  variant?: 'primary' | 'danger';
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: React.ReactNode;
}

export function ConfirmDialog({
  open = true,
  title,
  message,
  confirmText,
  cancelText,
  variant = 'danger',
  loading = false,
  onConfirm,
  onCancel,
  children,
}: ConfirmDialogProps) {
  const { t } = useI18n();
  if (!open) return null;
  const effectiveConfirm = confirmText ?? t('Xác nhận', 'Confirm');
  const effectiveCancel = cancelText ?? t('Hủy bỏ', 'Cancel');

  return (
    <Modal
      open={open}
      busy={loading}
      title={title}
      onClose={() => {
        if (!loading) onCancel();
      }}
      width={480}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={loading}>
            {effectiveCancel}
          </Button>
          <Button variant={variant} onClick={onConfirm} loading={loading}>
            {effectiveConfirm}
          </Button>
        </>
      }
    >
      <div className={variant === 'danger' ? 'cm-confirm-danger' : 'cm-confirm-message'}>{message}</div>
      {children ? <div className="cm-confirm-extra">{children}</div> : null}
    </Modal>
  );
}

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  width?: number | string;
  flex?: number;
  align?: 'left' | 'center' | 'right';
  render: (row: T, index: number, selected?: boolean) => React.ReactNode;
}

export interface VirtualTableProps<T> {
  rows?: T[];
  data?: T[];
  rowKey?: ((row: T, index: number) => string) | keyof T;
  columns: Column<T>[];
  rowHeight?: number;
  empty?: React.ReactNode;
  onRowDoubleClick?: (row: T) => void;
  onRowContextMenu?: (row: T, event: React.MouseEvent) => void;
  selectedKeys?: ReadonlySet<string>;
}

interface VirtualRowProps<T> {
  row: T;
  index: number;
  columns: Column<T>[];
  rowHeight: number;
  top: number;
  selected: boolean;
  onRowDoubleClick?: (row: T) => void;
  onRowContextMenu?: (row: T, event: React.MouseEvent) => void;
}

const VirtualRowInner = <T,>({
  row,
  index,
  columns,
  rowHeight,
  top,
  selected,
  onRowDoubleClick,
  onRowContextMenu,
}: VirtualRowProps<T>) => {
  return (
    <div
      role="row"
      aria-selected={selected}
      className={`cm-vtable-row ${selected ? 'cm-vtable-row-selected' : ''}`}
      style={{
        height: `${rowHeight}px`,
        transform: `translateY(${top}px)`,
      }}
      onDoubleClick={onRowDoubleClick ? () => onRowDoubleClick(row) : undefined}
      onContextMenu={onRowContextMenu ? (e) => onRowContextMenu(row, e) : undefined}
    >
      {columns.map((col) => {
        const cellStyle: React.CSSProperties = {
          width: col.width !== undefined ? (typeof col.width === 'number' ? `${col.width}px` : col.width) : undefined,
          flex: col.flex !== undefined ? `${col.flex} 1 0%` : col.width !== undefined ? '0 0 auto' : '1 1 0%',
          textAlign: col.align || 'left',
          justifyContent:
            col.align === 'center' ? 'center' : col.align === 'right' ? 'flex-end' : 'flex-start',
        };
        return (
          <div key={col.key} role="cell" className="cm-vtable-cell" style={cellStyle}>
            {col.render(row, index, selected)}
          </div>
        );
      })}
    </div>
  );
};

const VirtualRow = React.memo(VirtualRowInner) as typeof VirtualRowInner;

export function VirtualTable<T>({
  rows,
  data,
  rowKey,
  columns,
  rowHeight = 44,
  empty,
  onRowDoubleClick,
  onRowContextMenu,
  selectedKeys,
}: VirtualTableProps<T>) {
  const { t } = useI18n();
  const items = rows ?? data ?? [];
  const isEmptyView = items.length === 0 && Boolean(empty);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(520);

  useEffect(() => {
    if (isEmptyView) return;
    const el = containerRef.current;
    if (!el) return;
    const updateHeight = () => {
      if (el.clientHeight > 0) {
        setViewportHeight(el.clientHeight);
      }
    };
    updateHeight();
    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(updateHeight);
      observer.observe(el);
      return () => observer.disconnect();
    }
  }, [isEmptyView]);

  const totalHeight = items.length * rowHeight;
  const maxScrollTop = Math.max(0, totalHeight - viewportHeight);
  const effectiveScrollTop = Math.min(scrollTop, maxScrollTop);

  useEffect(() => {
    if (scrollTop > maxScrollTop) {
      setScrollTop(maxScrollTop);
      if (containerRef.current && containerRef.current.scrollTop > maxScrollTop) {
        containerRef.current.scrollTop = maxScrollTop;
      }
    }
  }, [maxScrollTop, scrollTop]);

  if (isEmptyView) {
    return <div className="cm-vtable-empty-wrap">{empty}</div>;
  }

  const overscan = 6;
  const startIndex = Math.max(0, Math.floor(effectiveScrollTop / rowHeight) - overscan);
  const visibleCount = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  const endIndex = Math.min(items.length, startIndex + visibleCount);
  const visibleRows = items.slice(startIndex, endIndex);
  const resolveKey = (row: T, idx: number): string => {
    if (typeof rowKey === 'function') return rowKey(row, idx);
    if (typeof rowKey === 'string' && row && typeof row === 'object' && rowKey in row) {
      return String((row as Record<string, unknown>)[rowKey as string]);
    }
    if (row && typeof row === 'object' && 'id' in row) {
      return String((row as Record<string, unknown>).id);
    }
    return String(idx);
  };

  return (
    <div className="cm-vtable" role="table">
      <div className="cm-vtable-header" role="row">
        {columns.map((col) => {
          const style: React.CSSProperties = {
            width: col.width !== undefined ? (typeof col.width === 'number' ? `${col.width}px` : col.width) : undefined,
            flex: col.flex !== undefined ? `${col.flex} 1 0%` : col.width !== undefined ? '0 0 auto' : '1 1 0%',
            textAlign: col.align || 'left',
            justifyContent:
              col.align === 'center' ? 'center' : col.align === 'right' ? 'flex-end' : 'flex-start',
          };
          return (
            <div key={col.key} role="columnheader" className="cm-vtable-header-cell" style={style}>
              {col.header}
            </div>
          );
        })}
      </div>
      <div
        ref={containerRef}
        className="cm-vtable-body"
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        {items.length === 0 ? (
          <div className="cm-vtable-no-rows">{t('Không có dữ liệu hiển thị.', 'No data to display.')}</div>
        ) : (
          <div className="cm-vtable-spacer" style={{ height: `${totalHeight}px` }}>
            {visibleRows.map((row, offset) => {
              const index = startIndex + offset;
              const key = resolveKey(row, index);
              const selected = selectedKeys ? selectedKeys.has(key) : false;
              return (
                <VirtualRow
                  key={key}
                  row={row}
                  index={index}
                  columns={columns}
                  rowHeight={rowHeight}
                  top={index * rowHeight}
                  selected={selected}
                  onRowDoubleClick={onRowDoubleClick}
                  onRowContextMenu={onRowContextMenu}
                />
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

export interface EmptyStateProps {
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
  secondaryLabel?: string;
  onSecondaryAction?: () => void;
}

export function EmptyState({
  title,
  description,
  actionLabel,
  onAction,
  secondaryLabel,
  onSecondaryAction,
}: EmptyStateProps) {
  return (
    <div className="cm-empty-state">
      <div className="cm-empty-card">
        <h3 className="cm-empty-title">{title}</h3>
        {description ? <p className="cm-empty-desc">{description}</p> : null}
        {(actionLabel || secondaryLabel) ? (
          <div className="cm-empty-actions">
            {actionLabel && onAction ? (
              <Button variant="primary" onClick={onAction}>
                {actionLabel}
              </Button>
            ) : null}
            {secondaryLabel && onSecondaryAction ? (
              <Button variant="secondary" onClick={onSecondaryAction}>
                {secondaryLabel}
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export interface StatusBadgeProps {
  state?: string;
  error?: string;
}

export function StatusBadge({ state = 'stopped', error = '' }: StatusBadgeProps) {
  const { t } = useI18n();
  const s = (state || 'stopped').toLowerCase();
  let label = t('Đã dừng', 'Stopped');
  let cls = 'cm-badge-stopped';
  if (s === 'running') {
    label = t('Đang chạy', 'Running');
    cls = 'cm-badge-running';
  } else if (s === 'starting') {
    label = t('Đang mở...', 'Starting...');
    cls = 'cm-badge-starting';
  } else if (s === 'stopping') {
    label = t('Đang dừng...', 'Stopping...');
    cls = 'cm-badge-starting';
  } else if (s === 'error') {
    label = t('Lỗi', 'Error');
    cls = 'cm-badge-error';
  }
  return (
    <span className={`cm-badge ${cls}`} title={error || label}>
      {label}
    </span>
  );
}

export function formatDate(value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '-';
  try {
    const d = typeof value === 'number' ? new Date(value * (value < 1e12 ? 1000 : 1)) : new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    const iso = new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString();
    return `${iso.slice(0, 10)} ${iso.slice(11, 19)}`;
  } catch {
    return String(value);
  }
}

export function formatBytes(bytes?: number | null): string {
  if (bytes === undefined || bytes === null || Number.isNaN(bytes)) return '-';
  const num = Number(bytes);
  if (num < 1024) return `${num} B`;
  if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
  if (num < 1024 * 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
  return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
