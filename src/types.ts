export type MessageLevel = 'info' | 'warning' | 'error';

export interface Status {
  state: 'starting' | 'running' | 'stopping' | 'stopped' | 'error';
  pid: number | null;
  cpu_percent: number;
  memory_mb: number;
  error: string;
  egress_ip?: string;
}

export interface Location {
  ip?: string;
  country?: string;
  timezone?: string;
  locale?: string;
  latitude?: number | null;
  longitude?: number | null;
  locked?: boolean;
}

export interface Profile {
  id: string;
  name: string;
  group: string;
  tags: string[];
  note: string;
  os: string;
  browser_version: string;
  proxy_id: string;
  proxy_name?: string;
  location: Location;
  startup_urls: string[];
  bookmarks: {title: string; url: string}[];
  extensions: string[];
  fingerprint?: Record<string, unknown>;
  fingerprint_meta?: {use_preset?: boolean; generated_at?: string};
  created_at: string;
  updated_at: string;
  state?: Status['state'];
  pid?: number | null;
  cpu_percent?: number;
  memory_mb?: number;
  error?: string;
}

export interface ProxyCheck {
  ok?: boolean;
  ip?: string;
  latency_ms?: number;
  error?: string;
  checked_at?: string;
  country?: string;
  [key: string]: unknown;
}

export interface Proxy {
  id: string;
  name: string;
  server: string;
  enabled: boolean;
  username?: string;
  password?: string;
  has_password?: boolean;
  has_credentials?: boolean;
  last_check: ProxyCheck;
  created_at?: string;
  updated_at?: string;
}

export interface Version {
  id: string;
  name: string;
  path?: string;
  release_url?: string;
  asset_url?: string;
  sha256?: string;
  prerelease?: boolean;
  draft?: boolean;
  size?: number;
  installed_at?: string;
  status?: string;
  [key: string]: unknown;
}

export interface Settings {
  max_running: number;
  default_proxy_id: string;
  auto_assign_proxy: boolean;
  backup_interval_hours: number;
  backup_retention: number;
  auto_check_updates?: boolean;
  update_check_hours: number;
  auto_download_updates: boolean;
  last_scheduled_backup_at?: string;
  last_update_check_at?: string;
  [key: string]: unknown;
}

export interface BackupState {
  state: 'disabled' | 'password_required' | 'waiting' | 'running' | 'error';
  message: string;
  last_at: string;
}

export interface Backup {
  path: string;
  filename: string;
  size: number;
  size_mb?: number;
  created_at: string;
  is_encrypted: boolean;
  is_scheduled: boolean;
  profiles_count: number | null;
  has_proxy_credentials: boolean | null;
  warning?: string;
}

export interface BackupInspection {
  path: string;
  created_at: string;
  is_encrypted: boolean;
  profiles_count: number;
  profiles: Profile[];
  proxies: Proxy[];
  missing_versions: string[];
  warning: string;
  compatibility_warning: string;
  compatibility_notes: string;
  file_count: number;
  total_size: number;
  [key: string]: unknown;
}

export interface FingerprintData {
  updated_at: string;
  files: {name: string; count?: number; min_firefox_version?: number; [key: string]: unknown}[];
  snapshot?: string;
  source?: string;
}

export interface AppSnapshot {
  profiles: Profile[];
  proxies: Proxy[];
  versions: Version[];
  settings: Settings;
  fingerprint_data: FingerprintData;
  root: string;
  backup: BackupState;
}

export type InstallationState =
  | 'idle'
  | 'downloading'
  | 'paused'
  | 'verifying'
  | 'extracting'
  | 'installing'
  | 'completed'
  | 'cancelled'
  | 'error';

export interface InstallationStatus {
  version_id: string;
  name: string;
  state: InstallationState;
  downloaded_bytes: number;
  total_bytes: number | null;
  error: string;
}

export type InstallationAction = 'pause' | 'resume' | 'cancel';

export interface InstallationControlParams {
  id: string;
  action: InstallationAction;
}

export interface StatusEvent {
  statuses: Record<string, Status>;
  running_count: number;
  max_running: number;
  backup: BackupState;
  busy: number;
  installation?: InstallationStatus;
}

export interface PageProps {
  snapshot: AppSnapshot;
  onRefresh: () => Promise<void>;
  onMessage: (message: string, level?: MessageLevel) => void;
}

export interface BatchResult {
  succeeded: string[];
  errors: {id: string; message: string}[];
}

export interface LogRow {
  id: number;
  time: string;
  level: string;
  profile_id: string;
  message: string;
}

export interface UpdateResult {
  has_update: boolean;
  latest_version: Version | null;
  current_version: string;
  error?: string;
}
