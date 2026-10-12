import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import type { MessageLevel, StatusEvent } from './types';

export async function request<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>('app_request', { method, params });
}

type Filter = { name: string; extensions: string[] };
export async function openPath(options: { directory?: boolean; filters?: Filter[] } = {}): Promise<string | null> {
  const selected = await open({ multiple: false, ...options });
  return typeof selected === 'string' ? selected : null;
}
export function savePath(options: { defaultPath?: string; filters?: Filter[] } = {}): Promise<string | null> {
  return save(options);
}

export function subscribeStatus(handler: (data: StatusEvent) => void): Promise<() => void> {
  return listen<StatusEvent>('app:status', event => handler(event.payload));
}
export function subscribeChanged(handler: (data: { resource: string }) => void): Promise<() => void> {
  return listen<{ resource: string }>('app:changed', event => handler(event.payload));
}
export function subscribeNotice(handler: (data: { level: MessageLevel; message: string }) => void): Promise<() => void> {
  return listen<{ level: MessageLevel; message: string }>('app:notice', event => handler(event.payload));
}
