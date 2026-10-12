import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { isTauri } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { request } from './api';

export type Language = 'vi' | 'en';

interface I18n {
  language: Language;
  setLanguage: (language: Language) => void;
  t: (vi: string, en: string) => string;
  locale: 'vi-VN' | 'en-US';
}

const storageKey = 'camoumanager.language';
const I18nContext = createContext<I18n | null>(null);

export function LocaleProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() => {
    try {
      return localStorage.getItem(storageKey) === 'en' ? 'en' : 'vi';
    } catch {
      return 'vi';
    }
  });
  const setLanguage = useCallback((next: Language) => {
    try {
      localStorage.setItem(storageKey, next);
    } catch (error) {
      console.warn('Could not save the interface language preference.', error);
    }
    setLanguageState(next);
  }, []);
  const t = useCallback((vi: string, en: string) => language === 'en' ? en : vi, [language]);

  useEffect(() => {
    document.documentElement.lang = language;
    if (isTauri()) {
      request('app.language', { language }).catch(error => console.error('Could not update the native interface language.', error));
      getCurrentWindow().setTitle(t('CamouManager - Quản lý trình duyệt Camoufox', 'CamouManager - Camoufox Browser Manager'))
        .catch(error => console.error('Could not update the window title.', error));
    }
  }, [language, t]);

  const value = useMemo<I18n>(() => ({ language, setLanguage, t, locale: language === 'en' ? 'en-US' : 'vi-VN' }), [language, setLanguage, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  const value = useContext(I18nContext);
  if (!value) throw new Error('useI18n must be used within LocaleProvider.');
  return value;
}
