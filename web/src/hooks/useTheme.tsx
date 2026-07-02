import { createContext, useEffect, useState, type ReactNode } from 'react';
import type { Theme } from '@/lib/theme';

interface ThemeContextValue {
  theme: Theme;
  resolved: 'light' | 'dark';
  setTheme: (t: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'system',
  resolved: 'dark',
  setTheme: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeRaw] = useState<Theme>(() => {
    if (typeof window !== 'undefined') {
      return (localStorage.getItem('ndns-theme') as Theme) || 'system';
    }
    return 'system';
  });
  // Initialize from the class that theme-init.js already set pre-paint, so
  // `resolved` is correct on the very first render (consumers like the themed
  // Toaster would otherwise flash the wrong theme for one frame).
  const [resolved, setResolved] = useState<'light' | 'dark'>(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark') ? 'dark' : 'light'
  );

  useEffect(() => {
    const apply = (isDark: boolean) => {
      document.documentElement.classList.toggle('dark', isDark);
      setResolved(isDark ? 'dark' : 'light');
    };

    if (theme === 'system') {
      const mq = matchMedia('(prefers-color-scheme: dark)');
      apply(mq.matches);
      const handler = (e: MediaQueryListEvent) => apply(e.matches);
      mq.addEventListener('change', handler);
      return () => mq.removeEventListener('change', handler);
    }

    apply(theme === 'dark');
  }, [theme]);

  const setTheme = (t: Theme) => {
    setThemeRaw(t);
    if (typeof window !== 'undefined') {
      localStorage.setItem('ndns-theme', t);
    }
  };

  return (
    <ThemeContext.Provider value={{ theme, resolved, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export { ThemeContext };
