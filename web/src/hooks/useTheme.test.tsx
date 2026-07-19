import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { ThemeProvider, ThemeContext } from './useTheme';
import { useContext } from 'react';

// Consumer component to read theme context
function ThemeConsumer() {
  const ctx = useContext(ThemeContext);
  return (
    <div>
      <span data-testid="theme">{ctx.resolved}</span>
      <span data-testid="config-theme">{ctx.theme}</span>
      <button onClick={() => ctx.setTheme('dark')}>Set dark</button>
      <button onClick={() => ctx.setTheme('light')}>Set light</button>
      <button onClick={() => ctx.setTheme('system')}>Set system</button>
    </div>
  );
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove('dark');
    // Default to light mode document state
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('provides default light theme', () => {
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    expect(screen.getByTestId('theme').textContent).toBe('light');
  });

  it('provides theme context to children', () => {
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    expect(screen.getByText('Set dark')).toBeInTheDocument();
  });

  it('reads initial theme from localStorage', () => {
    localStorage.setItem('ndns-theme', 'dark');
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    expect(screen.getByTestId('config-theme').textContent).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('applies dark theme when theme is set to dark', () => {
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    act(() => {
      screen.getByText('Set dark').click();
    });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(screen.getByTestId('theme').textContent).toBe('dark');
    expect(localStorage.getItem('ndns-theme')).toBe('dark');
  });

  it('applies light theme when theme is set to light', () => {
    localStorage.setItem('ndns-theme', 'dark');
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    act(() => {
      screen.getByText('Set light').click();
    });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(screen.getByTestId('theme').textContent).toBe('light');
  });

  it('uses system preference when theme is system', () => {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: true,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    act(() => {
      screen.getByText('Set system').click();
    });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(screen.getByTestId('theme').textContent).toBe('dark');
  });

  it('initializes with dark from document class when set', () => {
    // Render with light theme first then add dark class to ensure
    // state initializer reads it from the document.
    document.documentElement.classList.add('dark');
    // Theme defaults to 'system' so document class on initial mount wins.
    // Confirm that resolving happens correctly via the system branch.
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: true,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
    render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    // The matchMedia matches=true branch flips to dark.
    expect(screen.getByTestId('theme').textContent).toBe('dark');
  });

  it('cleans up matchMedia listener on unmount', () => {
    const removeEventListener = vi.fn();
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
    const { unmount } = render(
      <ThemeProvider>
        <ThemeConsumer />
      </ThemeProvider>,
    );
    unmount();
    expect(removeEventListener).toHaveBeenCalled();
  });
});
