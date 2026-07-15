import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ThemeProvider, ThemeContext } from './useTheme';
import { useContext } from 'react';

// Consumer component to read theme context
function ThemeConsumer() {
  const ctx = useContext(ThemeContext);
  return (
    <div>
      <span data-testid="theme">{ctx.resolved}</span>
      <button onClick={() => ctx.setTheme('dark')}>Set dark</button>
    </div>
  );
}

describe('ThemeProvider', () => {
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
});
