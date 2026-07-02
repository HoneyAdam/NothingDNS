import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface Props {
  children: ReactNode;
  /** Reset key — when it changes (e.g. route path), the boundary clears its error. */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

// ErrorBoundary keeps a render error in one page from white-screening the
// whole app (sidebar, shell, everything). React has no hook equivalent, so
// this stays a class component. On route change (resetKey) it self-heals.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Keep a console trail for debugging; the user sees the panel below.
    console.error('Unhandled render error:', error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-[60vh] items-center justify-center p-6" role="alert">
          <div className="max-w-md rounded-lg border border-border bg-card p-8 text-center shadow-sm">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
              <AlertTriangle className="h-6 w-6 text-destructive" />
            </div>
            <h2 className="mb-1 text-lg font-semibold text-card-foreground">Something went wrong</h2>
            <p className="mb-5 text-sm text-muted-foreground break-words">
              {this.state.error.message || 'An unexpected error occurred while rendering this page.'}
            </p>
            <Button onClick={() => this.setState({ error: null })}>
              <RefreshCw className="h-4 w-4" />
              Try again
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
