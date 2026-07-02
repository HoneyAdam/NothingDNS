import type { ComponentType, ReactNode } from 'react';
import { AlertCircle, RefreshCw, Inbox, type LucideProps } from 'lucide-react';
import { Button } from '@/components/ui/button';

// ErrorState — the standard "the request failed" panel. Distinct from an empty
// state: a failed fetch must NOT look like "no data configured", which would
// invite the user to recreate things that already exist.
export function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-card px-6 py-12 text-center" role="alert">
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-destructive/10">
        <AlertCircle className="h-5 w-5 text-destructive" />
      </div>
      <p className="mb-1 text-sm font-medium text-card-foreground">Failed to load</p>
      <p className="mb-5 max-w-sm text-sm text-muted-foreground break-words">
        {message || 'The request could not be completed.'}
      </p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="h-4 w-4" />
          Retry
        </Button>
      )}
    </div>
  );
}

// EmptyState — the standard "nothing here yet" panel with an optional CTA.
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
}: {
  icon?: ComponentType<LucideProps>;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 py-12 text-center">
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-muted">
        <Icon className="h-5 w-5 text-muted-foreground" />
      </div>
      <p className="mb-1 text-sm font-medium text-foreground">{title}</p>
      {description && <p className="mb-5 max-w-sm text-sm text-muted-foreground">{description}</p>}
      {action}
    </div>
  );
}
