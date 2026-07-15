import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ErrorState, EmptyState } from './states';

describe('ErrorState', () => {
  it('renders default message', () => {
    render(<ErrorState />);
    expect(screen.getByText('Failed to load')).toBeInTheDocument();
    expect(screen.getByText('The request could not be completed.')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('renders custom message', () => {
    render(<ErrorState message="Connection refused" />);
    expect(screen.getByText('Connection refused')).toBeInTheDocument();
  });

  it('renders retry button when onRetry is provided', () => {
    const onRetry = vi.fn();
    render(<ErrorState onRetry={onRetry} />);
    const retry = screen.getByText('Retry');
    expect(retry).toBeInTheDocument();
  });

  it('calls onRetry when clicked', async () => {
    const onRetry = vi.fn();
    const user = userEvent.setup();
    render(<ErrorState onRetry={onRetry} />);
    await user.click(screen.getByText('Retry'));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('does not render retry button without onRetry', () => {
    render(<ErrorState />);
    expect(screen.queryByText('Retry')).not.toBeInTheDocument();
  });
});

describe('EmptyState', () => {
  it('renders title and description', () => {
    render(<EmptyState title="No zones found" description="Create your first zone to get started." />);
    expect(screen.getByText('No zones found')).toBeInTheDocument();
    expect(screen.getByText('Create your first zone to get started.')).toBeInTheDocument();
  });

  it('renders action button when provided', () => {
    render(
      <EmptyState
        title="Empty"
        action={<button type="button">Add zone</button>}
      />,
    );
    expect(screen.getByText('Add zone')).toBeInTheDocument();
  });

  it('renders without description', () => {
    render(<EmptyState title="Just a title" />);
    expect(screen.getByText('Just a title')).toBeInTheDocument();
    // No description should be present
    expect(screen.queryByText('Create your first zone to get started.')).not.toBeInTheDocument();
  });
});
