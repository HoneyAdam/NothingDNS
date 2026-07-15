import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfirmDialog } from './confirm-dialog';

describe('ConfirmDialog', () => {
  it('renders when open', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Delete zone"
        description="This action cannot be undone."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText('Delete zone')).toBeInTheDocument();
    expect(screen.getByText('This action cannot be undone.')).toBeInTheDocument();
    expect(screen.getByText('Confirm')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    render(
      <ConfirmDialog
        open={false}
        title="Delete zone"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.queryByText('Delete zone')).not.toBeInTheDocument();
  });

  it('calls onConfirm when confirm is clicked', async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(
      <ConfirmDialog
        open={true}
        title="Delete zone"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('calls onCancel when cancel is clicked', async () => {
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(
      <ConfirmDialog
        open={true}
        title="Confirm"
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );
    await user.click(screen.getByText('Cancel'));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it('disables buttons while loading', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Deleting..."
        loading={true}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText('Confirm')).toBeDisabled();
    expect(screen.getByText('Cancel')).toBeDisabled();
  });

  it('renders destructive variant', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Delete"
        destructive={true}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    const confirmBtn = screen.getByText('Confirm');
    expect(confirmBtn).toBeInTheDocument();
    // The button should have the destructive variant class
    expect(confirmBtn.className).toContain('destructive');
  });

  it('uses custom button labels', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Save"
        confirmLabel="Save changes"
        cancelLabel="Keep editing"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText('Save changes')).toBeInTheDocument();
    expect(screen.getByText('Keep editing')).toBeInTheDocument();
  });

  it('shows spinner when loading', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Processing"
        loading={true}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    // The Loader2 icon has the animate-spin class
    const loader = document.querySelector('.animate-spin');
    expect(loader).toBeInTheDocument();
  });

  it('calls onCancel when dialog is dismissed via backdrop', async () => {
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(
      <ConfirmDialog
        open={true}
        title="Dismiss test"
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );
    // Press Escape to dismiss
    await user.keyboard('{Escape}');
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it('does not call onCancel when loading and dialog is dismissed', async () => {
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(
      <ConfirmDialog
        open={true}
        title="Loading dismiss"
        loading={true}
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );
    // Press Escape — loading is true so onCancel should not fire
    await user.keyboard('{Escape}');
    expect(onCancel).not.toHaveBeenCalled();
  });
});
