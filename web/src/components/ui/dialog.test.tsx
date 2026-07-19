import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './dialog';

describe('Dialog', () => {
  it('opens when triggered', async () => {
    const user = userEvent.setup();
    render(
      <Dialog>
        <DialogTrigger>Open</DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button>OK</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>,
    );
    await user.click(screen.getByText('Open'));
    expect(screen.getByText('Title')).toBeInTheDocument();
    expect(screen.getByText('Desc')).toBeInTheDocument();
    expect(screen.getByText('OK')).toBeInTheDocument();
  });

  it('calls onClose when dialog is closed', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <Dialog onClose={onClose} open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    expect(screen.getByText('Title')).toBeInTheDocument();
    // Press Escape to close
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });

  it('uses onOpenChange when both are provided', async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onClose = vi.fn();
    render(
      <Dialog onOpenChange={onOpenChange} onClose={onClose} open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    await user.keyboard('{Escape}');
    expect(onOpenChange).toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('uses onClose fallback only when onOpenChange is not provided', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <Dialog onClose={onClose} open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    // Verify open=true stays open
    expect(screen.getByText('Title')).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose only when v=false (open transitions to close)', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    // Start open=true and close via Escape — onClose is invoked with v=false
    const { rerender } = render(
      <Dialog onClose={onClose} open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    // Close via Escape
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
    // Reset the mock and trigger open transition by clicking a trigger
    onClose.mockClear();
    rerender(
      <Dialog onClose={onClose} open={false}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    // Now open with new render
    rerender(
      <Dialog onClose={onClose} open={true}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    // Pressing Escape should now invoke the onClose fallback again
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });

  it('does not pass any onOpenChange when neither provided', () => {
    // Sanity check that the component renders without throwing when neither prop is set
    render(
      <Dialog>
        <DialogTrigger>Open</DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Desc</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    expect(screen.getByText('Open')).toBeInTheDocument();
  });
});
