import { create } from 'zustand';
import type { QueryEvent } from '@/lib/api';

// Shared live-query stream. A SINGLE WebSocket is opened once at the app root
// (App.tsx) and feeds events here; pages (e.g. the dashboard) read from this
// store instead of each opening their own `/ws` connection. This avoids the
// previous bug where the dashboard and the app shell held two independent
// sockets with two reconnect loops.
const MAX_EVENTS = 100;

interface QueryStreamState {
  events: QueryEvent[];
  connected: boolean;
  pushEvent: (event: QueryEvent) => void;
  setConnected: (connected: boolean) => void;
}

export const useQueryStream = create<QueryStreamState>((set) => ({
  events: [],
  connected: false,
  pushEvent: (event) =>
    set((state) => ({ events: [event, ...state.events].slice(0, MAX_EVENTS) })),
  setConnected: (connected) => set({ connected }),
}));
