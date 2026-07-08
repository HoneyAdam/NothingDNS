# NothingDNS Web Dashboard

React 19 + TypeScript + Vite dashboard for NothingDNS. The source lives in `web/src/`; production assets are built into `internal/dashboard/static/dist/` and embedded/served by the Go API server.

## Stack

- React 19 with `react-router-dom` routes
- TypeScript 6
- Vite 8
- Tailwind CSS 4 via `@tailwindcss/vite`
- TanStack Query for API state
- Zustand for auth/query-stream state
- Radix UI primitives plus local `components/ui/*`
- Sonner for toast notifications

## Routes

The dashboard routes are defined in `src/App.tsx`:

| Route | Page |
|---|---|
| `/` | Dashboard summary |
| `/zones` | Zone list |
| `/zones/:name` | Zone detail and record editing |
| `/dnssec` | DNSSEC status/keys |
| `/cluster` | Cluster status |
| `/query-log` | Live/recent query log |
| `/top-domains` | Top domains |
| `/geoip` | GeoIP/GeoDNS stats |
| `/blocklist` | Blocklist status and controls |
| `/rpz` | RPZ policy rules |
| `/acl` | ACL settings |
| `/upstreams` | Upstream resolver status |
| `/zone-transfer` | Slave/transfer state |
| `/dns64-cookies` | DNS64 and DNS Cookie state |
| `/charts` | Historical metrics charts |
| `/users` | User/RBAC management |
| `/settings` | Server settings |
| `/about` | Build/about page |

## Development

```bash
cd web
npm install
npm run dev
```

The dev server talks to the same relative API paths used in production. Run a NothingDNS API server on the expected origin or proxy traffic as needed for local development.

## Build and validation

```bash
cd web
npm run lint
npm run build
npm run smoke
```

`npm run build` runs `tsc -b`, `vite build`, and `scripts/verify-css-tokens.mjs`. The token verifier checks the built CSS under `internal/dashboard/static/dist/assets/` for required design-system utility classes so missing Tailwind v4 color tokens fail the build instead of shipping broken transparent UI surfaces.

## Authentication and API behavior

- API helpers live in `src/lib/api.ts` and call same-origin endpoints such as `/api/v1/status`.
- Bearer tokens are read from the in-memory Zustand auth store; HttpOnly cookies are not read by JavaScript.
- A `401` response clears client auth and returns the user to the login page.
- Structured backend errors are normalized from either `{ "error": "..." }` or `{ "error": { "message": "...", "code": "..." } }` shapes.
- The shared WebSocket connection is opened at `/ws` after authentication; pages subscribe via `src/stores/queryStream.ts`.

## Production assets

When dashboard code changes, regenerate and commit `internal/dashboard/static/dist/`:

```bash
cd web
npm run build
```

The Go server serves the SPA from `internal/dashboard/static/dist/`, falls back to `index.html` for non-API routes, and serves `/assets/*` directly.
