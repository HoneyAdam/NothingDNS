#!/usr/bin/env node
// Regression guard for the worst class of dashboard bug: a shadcn/ui component
// references a color token (bg-card, bg-popover, border-input, ...) that is not
// defined in index.css. In Tailwind v4 an undefined color token means the
// utility class is simply NOT GENERATED — the build succeeds, tsc passes, and
// the app ships with transparent cards and see-through floating menus.
//
// This asserts the load-bearing utility classes are present in the built CSS.
// Runs as part of `npm run build`, so a token that goes missing fails the build
// instead of shipping silently.
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const distAssets = fileURLToPath(new URL('../../internal/dashboard/static/dist/assets/', import.meta.url));

// Utility classes that MUST exist, each keyed to the component(s) that break
// without it. Escaped for use inside a `.<class>` regex.
const required = [
  'bg-card',
  'text-card-foreground',
  'bg-popover',
  'text-popover-foreground',
  'border-input',
  'bg-background',
  'bg-primary',
  'text-muted-foreground',
  'bg-surface',
  'bg-accent',
];

const cssFiles = readdirSync(distAssets).filter((f) => /^index-.*\.css$/.test(f));
if (cssFiles.length === 0) {
  console.error('verify-css-tokens: no built index-*.css found in', distAssets);
  process.exit(1);
}
// Use the newest built CSS.
const cssFile = cssFiles.sort().at(-1);
const css = readFileSync(distAssets + cssFile, 'utf8');

const missing = required.filter((cls) => {
  const esc = cls.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Match the class as a selector: `.<class>` followed by a CSS boundary.
  return !new RegExp(`\\.${esc}[\\s{,:>~+.]`).test(css);
});

if (missing.length > 0) {
  console.error(`verify-css-tokens: FAIL — ${missing.length} required utility class(es) missing from ${cssFile}:`);
  for (const m of missing) console.error(`  .${m}  (likely an undefined --color-* token in src/index.css)`);
  process.exit(1);
}

console.log(`verify-css-tokens: OK — all ${required.length} required utility classes present in ${cssFile}`);
