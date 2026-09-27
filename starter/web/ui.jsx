// Small shared pieces: the presence gate, error display, and org theming.

import React from 'react';

// Is `permission` allowed in a resolved set the SERVER sent? The only question the console
// ever asks about authority, and it never computes the answer itself.
export const allowed = (set, permission) => set?.[permission]?.effect === 'allow';

// Present or absent, never disabled. If the server's set allows `permission`, render the
// child with data-permission and data-state="unlocked"; otherwise render nothing at all.
export function Gate({ set, permission, children }) {
  if (!permission || !allowed(set, permission)) return null;
  return React.cloneElement(children, { 'data-permission': permission, 'data-state': 'unlocked' });
}

// A failed request is never silent: show the server's own message, and its code.
export function ErrorNote({ error, testId = 'action-error' }) {
  if (!error) return null;
  return (
    <p className="error" role="alert" data-testid={testId} data-error-code={error.code}>
      {error.message}{error.reason ? ` (${error.reason})` : ''}
    </p>
  );
}

// Org identity. Colours are keyed by the org's theme NAME, which is presentation, not
// authority. An unknown theme still gets a stable colour of its own, derived from the name.
const THEMES = {
  cobalt: { accent: '#1d4ed8', bg: '#eef2ff' },
  amber: { accent: '#b45309', bg: '#fff7e6' },
  emerald: { accent: '#047857', bg: '#ecfdf5' },
  rose: { accent: '#be123c', bg: '#fff1f2' },
  violet: { accent: '#6d28d9', bg: '#f5f3ff' },
  slate: { accent: '#334155', bg: '#f1f5f9' },
};

export function themeStyle(theme = '') {
  const known = THEMES[theme];
  if (known) return { '--accent': known.accent, background: known.bg };
  let hue = 0;
  for (const ch of theme) hue = (hue * 31 + ch.charCodeAt(0)) % 360;
  return { '--accent': `hsl(${hue} 60% 35%)`, background: `hsl(${hue} 70% 96%)` };
}

export const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
