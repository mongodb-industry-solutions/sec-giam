// The console's own identity. GIAM is a product in its own right, so it has a name of its own rather
// than borrowing the name of any application it protects.
//
// Per-realm and per-client theming (the login page rendering as the relying party's own) overrides
// this at render time from the realm's branding block. This is only the default.
export const BRAND = {
  primary: process.env.NEXT_PUBLIC_GIAM_NAME_PRIMARY || 'GIAM',
  secondary: process.env.NEXT_PUBLIC_GIAM_NAME_SECONDARY || '',
  get full() {
    return [this.primary, this.secondary].filter(Boolean).join(' ');
  },
  // GIAM: General Identity and Access Manager.
  expansion: 'General Identity and Access Manager',
  tagline: 'Identity and access for people and systems',
} as const;
