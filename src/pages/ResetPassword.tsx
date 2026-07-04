// pages/ResetPassword.tsx
// Re-exports the view that handles the actual PKCE token exchange + password update.
// Previous version called supabase.auth.getSession() (stub → null) which immediately
// redirected to /auth?mode=reset, destroying the recovery code in the URL.
export { default } from '@/views/ResetPassword';
