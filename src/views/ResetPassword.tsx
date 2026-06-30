"use client";
import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from '@/lib/router-compat';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Shield, Lock, Eye, EyeOff, CheckCircle, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

/**
 * /auth/reset-password
 *
 * Landing page for the Supabase password reset email link.
 * Supabase sends the user here with ?code=xxx (PKCE flow) in the query params.
 *
 * Previous behaviour: immediately redirect to /auth?mode=reset — destroying
 * the auth code. This page now handles the reset inline.
 *
 * Flow:
 *   1. Read ?code from URL (Supabase PKCE recovery code)
 *   2. User enters new password + confirm
 *   3. POST /api/auth/update-password { code, password }
 *   4. Server exchanges code → session → updates password
 *   5. Redirect to /auth (login) on success
 */
const ResetPassword = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { toast } = useToast();

  const code = searchParams.get('code') || searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  // If no code in URL, the user may have landed here directly or the link expired
  const hasCode = code.length > 0;

  // Auto-redirect after success
  useEffect(() => {
    if (done) {
      const timer = setTimeout(() => navigate('/auth'), 3000);
      return () => clearTimeout(timer);
    }
  }, [done, navigate]);

  const passwordOk = password.length >= 8;
  const confirmOk  = password === confirm && confirm.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!passwordOk) {
      toast({ title: 'Password too short', description: 'At least 8 characters required.', variant: 'destructive' });
      return;
    }
    if (!confirmOk) {
      toast({ title: 'Passwords do not match', description: 'Both fields must match.', variant: 'destructive' });
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/auth/update-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error((data as any)?.error || `Error ${res.status}`);
      }

      setDone(true);
      toast({
        title: 'Password updated!',
        description: 'Your password has been reset. Redirecting to login…',
        variant: 'default',
      });
    } catch (err: any) {
      toast({
        title: 'Password reset failed',
        description: err.message || 'Please request a new reset link.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  // ── Success state ────────────────────────────────────────────────────────────
  if (done) {
    return (
      <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-4">
        <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <CheckCircle className="h-14 w-14 text-success" />
            </div>
            <CardTitle className="text-xl text-foreground">Password Updated</CardTitle>
            <p className="text-sm text-muted-foreground">
              Your password has been reset successfully. Redirecting to login in 3 seconds…
            </p>
          </CardHeader>
          <CardContent>
            <Button className="w-full" variant="cyber" onClick={() => navigate('/auth')}>
              Go to Login Now
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── No code in URL ───────────────────────────────────────────────────────────
  if (!hasCode) {
    return (
      <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-4">
        <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <AlertTriangle className="h-14 w-14 text-warning" />
            </div>
            <CardTitle className="text-xl text-foreground">Link Invalid or Expired</CardTitle>
            <p className="text-sm text-muted-foreground">
              This password reset link is missing its security token. It may have expired
              (links are valid for 1 hour) or been used already.
            </p>
          </CardHeader>
          <CardContent>
            <Button className="w-full" variant="cyber" onClick={() => navigate('/auth?mode=reset')}>
              Request a New Reset Link
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── New password form ────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-4">
      <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center mb-2">
            <div className="p-3 rounded-xl bg-primary/10 border border-primary/20">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <CardTitle className="text-xl text-foreground">Set New Password</CardTitle>
          <p className="text-sm text-muted-foreground">
            Choose a strong password. Must be at least 8 characters.
          </p>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* New password */}
            <div className="space-y-2">
              <Label htmlFor="new-password" className="text-foreground flex items-center gap-2">
                <Lock className="h-4 w-4" />
                New Password
              </Label>
              <div className="relative">
                <Input
                  id="new-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
                  placeholder="Minimum 8 characters"
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {password.length > 0 && !passwordOk && (
                <p className="text-xs text-destructive">Too short — minimum 8 characters</p>
              )}
            </div>

            {/* Confirm password */}
            <div className="space-y-2">
              <Label htmlFor="confirm-password" className="text-foreground flex items-center gap-2">
                <Lock className="h-4 w-4" />
                Confirm Password
              </Label>
              <Input
                id="confirm-password"
                type={showPassword ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
                placeholder="Repeat your new password"
              />
              {confirm.length > 0 && !confirmOk && (
                <p className="text-xs text-destructive">Passwords do not match</p>
              )}
            </div>

            <Button
              type="submit"
              variant="cyber"
              className="w-full"
              disabled={loading || !passwordOk || !confirmOk}
            >
              {loading ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  <span>Updating password…</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4" />
                  <span>Set New Password</span>
                </div>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

export default ResetPassword;
