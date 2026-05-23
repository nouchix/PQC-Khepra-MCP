import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Shield, Mail, ArrowLeft, CheckCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface PasswordResetOTPProps {
  onBack: () => void;
  onSuccess: () => void;
}

const PasswordResetOTP = ({ onBack, onSuccess }: PasswordResetOTPProps) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  const { toast } = useToast();

  const handleSendResetEmail = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      toast({
        title: "Email Required",
        description: "Please enter your email address",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);

    try {
      // Use Supabase's built-in password reset (works immediately, no domain verification needed)
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${globalThis.location.origin}/auth/reset-password`,
      });

      if (error) {
        throw error;
      }

      setEmailSent(true);
      toast({
        title: "Password Reset Email Sent",
        description: "Check your email for a password reset link. The link will expire in 1 hour.",
        variant: "default"
      });

    } catch (error: any) {
      toast({
        title: "Failed to Send Reset Email",
        description: error.message || "Unable to send password reset email. Please try again.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  if (emailSent) {
    return (
      <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center mb-4">
            <CheckCircle className="h-12 w-12 text-success" />
          </div>
          <CardTitle className="text-xl text-foreground">
            Check Your Email
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-2">
            We've sent a password reset link to <strong>{email}</strong>
          </p>
          <p className="text-xs text-muted-foreground mt-2">
            The link will expire in 1 hour. If you don't see the email, check your spam folder.
          </p>
        </CardHeader>

        <CardContent className="space-y-4">
          <Button
            type="button"
            variant="cyber"
            className="w-full"
            onClick={() => {
              setEmailSent(false);
              setEmail('');
            }}
          >
            Send Another Email
          </Button>

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={onBack}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Login
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
      <CardHeader className="text-center">
        <div className="flex items-center justify-center mb-4">
          <Shield className="h-8 w-8 text-primary" />
        </div>
        <CardTitle className="text-xl text-foreground">
          Reset Your Password
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Enter your email address and we'll send you a link to reset your password
        </p>
      </CardHeader>

      <CardContent>
        <form onSubmit={handleSendResetEmail} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email" className="text-foreground flex items-center space-x-2">
              <Mail className="h-4 w-4" />
              <span>Email Address</span>
            </Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
              placeholder="Enter your email address"
              autoFocus
            />
          </div>

          <Button
            type="submit"
            variant="cyber"
            className="w-full"
            disabled={loading}
          >
            {loading ? (
              <div className="flex items-center space-x-2">
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                <span>Sending Email...</span>
              </div>
            ) : (
              <div className="flex items-center space-x-2">
                <Mail className="h-4 w-4" />
                <span>Send Reset Link</span>
              </div>
            )}
          </Button>

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={onBack}
            disabled={loading}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Login
          </Button>
        </form>
      </CardContent>
    </Card>
  );
};

export default PasswordResetOTP;