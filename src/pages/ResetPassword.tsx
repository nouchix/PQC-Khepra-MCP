import { useState, useEffect } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Shield, Lock, Eye, EyeOff, CheckCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const ResetPassword = () => {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [isValidSession, setIsValidSession] = useState(false);
    const navigate = useNavigate();
    const { toast } = useToast();

    useEffect(() => {
        // Check if user has a valid recovery session
        supabase.auth.getSession().then(({ data: { session } }) => {
            if (session) {
                setIsValidSession(true);
            } else {
                toast({
                    title: "Invalid or Expired Link",
                    description: "This password reset link is invalid or has expired. Please request a new one.",
                    variant: "destructive"
                });
                setTimeout(() => navigate('/auth?mode=reset'), 3000);
            }
        });
    }, [navigate, toast]);

    const handleResetPassword = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!newPassword || newPassword.length < 8) {
            toast({
                title: "Invalid Password",
                description: "Password must be at least 8 characters long",
                variant: "destructive"
            });
            return;
        }

        if (newPassword !== confirmPassword) {
            toast({
                title: "Password Mismatch",
                description: "Passwords do not match",
                variant: "destructive"
            });
            return;
        }

        setLoading(true);

        try {
            const { error } = await supabase.auth.updateUser({
                password: newPassword
            });

            if (error) {
                throw error;
            }

            toast({
                title: "Password Reset Successful",
                description: "Your password has been updated. Redirecting to login...",
                variant: "default"
            });

            // Sign out and redirect to login
            await supabase.auth.signOut();
            setTimeout(() => navigate('/auth'), 2000);

        } catch (error: any) {
            toast({
                title: "Password Reset Failed",
                description: error.message || "Unable to reset password. Please try again.",
                variant: "destructive"
            });
        } finally {
            setLoading(false);
        }
    };

    if (!isValidSession) {
        return (
            <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6">
                <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
                    <CardHeader className="text-center">
                        <div className="flex items-center justify-center mb-4">
                            <Shield className="h-8 w-8 text-warning animate-pulse" />
                        </div>
                        <CardTitle className="text-xl text-foreground">
                            Verifying Reset Link...
                        </CardTitle>
                    </CardHeader>
                </Card>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6 relative overflow-hidden">
            {/* Background Effects */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--primary-glow)_0%,_transparent_50%)] opacity-10"></div>
            <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-primary/5 via-transparent to-accent/5"></div>

            <Card className="w-full max-w-md card-cyber backdrop-blur-lg relative z-10">
                <CardHeader className="text-center">
                    <div className="flex items-center justify-center mb-4">
                        <Shield className="h-8 w-8 text-primary" />
                    </div>
                    <CardTitle className="text-xl text-foreground">
                        Set New Password
                    </CardTitle>
                    <p className="text-sm text-muted-foreground">
                        Enter your new password below
                    </p>
                </CardHeader>

                <CardContent>
                    <form onSubmit={handleResetPassword} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="newPassword" className="text-foreground flex items-center space-x-2">
                                <Lock className="h-4 w-4" />
                                <span>New Password</span>
                            </Label>
                            <div className="relative">
                                <Input
                                    id="newPassword"
                                    type={showPassword ? "text" : "password"}
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    required
                                    minLength={8}
                                    className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
                                    placeholder="Enter new password (min 8 characters)"
                                    autoFocus
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
                                >
                                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                </button>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirmPassword" className="text-foreground flex items-center space-x-2">
                                <Lock className="h-4 w-4" />
                                <span>Confirm Password</span>
                            </Label>
                            <div className="relative">
                                <Input
                                    id="confirmPassword"
                                    type={showConfirmPassword ? "text" : "password"}
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                    className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
                                    placeholder="Confirm new password"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
                                >
                                    {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                </button>
                            </div>
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
                                    <span>Resetting Password...</span>
                                </div>
                            ) : (
                                <div className="flex items-center space-x-2">
                                    <CheckCircle className="h-4 w-4" />
                                    <span>Reset Password</span>
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
