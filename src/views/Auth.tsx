import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useSearchParams } from '@/lib/router-compat';
import { useAuth } from '@/hooks/useAuth';
import { useSecurityHardening } from '@/hooks/useSecurityHardening';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, User, Lock, Building, Eye, EyeOff, CheckCircle, Fingerprint, Mail } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import PasswordResetOTP from '@/components/auth/PasswordResetOTP';

const Auth = () => {
  const [searchParams] = useSearchParams();
  const mode = searchParams.get('mode');
  const [activeTab, setActiveTab] = useState('login');
  const [showPasswordReset, setShowPasswordReset] = useState(mode === 'reset');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [department, setDepartment] = useState('');
  const [securityClearance, setSecurityClearance] = useState('UNCLASSIFIED');
  const [loading, setLoading] = useState(false);
  const [showEmailVerification, setShowEmailVerification] = useState(false);
  const [registeredEmail, setRegisteredEmail] = useState('');
  const [lockoutSeconds, setLockoutSeconds] = useState(0);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const loginEmailRef = useRef<HTMLInputElement>(null);
  const regEmailRef = useRef<HTMLInputElement>(null);

  const { signIn, signUp, user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const {
    validateInput,
    trackAuthAttempt,
    isAccountLocked,
    getLockoutTimeRemaining,
    checkPasswordStrength
  } = useSecurityHardening();

  const [passwordStrengthData, setPasswordStrengthData] = useState({ score: 0, feedback: [] as string[], isStrong: false });

  useEffect(() => {
    if (password) {
      setPasswordStrengthData(checkPasswordStrength(password));
    }
  }, [password]);

  useEffect(() => {
    if (user) {
      navigate('/dashboard');
    }
  }, [user, navigate]);

  // Dynamic lockout countdown
  useEffect(() => {
    if (!isAccountLocked()) {
      setLockoutSeconds(0);
      return;
    }

    const updateTimer = () => {
      const remaining = getLockoutTimeRemaining();
      if (remaining <= 0) {
        setLockoutSeconds(0);
      } else {
        setLockoutSeconds(Math.ceil(remaining / 1000));
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [isAccountLocked, getLockoutTimeRemaining]);

  // Focus first input on tab switch
  useEffect(() => {
    const timer = setTimeout(() => {
      if (activeTab === 'login') {
        loginEmailRef.current?.focus();
      } else {
        regEmailRef.current?.focus();
      }
    }, 100);
    return () => clearTimeout(timer);
  }, [activeTab]);

  const clearFieldError = useCallback((field: string) => {
    setFieldErrors(prev => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }, []);

  const validateField = useCallback((field: string, value: string, type?: string): boolean => {
    if (type === 'email') {
      const result = validateInput(value, 'email');
      if (!result.isValid) {
        setFieldErrors(prev => ({ ...prev, [field]: result.error || 'Invalid email' }));
        return false;
      }
    }
    clearFieldError(field);
    return true;
  }, [validateInput, clearFieldError]);

  const handlePasswordResetSuccess = () => {
    setShowPasswordReset(false);
    toast({
      title: "Password Reset Complete",
      description: "You can now log in with your new password",
      variant: "default"
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const isLoginMode = activeTab === 'login';

    if (isAccountLocked()) return;

    // Inline field validation
    const newErrors: Record<string, string> = {};
    let hasErrors = false;

    const emailValidation = validateInput(email, 'email');
    if (!emailValidation.isValid) {
      newErrors.email = emailValidation.error || 'Invalid email address';
      hasErrors = true;
    }

    if (isLoginMode) {
      if (!password) {
        newErrors.password = 'Password is required';
        hasErrors = true;
      }
    } else {
      const passwordValidation = validateInput(password, 'password');
      if (!passwordValidation.isValid) {
        newErrors.password = passwordValidation.error || 'Invalid password';
        hasErrors = true;
      } else if (!passwordStrengthData.isStrong) {
        newErrors.password = 'Password must meet all security requirements';
        hasErrors = true;
      }

      if (!username) {
        newErrors.username = 'Username is required';
        hasErrors = true;
      } else {
        const usernameValidation = validateInput(username, 'username');
        if (!usernameValidation.isValid) {
          newErrors.username = usernameValidation.error || 'Invalid username';
          hasErrors = true;
        }
      }

      if (!fullName) {
        newErrors.fullName = 'Full name is required';
        hasErrors = true;
      }
    }

    setFieldErrors(newErrors);
    if (hasErrors) return;

    setLoading(true);

    try {
      if (isLoginMode) {
        const { error } = await signIn(email, password);

        if (error) {
          await trackAuthAttempt(false, email, {
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString()
          });

          toast({
            title: "Authentication Failed",
            description: error.message,
            variant: "destructive"
          });
        } else {
          await trackAuthAttempt(true, email, {
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString()
          });

          toast({
            title: "Access Granted",
            description: "Welcome back!",
            variant: "default"
          });

          navigate('/dashboard');
        }
      } else {
        const { error } = await signUp(email, password, {
          username,
          full_name: fullName,
          department,
          security_clearance: securityClearance,
          role: 'viewer'
        });

        if (error) {
          toast({
            title: "Registration Failed",
            description: error.message,
            variant: "destructive"
          });
        } else {
          setRegisteredEmail(email);
          setShowEmailVerification(true);
          setEmail('');
          setPassword('');
          setFieldErrors({});
          setActiveTab('login');
        }
      }
    } catch (error: any) {
      toast({
        title: "System Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getPasswordStrengthColor = () => {
    if (passwordStrengthData.score <= 2) return 'bg-destructive';
    if (passwordStrengthData.score <= 4) return 'bg-warning';
    if (passwordStrengthData.score <= 6) return 'bg-info';
    return 'bg-success';
  };

  const getPasswordStrengthText = () => {
    if (passwordStrengthData.score <= 2) return 'Weak';
    if (passwordStrengthData.score <= 4) return 'Fair';
    if (passwordStrengthData.score <= 6) return 'Good';
    return 'Strong';
  };

  const formatLockoutTime = () => {
    const minutes = Math.floor(lockoutSeconds / 60);
    const seconds = lockoutSeconds % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-4 sm:p-6 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--primary-glow)_0%,_transparent_50%)] opacity-10"></div>
      <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-primary/5 via-transparent to-accent/5"></div>

      {/* Decorative floating icons */}
      <div className="absolute top-20 left-20 animate-float hidden sm:block" aria-hidden="true">
        <Shield className="h-8 w-8 text-primary/20" />
      </div>
      <div className="absolute bottom-20 right-20 animate-float hidden sm:block" style={{ animationDelay: '2s' }} aria-hidden="true">
        <Lock className="h-6 w-6 text-accent/20" />
      </div>
      <div className="absolute top-1/2 left-10 animate-float hidden sm:block" style={{ animationDelay: '4s' }} aria-hidden="true">
        <Fingerprint className="h-10 w-10 text-primary/15" />
      </div>

      {/* Password Reset Modal */}
      <Dialog open={showPasswordReset} onOpenChange={setShowPasswordReset}>
        <DialogContent className="sm:max-w-md p-0 bg-transparent border-none shadow-none [&>button:last-child]:hidden">
          <DialogTitle className="sr-only">Reset Password</DialogTitle>
          <PasswordResetOTP
            onBack={() => setShowPasswordReset(false)}
            onSuccess={handlePasswordResetSuccess}
          />
        </DialogContent>
      </Dialog>

      <Card className="w-full max-w-[calc(100vw-2rem)] sm:max-w-lg md:max-w-xl lg:max-w-4xl card-cyber backdrop-blur-lg relative z-10">
        <CardHeader className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-2">
            <img
              src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
              alt="SouHimBou AI Logo"
              className="h-10 w-auto"
            />
            <h1 className="text-2xl sm:text-3xl font-bold bg-gradient-cyber bg-clip-text text-transparent">
              SouHimBou AI
            </h1>
          </div>
          <CardTitle className="text-lg sm:text-xl text-foreground">
            STIG-First Compliance Autopilot
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Our Platform bridges CMMC requirements and STIGs implementation, AI-powered, friction-free!
          </p>
          <Badge variant="outline" className="inline-flex items-center space-x-1 border-warning text-warning">
            <Shield className="h-3 w-3" />
            <span>DoD CLASSIFIED</span>
          </Badge>

          {/* Email Verification Notice */}
          {showEmailVerification && (
            <div className="p-4 bg-success/10 border border-success/30 rounded-lg animate-fade-in text-left" role="alert">
              <div className="flex items-center space-x-2 text-success mb-2">
                <Mail className="h-5 w-5" />
                <span className="font-semibold">Check Your Email</span>
              </div>
              <p className="text-sm text-muted-foreground">
                We sent a verification link to <strong className="text-foreground">{registeredEmail}</strong>.
                Click the link to verify your account, then sign in below.
              </p>
            </div>
          )}

          {/* Dynamic Lockout Timer */}
          {lockoutSeconds > 0 && (
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg" role="alert" aria-live="assertive">
              <div className="flex items-center space-x-2 text-destructive">
                <Lock className="h-4 w-4" />
                <span className="text-sm font-medium">Account Locked</span>
              </div>
              <p className="text-sm text-destructive/80 mt-1">
                Too many failed attempts. Try again in <strong>{formatLockoutTime()}</strong>
              </p>
            </div>
          )}
        </CardHeader>

        <CardContent>
            <Tabs
              value={activeTab}
              onValueChange={(tab) => {
                setActiveTab(tab);
                setEmail('');
                setPassword('');
                setFieldErrors({});
              }}
              className="w-full"
            >
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="login" className="flex items-center gap-2">
                <Lock className="h-4 w-4" />
                Login
              </TabsTrigger>
              <TabsTrigger value="register" className="flex items-center gap-2">
                <User className="h-4 w-4" />
                Register
              </TabsTrigger>
            </TabsList>

            {/* ── Login Tab ── */}
            <TabsContent value="login" className="mt-6">
              <form onSubmit={handleSubmit} className="space-y-4" noValidate>
                <div className="space-y-2">
                  <Label htmlFor="login-email" className="text-foreground flex items-center space-x-2">
                    <User className="h-4 w-4" />
                    <span>Email Address</span>
                  </Label>
                  <Input
                    ref={loginEmailRef}
                    id="login-email"
                    type="email"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); clearFieldError('email'); }}
                    onBlur={() => email && validateField('email', email, 'email')}
                    required
                    aria-invalid={!!fieldErrors.email}
                    aria-describedby={fieldErrors.email ? 'login-email-error' : undefined}
                    className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
                    placeholder="Enter your email"
                  />
                  {fieldErrors.email && (
                    <p id="login-email-error" className="text-sm text-destructive" role="alert">{fieldErrors.email}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="login-password" className="text-foreground flex items-center space-x-2">
                    <Lock className="h-4 w-4" />
                    <span>Password</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="login-password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => { setPassword(e.target.value); clearFieldError('password'); }}
                      required
                      aria-invalid={!!fieldErrors.password}
                      aria-describedby={fieldErrors.password ? 'login-password-error' : undefined}
                      className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p id="login-password-error" className="text-sm text-destructive" role="alert">{fieldErrors.password}</p>
                  )}
                </div>

                <Button
                  type="submit"
                  variant="cyber"
                  className="w-full"
                  disabled={loading || lockoutSeconds > 0}
                >
                  {loading ? (
                    <div className="flex items-center space-x-2">
                      <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" aria-hidden="true" />
                      <span>Authenticating...</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <Lock className="h-4 w-4" />
                      <span>Authenticate</span>
                    </div>
                  )}
                </Button>

                <div className="text-center">
                  <button
                    type="button"
                    onClick={() => setShowPasswordReset(true)}
                    className="text-sm text-primary hover:text-primary-glow transition-colors px-4 py-2 rounded-md hover:bg-primary/5 min-h-[44px] min-w-[44px]"
                    disabled={loading || lockoutSeconds > 0}
                  >
                    Forgot your password?
                  </button>
                </div>
              </form>
            </TabsContent>

            {/* ── Register Tab ── */}
            <TabsContent value="register" className="mt-6">
              <form onSubmit={handleSubmit} className="space-y-4" noValidate>
                <div className="space-y-2">
                  <Label htmlFor="reg-email" className="text-foreground flex items-center space-x-2">
                    <User className="h-4 w-4" />
                    <span>Email Address</span>
                  </Label>
                  <Input
                    ref={regEmailRef}
                    id="reg-email"
                    type="email"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); clearFieldError('email'); }}
                    onBlur={() => email && validateField('email', email, 'email')}
                    required
                    aria-invalid={!!fieldErrors.email}
                    aria-describedby={fieldErrors.email ? 'reg-email-error' : undefined}
                    className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
                    placeholder="Enter your email"
                  />
                  {fieldErrors.email && (
                    <p id="reg-email-error" className="text-sm text-destructive" role="alert">{fieldErrors.email}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="reg-password" className="text-foreground flex items-center space-x-2">
                    <Lock className="h-4 w-4" />
                    <span>Password</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="reg-password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => { setPassword(e.target.value); clearFieldError('password'); }}
                      required
                      aria-invalid={!!fieldErrors.password}
                      aria-describedby={fieldErrors.password ? 'reg-password-error' : 'reg-password-strength'}
                      className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
                      placeholder="Create a strong password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p id="reg-password-error" className="text-sm text-destructive" role="alert">{fieldErrors.password}</p>
                  )}

                  {/* Password Strength with ARIA live region */}
                  {password && (
                    <div className="space-y-2" id="reg-password-strength" aria-live="polite" aria-atomic="true">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">Password Strength:</span>
                        <span className={`font-medium ${passwordStrengthData.isStrong ? 'text-success' : 'text-warning'}`}>
                          {getPasswordStrengthText()}
                        </span>
                      </div>
                      <div
                        className="w-full bg-muted rounded-full h-2"
                        role="progressbar"
                        aria-valuenow={passwordStrengthData.score}
                        aria-valuemin={0}
                        aria-valuemax={8}
                        aria-label="Password strength"
                      >
                        <div
                          className={`h-2 rounded-full transition-all duration-300 ${getPasswordStrengthColor()}`}
                          style={{ width: `${(passwordStrengthData.score / 8) * 100}%` }}
                        />
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {passwordStrengthData.feedback.length > 0 ? (
                          <div>Missing: {passwordStrengthData.feedback.join(', ')}</div>
                        ) : (
                          <div className="text-success">All security requirements met</div>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="reg-username" className="text-foreground">Username</Label>
                  <Input
                    id="reg-username"
                    value={username}
                    onChange={(e) => { setUsername(e.target.value); clearFieldError('username'); }}
                    required
                    aria-invalid={!!fieldErrors.username}
                    aria-describedby={fieldErrors.username ? 'reg-username-error' : undefined}
                    className="bg-input/50 border-border text-foreground"
                    placeholder="Choose a username"
                  />
                  {fieldErrors.username && (
                    <p id="reg-username-error" className="text-sm text-destructive" role="alert">{fieldErrors.username}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="reg-fullName" className="text-foreground">Full Name</Label>
                  <Input
                    id="reg-fullName"
                    value={fullName}
                    onChange={(e) => { setFullName(e.target.value); clearFieldError('fullName'); }}
                    required
                    aria-invalid={!!fieldErrors.fullName}
                    aria-describedby={fieldErrors.fullName ? 'reg-fullname-error' : undefined}
                    className="bg-input/50 border-border text-foreground"
                    placeholder="Enter your full name"
                  />
                  {fieldErrors.fullName && (
                    <p id="reg-fullname-error" className="text-sm text-destructive" role="alert">{fieldErrors.fullName}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="reg-department" className="text-foreground flex items-center space-x-2">
                    <Building className="h-4 w-4" />
                    <span>Department</span>
                  </Label>
                  <Input
                    id="reg-department"
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="bg-input/50 border-border text-foreground"
                    placeholder="Enter your department"
                  />
                </div>

                <div className="space-y-2">
                  <Label className="text-foreground">Security Clearance</Label>
                  <Select value={securityClearance} onValueChange={setSecurityClearance}>
                    <SelectTrigger className="bg-input/50 border-border text-foreground">
                      <SelectValue placeholder="Select clearance level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="UNCLASSIFIED">UNCLASSIFIED</SelectItem>
                      <SelectItem value="CONFIDENTIAL">CONFIDENTIAL</SelectItem>
                      <SelectItem value="SECRET">SECRET</SelectItem>
                      <SelectItem value="TOP_SECRET">TOP SECRET</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button
                  type="submit"
                  variant="default"
                  className="w-full"
                  disabled={loading}
                >
                  {loading ? (
                    <div className="flex items-center space-x-2">
                      <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" aria-hidden="true" />
                      <span>Registering...</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4" />
                      <span>Create Account</span>
                    </div>
                  )}
                </Button>
              </form>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;
