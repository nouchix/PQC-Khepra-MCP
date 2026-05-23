import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from '@/lib/router-compat';
import { useAuth } from '@/hooks/useAuth';
import { useSecurityHardening } from '@/hooks/useSecurityHardening';
import { useUserAgreements } from '@/hooks/useUserAgreements';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, User, Lock, Building, Eye, EyeOff, CheckCircle, Fingerprint } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import PasswordResetOTP from '@/components/auth/PasswordResetOTP';


const Auth = () => {
  const [searchParams] = useSearchParams();
  const mode = searchParams.get('mode');
  const [isLogin, setIsLogin] = useState(mode !== 'reset');
  const [showPasswordReset, setShowPasswordReset] = useState(mode === 'reset');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [department, setDepartment] = useState('');
  const [securityClearance, setSecurityClearance] = useState('UNCLASSIFIED');
  const [loading, setLoading] = useState(false);
  const { signIn, signUp, user } = useAuth();
  useUserAgreements(); // Just call it if needed for side effects, or remove if truly unnecessary
  const navigate = useNavigate();
  const { toast } = useToast();

  const {
    validateInput,
    trackAuthAttempt,
    isAccountLocked,
    getLockoutTimeRemaining,
    checkPasswordStrength
  } = useSecurityHardening();

  const [passwordStrengthData, setPasswordStrengthData] = useState({ score: 0, feedback: [], isStrong: false });

  useEffect(() => {
    if (password) {
      setPasswordStrengthData(checkPasswordStrength(password));
    }
  }, [password]); // Remove checkPasswordStrength from dependencies to prevent infinite loop

  const [timerTick, setTimerTick] = useState(0);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isAccountLocked()) {
      interval = setInterval(() => {
        setTimerTick(prev => prev + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isAccountLocked()]);

  useEffect(() => {
    if (user) {
      navigate('/dashboard');
    }
  }, [user, navigate]);


  const handlePasswordResetSuccess = () => {
    setShowPasswordReset(false);
    setIsLogin(true);
    toast({
      title: "Password Reset Complete",
      description: "You can now log in with your new password",
      variant: "default"
    });
  };

  const validateAuthInputs = () => {
    const emailValidation = validateInput(email, 'email');
    if (!emailValidation.isValid) {
      toast({ title: "Invalid Email", description: emailValidation.error, variant: "destructive" });
      return false;
    }

    if (isLogin) {
      if (!password || password.length < 1) {
        toast({ title: "Invalid Password", description: "Password is required", variant: "destructive" });
        return false;
      }
    } else {
      const passwordValidation = validateInput(password, 'password');
      if (!passwordValidation.isValid) {
        toast({ title: "Invalid Password", description: passwordValidation.error, variant: "destructive" });
        return false;
      }

      if (!passwordStrengthData.isStrong) {
        toast({ title: "Password Too Weak", description: "Password must meet all security requirements.", variant: "destructive" });
        return false;
      }

      if (username) {
        const usernameValidation = validateInput(username, 'username');
        if (!usernameValidation.isValid) {
          toast({ title: "Invalid Username", description: usernameValidation.error, variant: "destructive" });
          return false;
        }
      }
    }
    return true;
  };

  const handleLoginSubmit = async () => {
    const { error } = await signIn(email, password);
    if (error) {
      await trackAuthAttempt(false, email, { userAgent: navigator.userAgent, timestamp: new Date().toISOString() });
      let description = error.message;
      if (description.toLowerCase().includes("email not confirmed")) {
        description = "Account found, but your email hasn't been verified. Please check your inbox (and spam folder) for the verification link.";
      }
      toast({ title: "Authentication Failed", description, variant: "destructive" });
    } else {
      await trackAuthAttempt(true, email, { userAgent: navigator.userAgent, timestamp: new Date().toISOString() });
      toast({ title: "Access Granted", description: "Checking legal compliance...", variant: "default" });
      navigate('/dashboard');
    }
  };

  const handleRegistrationSubmit = async () => {
    const { error } = await signUp(email, password, {
      username,
      full_name: fullName,
      department,
      security_clearance: securityClearance,
      role: 'viewer'
    });

    if (error) {
      let description = error.message;
      if (description.toLowerCase().includes("email not confirmed")) {
        description = "This email is already registered but unverified. Please check your inbox for the confirmation link or contact support.";
      } else if (error.status === 422 && description.toLowerCase().includes("already registered")) {
        description = "An account with this email already exists. Try logging in instead.";
      }
      toast({ title: "Registration Failed", description, variant: "destructive" });
    } else {
      toast({
        title: "Registration Successful",
        description: "Check your email to verify your account, then sign in to accept legal terms.",
        variant: "default"
      });
      setIsLogin(true);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isAccountLocked()) {
      const timeRemaining = getLockoutTimeRemaining();
      const minutes = Math.floor(timeRemaining / 60000);
      const seconds = Math.floor((timeRemaining % 60000) / 1000);
      toast({
        title: "Account Temporarily Locked",
        description: `Too many failed attempts. Try again in ${minutes}:${seconds.toString().padStart(2, '0')}.`,
        variant: "destructive"
      });
      return;
    }

    if (!validateAuthInputs()) return;

    setLoading(true);
    try {
      if (isLogin) {
        await handleLoginSubmit();
      } else {
        await handleRegistrationSubmit();
      }
    } catch (error: any) {
      toast({ title: "System Error", description: error.message, variant: "destructive" });
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

  const renderLoginTab = () => (
    <TabsContent value="login" className="space-y-4 mt-6">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email" className="text-foreground flex items-center space-x-2">
            <User className="h-4 w-4" />
            <span>Email Address</span>
          </Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
            placeholder="Enter your email"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="password" className="text-foreground flex items-center space-x-2">
            <Lock className="h-4 w-4" />
            <span>Password</span>
          </Label>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
              placeholder="Enter your password"
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

        <Button
          type="submit"
          variant="cyber"
          className="w-full h-12 text-lg font-bold shadow-lg"
          disabled={loading || isAccountLocked()}
        >
          {loading ? (
            <div className="flex items-center space-x-2">
              <div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
              <span>Authenticating...</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5" />
              <span>Authenticate Access</span>
            </div>
          )}
        </Button>

        <div className="text-center">
          <button
            type="button"
            onClick={() => setShowPasswordReset(true)}
            className="text-sm text-primary hover:text-primary-glow transition-colors"
            disabled={loading || isAccountLocked()}
          >
            Forgot your password?
          </button>
        </div>
      </form>
    </TabsContent>
  );

  const renderRegisterTab = () => (
    <TabsContent value="register" className="space-y-4 mt-6">
      <form onSubmit={(e) => {
        setIsLogin(false);
        handleSubmit(e);
      }} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="reg-email" className="text-foreground flex items-center space-x-2">
            <User className="h-4 w-4" />
            <span>Email Address</span>
          </Label>
          <Input
            id="reg-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground"
            placeholder="Enter your email"
          />
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
              onChange={(e) => setPassword(e.target.value)}
              required
              className="bg-input/50 border-border text-foreground placeholder:text-muted-foreground pr-10"
              placeholder="Enter your password"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground"
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>

          {password && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Password Strength:</span>
                <span className={`font-medium ${passwordStrengthData.isStrong ? 'text-success' : 'text-warning'}`}>
                  {getPasswordStrengthText()}
                </span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all duration-300 ${getPasswordStrengthColor()}`}
                  style={{ width: `${(passwordStrengthData.score / 8) * 100}%` }}
                ></div>
              </div>
              <div className="text-xs text-muted-foreground">
                {passwordStrengthData.feedback.length > 0 ? (
                  <div>Missing: {passwordStrengthData.feedback.join(', ')}</div>
                ) : (
                  <div>All security requirements met ✓</div>
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
            onChange={(e) => setUsername(e.target.value)}
            required
            className="bg-input/50 border-border text-foreground"
            placeholder="Choose a username"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="reg-fullName" className="text-foreground">Full Name</Label>
          <Input
            id="reg-fullName"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            required
            className="bg-input/50 border-border text-foreground"
            placeholder="Enter your full name"
          />
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
          <Label htmlFor="reg-clearance" className="text-foreground">Security Clearance</Label>
          <select
            id="reg-clearance"
            value={securityClearance}
            onChange={(e) => setSecurityClearance(e.target.value)}
            className="w-full h-10 rounded-lg border border-border bg-input/50 px-3 py-2 text-foreground"
          >
            <option value="UNCLASSIFIED">UNCLASSIFIED</option>
            <option value="CONFIDENTIAL">CONFIDENTIAL</option>
            <option value="SECRET">SECRET</option>
            <option value="TOP_SECRET">TOP SECRET</option>
          </select>
        </div>

        <Button
          type="submit"
          variant="cyber"
          className="w-full h-12 text-lg font-bold shadow-lg"
          disabled={loading || isAccountLocked()}
        >
          {loading ? (
            <div className="flex items-center space-x-2">
              <div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
              <span>Registering Account...</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-5 w-5" />
              <span>Complete Registration</span>
            </div>
          )}
        </Button>

        <p className="text-center text-xs text-muted-foreground pt-2">
          Already have an account? Switch to the login tab to authenticate.
        </p>
      </form>
    </TabsContent>
  );


  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--primary-glow)_0%,_transparent_50%)] opacity-10"></div>
      <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-primary/5 via-transparent to-accent/5"></div>

      {/* Floating Security Icons */}
      <div className="absolute top-20 left-20 animate-float">
        <Shield className="h-8 w-8 text-primary/20" />
      </div>
      <div className="absolute bottom-20 right-20 animate-float" style={{ animationDelay: '2s' }}>
        <Lock className="h-6 w-6 text-accent/20" />
      </div>
      <div className="absolute top-1/2 left-10 animate-float" style={{ animationDelay: '4s' }}>
        <Fingerprint className="h-10 w-10 text-primary/15" />
      </div>

      <Card className="w-full max-w-4xl card-cyber backdrop-blur-lg relative z-10">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <img
              src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
              alt="SouHimBou AI Logo"
              className="h-10 w-auto"
            />
            <h1 className="text-3xl font-bold bg-gradient-cyber bg-clip-text text-transparent">
              SouHimBou AI
            </h1>
          </div>
          <CardTitle className="text-xl text-foreground">
            STIG-First Compliance Autopilot
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-2">
            Our Platform bridges CMMC requirements and STIGs implementation, AI-powered, friction-free!
          </p>
          <Badge variant="outline" className="inline-flex items-center space-x-1 border-primary/30 text-primary">
            <Shield className="h-3 w-3" />
            <span>UNCLASSIFIED // FOUO</span>
          </Badge>

          {isAccountLocked() && (
            <div className="mt-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
              <div className="flex items-center space-x-2 text-destructive">
                <Lock className="h-4 w-4" />
                <span className="text-sm font-medium">Account Locked</span>
              </div>
              <p key={`lock-timer-${timerTick}`} className="text-xs text-destructive/80 mt-1">
                Security lockout active - Try again in {Math.ceil(getLockoutTimeRemaining() / 1000)}s
              </p>
            </div>
          )}
        </CardHeader>

        <CardContent>
          {showPasswordReset ? (
            <PasswordResetOTP
              onBack={() => setShowPasswordReset(false)}
              onSuccess={handlePasswordResetSuccess}
            />
          ) : (
            <Tabs defaultValue="login" className="w-full">
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

              {renderLoginTab()}
              {renderRegisterTab()}

            </Tabs>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;