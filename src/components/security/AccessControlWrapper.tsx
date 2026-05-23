import { ReactNode } from 'react';
import { useSecurityClearance, SecurityClearanceLevel } from '@/hooks/useSecurityClearance';
import { useUserProfile } from '@/hooks/useUserProfile';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Shield, Lock, AlertTriangle } from 'lucide-react';

interface AccessControlWrapperProps {
  children: ReactNode;
  requiredClearance?: SecurityClearanceLevel;
  requiredRole?: string;
  resourceType?: string;
  resourceId?: string;
  fallbackComponent?: ReactNode;
  showAccessDenied?: boolean;
  onAccessDenied?: () => void;
}

export const AccessControlWrapper = ({
  children,
  requiredClearance = 'UNCLASSIFIED',
  requiredRole,
  resourceType = 'resource',
  resourceId = 'unknown',
  fallbackComponent,
  showAccessDenied = true,
  onAccessDenied
}: AccessControlWrapperProps) => {
  const { profile } = useUserProfile();
  const { hasAccess, currentClearance, loading, validateSecurityAccess, requestElevatedAccess } = useSecurityClearance(requiredClearance);

  // Check role-based access if required
  const hasRoleAccess = requiredRole ? (
    profile?.role === requiredRole || 
    profile?.master_admin === true ||
    profile?.role === 'admin'
  ) : true;

  const hasFullAccess = hasAccess && hasRoleAccess;

  if (loading) {
    return (
      <div className="flex items-center justify-center p-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (hasFullAccess) {
    return <>{children}</>;
  }

  if (fallbackComponent) {
    return <>{fallbackComponent}</>;
  }

  if (!showAccessDenied) {
    return null;
  }

  const handleRequestAccess = async () => {
    if (requiredClearance !== currentClearance) {
      await requestElevatedAccess(requiredClearance, `Access required for ${resourceType}: ${resourceId}`);
    }
    onAccessDenied?.();
  };

  const getClearanceBadgeVariant = (clearance: string) => {
    switch (clearance) {
      case 'TOP_SECRET': return 'destructive';
      case 'SECRET': return 'secondary';
      case 'CONFIDENTIAL': return 'outline';
      default: return 'default';
    }
  };

  return (
    <div className="p-6 border-2 border-dashed border-muted-foreground/25 rounded-lg bg-muted/5">
      <Alert className="mb-4">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="flex items-center gap-2">
          <Lock className="h-4 w-4" />
          <span className="font-medium">Access Restricted</span>
        </AlertDescription>
      </Alert>

      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-muted-foreground" />
          <span className="text-sm text-muted-foreground">
            This resource requires additional permissions:
          </span>
        </div>

        <div className="grid gap-2">
          {requiredClearance !== 'UNCLASSIFIED' && (
            <div className="flex items-center justify-between">
              <span className="text-sm">Security Clearance:</span>
              <div className="flex items-center gap-2">
                <Badge variant={getClearanceBadgeVariant(currentClearance)}>
                  Current: {currentClearance}
                </Badge>
                <span className="text-muted-foreground">→</span>
                <Badge variant={getClearanceBadgeVariant(requiredClearance)}>
                  Required: {requiredClearance}
                </Badge>
              </div>
            </div>
          )}

          {requiredRole && (
            <div className="flex items-center justify-between">
              <span className="text-sm">Role:</span>
              <div className="flex items-center gap-2">
                <Badge variant="outline">
                  Current: {profile?.role || 'none'}
                </Badge>
                <span className="text-muted-foreground">→</span>
                <Badge variant="outline">
                  Required: {requiredRole}
                </Badge>
              </div>
            </div>
          )}
        </div>

        <div className="flex gap-2 pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRequestAccess}
            className="flex items-center gap-2"
          >
            <Shield className="h-4 w-4" />
            Request Access
          </Button>
        </div>

        <p className="text-xs text-muted-foreground">
          Contact your administrator or security officer if you believe you should have access to this resource.
        </p>
      </div>
    </div>
  );
};