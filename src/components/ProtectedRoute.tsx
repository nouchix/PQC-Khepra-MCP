import React, { useEffect, useState } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { useAuth } from '@/hooks/useAuth';
import { useUserAgreements } from '@/hooks/useUserAgreements';
import TermsAcceptance from './legal/TermsAcceptance';
import LoadingScreen from './LoadingScreen';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const { user, loading } = useAuth();
  const { hasAcceptedAll, loading: agreementsLoading, refreshAgreements } = useUserAgreements();
  const navigate = useNavigate();
  const [showTerms, setShowTerms] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  useEffect(() => {
    if (!agreementsLoading) {
      setShowTerms(!hasAcceptedAll);
    }
  }, [hasAcceptedAll, agreementsLoading]);

  if (loading || agreementsLoading) {
    return <LoadingScreen message="Verifying security clearance..." />;
  }

  if (!user) {
    return null;
  }

  return (
    <>
      {children}
      <TermsAcceptance
        open={showTerms}
        onOpenChange={setShowTerms}
        onAccepted={() => {
          refreshAgreements();
          setShowTerms(false);
        }}
      />
    </>
  );
};

export default ProtectedRoute;
