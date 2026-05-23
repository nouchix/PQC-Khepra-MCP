import { useEffect } from 'react';
import { useNavigate } from '@/lib/router-compat';

const ResetPassword = () => {
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect to auth page with reset mode
    navigate('/auth?mode=reset');
  }, [navigate]);

  return null;
};

export default ResetPassword;
