import { createContext, useContext, useState, useEffect, ReactNode, useMemo } from 'react';
import { supabase } from "@/integrations/supabase/client";

interface BrandingConfig {
  organization_name: string;
  logo_url?: string;
  primary_color: string;
  secondary_color: string;
  accent_color: string;
  platform_name: string;
  support_email: string;
  documentation_url?: string;
  custom_domain?: string;
  white_label_enabled: boolean;
  partner_name?: string;
  partner_logo_url?: string;
  footer_text?: string;
  theme_mode: 'light' | 'dark' | 'auto';
}

interface WhiteLabelContextType {
  branding: BrandingConfig;
  updateBranding: (updates: Partial<BrandingConfig>) => Promise<void> | void;
  isPartnerBranded: boolean;
  loading: boolean;
}

const defaultBranding: BrandingConfig = {
  organization_name: 'SouHimBou AI',
  primary_color: '#3b82f6',
  secondary_color: '#1e40af',
  accent_color: '#06b6d4',
  platform_name: 'SouHimBou AI | Agentic Cybersecurity & Compliance Platform',
  support_email: 'support@souhimbou.ai',
  white_label_enabled: false,
  theme_mode: 'dark'
};

const WhiteLabelContext = createContext<WhiteLabelContextType | undefined>(undefined);

export const useWhiteLabel = () => {
  const context = useContext(WhiteLabelContext);
  if (!context) {
    throw new Error('useWhiteLabel must be used within a WhiteLabelProvider');
  }
  return context;
};

interface WhiteLabelProviderProps {
  children: ReactNode;
  partnerId?: string; // For third-party partner integration
}

export const WhiteLabelProvider = ({
  children,
  partnerId
}: WhiteLabelProviderProps) => {
  const [branding, setBranding] = useState<BrandingConfig>(defaultBranding);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadBrandingConfig();
  }, [partnerId]);

  const loadBrandingConfig = async () => {
    try {
      setLoading(true);

      // Check if this is a partner-branded instance (Example: Ananse Sentinel)
      if (partnerId === 'ananse' || (typeof globalThis !== 'undefined' && globalThis.location?.hostname.includes('sentinel'))) {
        const sentinelBranding: BrandingConfig = {
          organization_name: 'Ananse Sentinel',
          logo_url: '/sentinel-logo.png',
          primary_color: '#4f46e5',
          secondary_color: '#312e81',
          accent_color: '#818cf8',
          platform_name: 'Ananse Sentinel Intelligence Platform',
          support_email: 'support@ananse-sentinel.io',
          documentation_url: 'https://docs.ananse-sentinel.io',
          white_label_enabled: true,
          partner_name: 'Ananse Sentinel',
          partner_logo_url: '/sentinel-logo.png',
          footer_text: 'Powered by AdinKhepra Sentinel Intelligence & SouHimBou AI',
          theme_mode: 'dark'
        };
        setBranding(sentinelBranding);
        applyTheme(sentinelBranding);
        return;
      }

      // Load from organization settings
      const { data: orgData } = await supabase
        .from('organizations')
        .select('name, logo_url, settings')
        .limit(1)
        .single();

      if (orgData?.settings && typeof orgData.settings === 'object' && (orgData.settings as any).branding) {
        const customBranding = {
          ...defaultBranding,
          organization_name: orgData.name,
          logo_url: orgData.logo_url,
          ...(orgData.settings as any).branding
        };
        setBranding(customBranding);
        applyTheme(customBranding);
      } else {
        setBranding(defaultBranding);
        applyTheme(defaultBranding);
      }
    } catch (error) {
      console.error('Error loading branding config:', error);
      setBranding(defaultBranding);
      applyTheme(defaultBranding);
    } finally {
      setLoading(false);
    }
  };

  const applyTheme = (brandingConfig: BrandingConfig) => {
    const root = document.documentElement;

    // Convert hex to HSL for CSS custom properties
    const hexToHsl = (hex: string) => {
      const r = Number.parseInt(hex.slice(1, 3), 16) / 255;
      const g = Number.parseInt(hex.slice(3, 5), 16) / 255;
      const b = Number.parseInt(hex.slice(5, 7), 16) / 255;

      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      let h = 0;
      let s = 0;
      const l = (max + min) / 2;

      if (max !== min) {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
          case r: h = (g - b) / d + (g < b ? 6 : 0); break;
          case g: h = (b - r) / d + 2; break;
          case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
      }

      return `${Math.round(h * 360)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
    };

    // Apply custom colors to CSS variables
    root.style.setProperty('--primary', hexToHsl(brandingConfig.primary_color));
    root.style.setProperty('--primary-foreground', '210 40% 98%');
    root.style.setProperty('--secondary', hexToHsl(brandingConfig.secondary_color));
    root.style.setProperty('--accent', hexToHsl(brandingConfig.accent_color));

    // Update document title
    document.title = brandingConfig.platform_name;

    // Update meta tags
    const metaDescription = document.querySelector('meta[name="description"]');
    if (metaDescription) {
      metaDescription.setAttribute('content',
        `${brandingConfig.platform_name} - Advanced Cybersecurity Operations and Compliance Platform`
      );
    }
  };

  const updateBranding = async (updates: Partial<BrandingConfig>) => {
    const newBranding = { ...branding, ...updates };
    setBranding(newBranding);
    applyTheme(newBranding);

    // Save to database if user has permissions
    try {
      const { data: orgs } = await supabase
        .from('organizations')
        .select('id, settings')
        .limit(1)
        .single();

      if (orgs) {
        const currentSettings = (orgs.settings as any) || {};
        const updatedSettings = {
          ...currentSettings,
          branding: {
            ...currentSettings.branding,
            ...updates
          }
        };

        await supabase
          .from('organizations')
          .update({ settings: updatedSettings })
          .eq('id', orgs.id);
      }
    } catch (error) {
      console.error('Error saving branding config:', error);
    }
  };

  const isPartnerBranded = branding.white_label_enabled && !!branding.partner_name;

  const contextValue = useMemo(() => ({
    branding,
    updateBranding,
    isPartnerBranded,
    loading
  }), [branding, updateBranding, isPartnerBranded, loading]);

  return (
    <WhiteLabelContext.Provider value={contextValue}>
      {children}
    </WhiteLabelContext.Provider>
  );
};