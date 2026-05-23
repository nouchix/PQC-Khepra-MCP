import { useEffect } from 'react';
import { useLocation } from '@/lib/router-compat';

/**
 * Sets document.title dynamically based on the current route.
 * Add new routes here as pages are created.
 */
const ROUTE_TITLES: Record<string, string> = {
    '/': 'SouHimBou AI | Agentic Cybersecurity & Compliance Platform',
    '/auth': 'Sign In | SouHimBou AI',
    '/blog': 'Security Blog | SouHimBou AI',
    '/dod': 'DoD Solutions | SouHimBou AI',
    '/onboarding': 'Get Started | SouHimBou AI',
    '/privacy': 'Privacy Policy | SouHimBou AI',
    '/terms': 'Terms of Service | SouHimBou AI',
    '/security': 'Security | SouHimBou AI',
    '/compliance': 'Compliance | SouHimBou AI',
    '/dashboard': 'Dashboard | SouHimBou AI',
    '/stig-dashboard': 'STIG Dashboard | SouHimBou AI',
    '/asset-scanning': 'Asset Scanning | SouHimBou AI',
    '/compliance-reports': 'Reports | SouHimBou AI',
    '/evidence-collection': 'Evidence | SouHimBou AI',
    '/billing': 'Billing | SouHimBou AI',
    '/master-admin': 'Admin Console | SouHimBou AI',
    '/vdp': 'Vulnerability Disclosure | SouHimBou AI',
};

const DEFAULT_TITLE = 'SouHimBou AI | Agentic Cybersecurity & Compliance Platform';

export function useDocumentTitle() {
    const { pathname } = useLocation();

    useEffect(() => {
        // Try exact match first, then prefix match for blog posts
        let title = ROUTE_TITLES[pathname];

        if (!title && pathname.startsWith('/blog/')) {
            title = 'Blog | SouHimBou AI';
        }

        document.title = title || DEFAULT_TITLE;
    }, [pathname]);
}
