import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Users, CreditCard, Key } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

const AdminSovereignty = () => {
    return (
        <div className="space-y-6">
            <Tabs defaultValue="license" className="space-y-6">
                <TabsList className="grid w-full grid-cols-3 bg-slate-900/50 border border-slate-800">
                    <TabsTrigger value="license">
                        <Key className="w-4 h-4 mr-2" />
                        License
                    </TabsTrigger>
                    <TabsTrigger value="sso">
                        <Shield className="w-4 h-4 mr-2" />
                        SSO/Auth
                    </TabsTrigger>
                    <TabsTrigger value="billing">
                        <CreditCard className="w-4 h-4 mr-2" />
                        Billing
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="license">
                    <LicenseManager />
                </TabsContent>

                <TabsContent value="sso">
                    <SSOConfig />
                </TabsContent>

                <TabsContent value="billing">
                    <BillingDashboard />
                </TabsContent>
            </Tabs>
        </div>
    );
};

const LicenseManager = () => {
    // Fetch license data
    const { data: licenseData } = useQuery({
        queryKey: ["license-status"],
        queryFn: async () => {
            const response = await fetch("/api/v1/admin/license");
            return response.json();
        },
    });

    return (
        <div className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">License Overview</CardTitle>
                    <CardDescription>Current subscription and seat usage</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Plan</div>
                            <div className="text-2xl font-bold text-slate-200">{licenseData?.plan || "Enterprise"}</div>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Seats Used</div>
                            <div className="text-2xl font-bold text-slate-200">
                                {licenseData?.seats_used || 0} / {licenseData?.seats_total || 100}
                            </div>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Expires</div>
                            <div className="text-2xl font-bold text-slate-200">
                                {licenseData?.expiry || "2026-12-31"}
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">Active Users</CardTitle>
                    <CardDescription>Manage user licenses and permissions</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-3">
                        {[1, 2, 3].map((i) => (
                            <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-600 to-blue-600 flex items-center justify-center text-white font-bold">
                                        U{i}
                                    </div>
                                    <div>
                                        <div className="text-sm font-medium text-slate-200">user{i}@example.com</div>
                                        <div className="text-xs text-slate-500">Last active: 2 hours ago</div>
                                    </div>
                                </div>
                                <button className="px-3 py-1 rounded bg-red-600 hover:bg-red-700 text-white text-sm">
                                    Revoke
                                </button>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

const SSOConfig = () => {
    return (
        <div className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">SSO Configuration</CardTitle>
                    <CardDescription>Configure SAML, OAuth, and Social Login</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-medium text-slate-200">SAML 2.0</h4>
                                    <p className="text-sm text-slate-500 mt-1">Enterprise SSO via SAML</p>
                                </div>
                                <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm">
                                    Configure
                                </button>
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-medium text-slate-200">OAuth 2.0</h4>
                                    <p className="text-sm text-slate-500 mt-1">Google, Microsoft, GitHub</p>
                                </div>
                                <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm">
                                    Configure
                                </button>
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-medium text-slate-200">Social Login</h4>
                                    <p className="text-sm text-slate-500 mt-1">LinkedIn, Twitter, Facebook</p>
                                </div>
                                <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm">
                                    Configure
                                </button>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

const BillingDashboard = () => {
    return (
        <div className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">Billing Overview</CardTitle>
                    <CardDescription>Usage-based pricing and invoices</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Current Month</div>
                            <div className="text-2xl font-bold text-slate-200">$2,450</div>
                            <div className="text-xs text-slate-500 mt-1">Based on usage</div>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Scans This Month</div>
                            <div className="text-2xl font-bold text-slate-200">1,247</div>
                            <div className="text-xs text-slate-500 mt-1">$2/scan</div>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                            <div className="text-sm text-slate-400">Next Invoice</div>
                            <div className="text-2xl font-bold text-slate-200">Feb 1</div>
                            <div className="text-xs text-slate-500 mt-1">Auto-pay enabled</div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                    <CardTitle className="text-slate-200">Payment Method</CardTitle>
                    <CardDescription>Manage your payment information</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                        <div className="flex items-center gap-3">
                            <CreditCard className="w-8 h-8 text-slate-400" />
                            <div>
                                <div className="text-sm font-medium text-slate-200">•••• •••• •••• 4242</div>
                                <div className="text-xs text-slate-500">Expires 12/2026</div>
                            </div>
                        </div>
                        <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm">
                            Update
                        </button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default AdminSovereignty;
