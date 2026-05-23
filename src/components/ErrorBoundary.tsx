import React, { Component, ErrorInfo } from 'react';
import { Shield, RefreshCw, Home, AlertTriangle } from 'lucide-react';

interface ErrorBoundaryProps {
    children: React.ReactNode;
}

interface ErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
    errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
        return { hasError: true, error };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        this.setState({ errorInfo });
        // Log to console for debugging — production would send to telemetry
        console.error('[ErrorBoundary] Unhandled error caught:', error, errorInfo);
    }

    handleReload = () => {
        globalThis.location.reload();
    };

    handleGoHome = () => {
        globalThis.location.href = '/';
    };

    render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-[hsl(220,15%,6%)] text-white flex items-center justify-center p-6 relative overflow-hidden">
                    {/* Background Effects */}
                    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_hsl(0,84%,60%,0.08)_0%,_transparent_50%)]" />
                    <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,0,0,0.03)_1px,transparent_1px),linear_gradient(to_bottom,rgba(255,0,0,0.03)_1px,transparent_1px)] bg-[size:3rem_3rem]" />

                    <div className="max-w-lg w-full relative z-10">
                        {/* Error Icon */}
                        <div className="flex justify-center mb-8">
                            <div className="w-20 h-20 bg-gradient-to-br from-red-500/20 to-red-900/20 border border-red-500/30 rounded-2xl flex items-center justify-center">
                                <AlertTriangle className="h-10 w-10 text-red-400" />
                            </div>
                        </div>

                        {/* Error Message */}
                        <div className="text-center space-y-4 mb-8">
                            <h1 className="text-3xl font-bold text-white">
                                System Anomaly Detected
                            </h1>
                            <p className="text-gray-400 text-lg leading-relaxed">
                                An unexpected error occurred in the application. Our telemetry has logged this incident for review.
                            </p>
                            {this.state.error && (
                                <div className="mt-4 p-4 bg-red-500/5 border border-red-500/20 rounded-lg text-left">
                                    <p className="text-xs text-red-300 font-mono break-all">
                                        {this.state.error.message}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Recovery Actions */}
                        <div className="flex flex-col sm:flex-row gap-3 justify-center">
                            <button
                                onClick={this.handleReload}
                                className="flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-black font-semibold rounded-lg transition-all duration-300 shadow-[0_0_20px_rgba(0,255,255,0.3)] hover:shadow-[0_0_30px_rgba(0,255,255,0.5)]"
                            >
                                <RefreshCw className="h-5 w-5" />
                                Reload Application
                            </button>
                            <button
                                onClick={this.handleGoHome}
                                className="flex items-center justify-center gap-2 px-6 py-3 border border-gray-600 hover:border-cyan-500/50 text-gray-300 hover:text-white font-semibold rounded-lg transition-all duration-300"
                            >
                                <Home className="h-5 w-5" />
                                Return Home
                            </button>
                        </div>

                        {/* Brand Footer */}
                        <div className="mt-12 text-center">
                            <div className="flex items-center justify-center gap-2 text-gray-600">
                                <Shield className="h-4 w-4" />
                                <span className="text-xs uppercase tracking-widest">SouHimBou AI • Resilience Protocol Active</span>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
