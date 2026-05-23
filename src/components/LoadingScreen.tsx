import { Shield } from 'lucide-react';

interface LoadingScreenProps {
    message?: string;
}

const LoadingScreen = ({ message = 'Initializing secure session...' }: LoadingScreenProps) => {
    return (
        <div className="min-h-screen bg-[hsl(220,15%,6%)] flex items-center justify-center relative overflow-hidden">
            {/* Ambient glow */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_hsl(194,100%,50%,0.06)_0%,_transparent_50%)]" />

            <div className="flex flex-col items-center gap-6 relative z-10">
                {/* Spinning Adinkra-style loader */}
                <div className="relative w-16 h-16">
                    {/* Outer ring */}
                    <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
                    {/* Spinning arc */}
                    <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
                    {/* Inner icon */}
                    <div className="absolute inset-0 flex items-center justify-center">
                        <Shield className="h-6 w-6 text-cyan-400/60 animate-pulse" />
                    </div>
                </div>

                {/* Message */}
                <div className="text-center space-y-2">
                    <p className="text-sm text-gray-400 tracking-wide">{message}</p>
                    {/* Skeleton shimmer bar */}
                    <div className="w-48 h-1 bg-gray-800 rounded-full overflow-hidden mx-auto">
                        <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent rounded-full animate-[shimmer_1.5s_ease-in-out_infinite]" />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LoadingScreen;
