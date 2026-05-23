import { useState } from 'react';
import { LogOut, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface SignOutDialogProps {
    /** The actual sign-out function from useAuth */
    onConfirm: () => void;
    /** Trigger element — replaces the default button if provided */
    children?: React.ReactNode;
}

/**
 * A confirmation dialog for sign-out to prevent accidental session termination.
 * Can wrap any clickable element or render its own button.
 */
const SignOutDialog = ({ onConfirm, children }: SignOutDialogProps) => {
    const [isOpen, setIsOpen] = useState(false);

    const handleConfirm = () => {
        setIsOpen(false);
        onConfirm();
    };

    return (
        <>
            {/* Trigger */}
            {children ? (
                <button type="button" onClick={() => setIsOpen(true)} className="appearance-none bg-transparent border-none p-0 m-0 cursor-pointer">
                    {children}
                </button>
            ) : (
                <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setIsOpen(true)}
                    aria-label="Sign out"
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                >
                    <LogOut className="h-5 w-5" />
                </Button>
            )}

            {/* Dialog */}
            {isOpen && (
                <>
                    <div
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[200]"
                        onClick={() => setIsOpen(false)}
                        aria-hidden="true"
                    />
                    <div
                        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[201]
                       w-full max-w-sm bg-[hsl(220,13%,10%)] border border-white/10
                       rounded-xl shadow-2xl p-6"
                        role="alertdialog"
                        aria-modal="true"
                        aria-labelledby="signout-title"
                        aria-describedby="signout-desc"
                    >
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center flex-shrink-0">
                                <AlertTriangle className="h-5 w-5 text-red-400" />
                            </div>
                            <div>
                                <h2 id="signout-title" className="text-white font-semibold text-sm">
                                    End Session?
                                </h2>
                                <p id="signout-desc" className="text-gray-400 text-xs mt-0.5">
                                    You'll need to sign in again to access your dashboard and compliance data.
                                </p>
                            </div>
                        </div>

                        <div className="flex gap-2 justify-end">
                            <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setIsOpen(false)}
                                className="text-gray-400 hover:text-white"
                            >
                                Cancel
                            </Button>
                            <Button
                                variant="destructive"
                                size="sm"
                                onClick={handleConfirm}
                                className="bg-red-600 hover:bg-red-700"
                            >
                                <LogOut className="h-3.5 w-3.5 mr-1.5" />
                                Sign Out
                            </Button>
                        </div>
                    </div>
                </>
            )}
        </>
    );
};

export default SignOutDialog;
