import { useState, useEffect } from 'react';

/**
 * Self-contained clock component that manages its own 1s interval.
 * Prevents parent (ConsoleLayout header) from re-rendering every second.
 */
const HeaderClock = () => {
    const [currentTime, setCurrentTime] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => {
            setCurrentTime(new Date());
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    return (
        <div className="text-right">
            <div>{currentTime.toLocaleTimeString()}</div>
            <div className="text-xs">UTC {currentTime.toISOString().slice(0, 10)}</div>
        </div>
    );
};

export default HeaderClock;
