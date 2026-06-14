import type { Metadata } from 'next';
import { ScadaHMI } from '@/components/ScadaHMI';

export const metadata: Metadata = {
  title: 'AkokoNan HMI — AdinKhepra SCADA View',
};

// Fullscreen kiosk page — no nav, no padding, just the 800×480 HMI panel.
// On the Pi: chromium-browser --kiosk http://localhost:3000/hmi
export default function HMIPage() {
  return (
    <main
      style={{
        margin: 0,
        padding: 0,
        background: '#080c14',
        width: '100vw',
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
      }}
    >
      <ScadaHMI />
    </main>
  );
}
