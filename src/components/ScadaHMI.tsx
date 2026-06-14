'use client';

import { useEffect, useState, useCallback } from 'react';

// ── Types (mirror pkg/scada/poller.go) ───────────────────────────────────────

interface SensorData {
  temperature: number;
  humidity: number;
  gas: number;
  water: number;
  distance: number;
  mpu: number;
  sound: number;
  ldr: number;
  ir: boolean;
  flame: boolean;
}

interface LiveState {
  connected: boolean;
  timestamp: string;
  sensors: SensorData;
  host: string;
  port: number;
  unit_id: number;
  error?: string;
}

interface AuditChannel {
  name: string;
  status: 'EXPOSED' | 'SIGNED' | 'NONE';
  mitre: string;
  note: string;
}

interface MitreFinding {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

interface AuditState {
  risk_level: string;
  channels: AuditChannel[];
  findings: MitreFinding[];
}

// ── Theme ─────────────────────────────────────────────────────────────────────

const C = {
  bg:         '#080c14',
  panel:      '#0d1520',
  border:     '#1e3050',
  green:      '#00e87a',
  red:        '#ff2d2d',
  yellow:     '#ffb020',
  orange:     '#ff6b00',
  blue:       '#4db8ff',
  textDim:    '#3a5a7a',
  textMid:    '#6a8aaa',
  textBright: '#d0e8ff',
} as const;

const SEV: Record<string, string> = {
  CRITICAL: C.red,
  HIGH:     C.yellow,
  MEDIUM:   C.blue,
};

// ── Tiny helpers ──────────────────────────────────────────────────────────────

function Dot({ ok, pulse }: { ok: boolean; pulse?: boolean }) {
  const color = ok ? C.green : C.red;
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: color, boxShadow: `0 0 5px ${color}`,
      flexShrink: 0,
      animation: pulse && ok ? 'pulse 1.5s ease-in-out infinite' : undefined,
    }} />
  );
}

function ChannelBadge({ status }: { status: AuditChannel['status'] }) {
  const cfg = {
    EXPOSED: { bg: '#2d0808', color: C.red,    label: 'EXPOSED' },
    SIGNED:  { bg: '#00200f', color: C.green,  label: 'SIGNED ✓' },
    NONE:    { bg: '#1a1200', color: C.yellow, label: 'NONE' },
  }[status];
  return (
    <span style={{
      background: cfg.bg, color: cfg.color,
      border: `1px solid ${cfg.color}50`,
      borderRadius: 3, fontSize: 9, fontWeight: 700,
      padding: '1px 5px', letterSpacing: '0.07em', flexShrink: 0,
    }}>
      {cfg.label}
    </span>
  );
}

// Compact sensor row — fits 10 rows in the left panel
function SRow({
  label, value, unit = '', alarm = false, warn = false, dim = false,
}: {
  label: string; value: string | number; unit?: string;
  alarm?: boolean; warn?: boolean; dim?: boolean;
}) {
  const valueColor = alarm ? C.red : warn ? C.yellow : dim ? '#2a4a6a' : C.textBright;
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '3px 8px', borderRadius: 3, marginBottom: 2,
      background: alarm ? '#1a0000' : 'transparent',
      border: alarm ? `1px solid ${C.red}30` : '1px solid transparent',
    }}>
      <span style={{ color: C.textMid, fontSize: 10, letterSpacing: '0.07em', textTransform: 'uppercase' }}>
        {label}
      </span>
      <span style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: valueColor }}>
        {value}
        {unit && <span style={{ fontSize: 10, color: C.textMid, marginLeft: 3 }}>{unit}</span>}
      </span>
    </div>
  );
}

// Discrete input row (boolean)
function DRow({ label, active, alarmWhenActive }: { label: string; active: boolean; alarmWhenActive?: boolean }) {
  const isAlarm = alarmWhenActive && active;
  const dotColor = isAlarm ? C.red : active ? C.yellow : C.green;
  const stateText = isAlarm ? '⚠ DETECTED' : active ? 'ACTIVE' : 'CLEAR';
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '3px 8px', borderRadius: 3, marginBottom: 2,
      background: isAlarm ? '#1a0000' : '#0a0f18',
      borderLeft: `3px solid ${dotColor}`,
    }}>
      <span style={{ color: C.textMid, fontSize: 10, letterSpacing: '0.07em', textTransform: 'uppercase' }}>
        {label}
      </span>
      <span style={{
        display: 'flex', alignItems: 'center', gap: 5,
        fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: dotColor,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: dotColor, boxShadow: `0 0 4px ${dotColor}`, display: 'inline-block' }} />
        {stateText}
      </span>
    </div>
  );
}

// Coil control button — sends FC05 write to the device
function CoilBtn({
  label, coil, active, onToggle,
}: {
  label: string; coil: number; active: boolean; onToggle: (coil: number, val: boolean) => void;
}) {
  return (
    <button
      onClick={() => onToggle(coil, !active)}
      style={{
        flex: 1, padding: '5px 4px',
        background: active ? '#2d0808' : '#0a0f18',
        border: `1px solid ${active ? C.red : C.border}`,
        borderRadius: 3, color: active ? C.red : C.textMid,
        fontSize: 9, fontWeight: 700, letterSpacing: '0.07em',
        cursor: 'pointer', textTransform: 'uppercase',
        transition: 'all 0.15s',
      }}
    >
      {label} {active ? '■ ON' : '□ OFF'}
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function ScadaHMI() {
  const [live, setLive]   = useState<LiveState | null>(null);
  const [audit, setAudit] = useState<AuditState | null>(null);
  const [lastOk, setLastOk] = useState(0);
  const [now, setNow] = useState(new Date());
  // Local coil state (optimistic — real state comes back via next poll)
  const [buzzer, setBuzzer] = useState(false);
  const [ledOn, setLedOn]   = useState(false);

  const fetchLive = useCallback(async () => {
    try {
      const r = await fetch('/api/scada/live');
      if (r.ok) { setLive(await r.json()); setLastOk(Date.now()); }
    } catch { /* keep stale */ }
  }, []);

  const fetchAudit = useCallback(async () => {
    try {
      const r = await fetch('/api/scada/audit');
      if (r.ok) setAudit(await r.json());
    } catch { /* silent */ }
  }, []);

  const writeCoil = useCallback(async (coil: number, value: boolean) => {
    // Optimistic local update
    if (coil === 0) setBuzzer(value);
    if (coil === 1) setLedOn(value);
    try {
      await fetch('/api/scada/coil', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coil, value }),
      });
    } catch { /* revert would go here in production */ }
  }, []);

  useEffect(() => {
    fetchLive();
    fetchAudit();
    const lt = setInterval(fetchLive, 1000);
    const at = setInterval(fetchAudit, 15_000);
    const ct = setInterval(() => setNow(new Date()), 1000);
    return () => { clearInterval(lt); clearInterval(at); clearInterval(ct); };
  }, [fetchLive, fetchAudit]);

  const stale     = Date.now() - lastOk > 5000;
  const connected = live?.connected && !stale;
  const s         = live?.sensors;
  const staleSec  = lastOk ? Math.round((Date.now() - lastOk) / 1000) : null;

  return (
    <>
      {/* Pulse animation for live dot */}
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }`}</style>

      <div style={{
        width: 800, height: 480,
        background: C.bg,
        fontFamily: "'Courier New', Courier, monospace",
        color: C.textBright,
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden', userSelect: 'none',
      }}>

        {/* ── Header ── */}
        <div style={{
          height: 38, background: C.panel, borderBottom: `1px solid ${C.border}`,
          display: 'flex', alignItems: 'center', padding: '0 10px', gap: 8, flexShrink: 0,
        }}>
          <span style={{ color: C.green, fontSize: 15 }}>⬡</span>
          <span style={{ color: C.textBright, fontWeight: 700, fontSize: 12, letterSpacing: '0.05em' }}>AkokoNan Pod</span>
          <span style={{ color: C.textDim, fontSize: 10 }}>ESP32 Field RTU · Capstone Group 3</span>

          <span style={{ flex: 1 }} />

          {live && (
            <span style={{ color: C.textDim, fontSize: 9 }}>
              {live.host}:{live.port} · Unit {live.unit_id}
            </span>
          )}
          <span style={{ color: C.textDim, fontSize: 10, marginLeft: 10 }}>
            {now.toLocaleTimeString('en-GB', { hour12: false })}
          </span>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, marginLeft: 10,
            padding: '2px 7px', borderRadius: 3,
            background: connected ? '#002010' : '#200a0a',
            border: `1px solid ${connected ? C.green : C.red}40`,
            fontSize: 9, fontWeight: 700, letterSpacing: '0.08em',
            color: connected ? C.green : C.red,
          }}>
            <Dot ok={!!connected} pulse />
            {connected ? 'LIVE' : stale ? `STALE ${staleSec}s` : 'CONNECTING…'}
          </span>
        </div>

        {/* ── Body ── */}
        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

          {/* ── Left: Process Values ── */}
          <div style={{
            width: 355, borderRight: `1px solid ${C.border}`,
            padding: '8px 6px 6px', display: 'flex', flexDirection: 'column', flexShrink: 0,
          }}>
            <div style={{ color: C.textDim, fontSize: 8, letterSpacing: '0.12em', marginBottom: 6, paddingLeft: 8 }}>
              PROCESS — FC03 HOLDING REGISTERS + FC02 DISCRETE INPUTS
            </div>

            {/* Analog sensors */}
            <SRow label="Temperature" value={s ? s.temperature.toFixed(1) : '—'} unit="°C"  dim={!connected} />
            <SRow label="Humidity"    value={s ? s.humidity.toFixed(1)    : '—'} unit="%"   dim={!connected} />
            <SRow label="Gas (ADC)"   value={s ? s.gas    : '—'} alarm={s ? s.gas > 3000 : false} dim={!connected} />
            <SRow label="Water (ADC)" value={s ? s.water  : '—'} warn={s ? s.water > 3500 : false} dim={!connected} />
            <SRow label="Distance"
              value={s ? (s.distance >= 999 ? '>999' : s.distance) : '—'}
              unit="cm"
              dim={s ? s.distance >= 999 : !connected}
            />
            <SRow label="Sound (ADC)" value={s ? s.sound  : '—'} warn={s ? s.sound > 3000 : false} dim={!connected} />
            <SRow label="Light (ADC)" value={s ? s.ldr    : '—'} dim={!connected} />
            <SRow label="MPU Accel"   value={s ? s.mpu    : '—'} dim={!connected || !s?.mpu} />

            <div style={{ borderTop: `1px solid ${C.border}`, margin: '5px 0 4px' }} />

            {/* Discrete inputs */}
            <DRow label="IR Motion"    active={!!s?.ir}    />
            <DRow label="Flame Sensor" active={!!s?.flame} alarmWhenActive />

            <div style={{ flex: 1 }} />

            {/* Coil controls */}
            <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 5 }}>
              <div style={{ color: C.textDim, fontSize: 8, letterSpacing: '0.1em', marginBottom: 4, paddingLeft: 4 }}>
                FC05 COIL WRITE — PHYSICAL OUTPUTS
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <CoilBtn label="Buzzer"   coil={0} active={buzzer} onToggle={writeCoil} />
                <CoilBtn label="LED Alarm" coil={1} active={ledOn}  onToggle={writeCoil} />
              </div>
            </div>
          </div>

          {/* ── Right: Security Audit ── */}
          <div style={{
            flex: 1, padding: '8px 10px', display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}>
            <div style={{ color: C.textDim, fontSize: 8, letterSpacing: '0.12em', marginBottom: 6 }}>
              ADINKHEPRA — OT CHANNEL SECURITY POSTURE
            </div>

            {/* Channel statuses */}
            <div style={{ marginBottom: 6 }}>
              {(audit?.channels ?? []).map(ch => (
                <div key={ch.name} style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  padding: '5px 8px', borderRadius: 3, marginBottom: 3,
                  background: C.panel, border: `1px solid ${C.border}`,
                }}>
                  <span style={{ flex: 1, fontSize: 10, color: '#8aaccc' }}>{ch.name}</span>
                  <ChannelBadge status={ch.status} />
                  {ch.mitre && (
                    <span style={{ fontSize: 8, color: C.textDim, fontFamily: 'monospace', letterSpacing: '0.06em' }}>
                      {ch.mitre}
                    </span>
                  )}
                </div>
              ))}
            </div>

            <div style={{ borderTop: `1px solid ${C.border}`, margin: '2px 0 6px' }} />

            {/* MITRE ATT&CK for ICS */}
            <div style={{ color: C.textDim, fontSize: 8, letterSpacing: '0.12em', marginBottom: 5 }}>
              MITRE ATT&CK FOR ICS — ACTIVE FINDINGS
            </div>

            <div style={{ flex: 1 }}>
              {(audit?.findings ?? []).map(f => (
                <div key={f.id} style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  padding: '4px 8px', marginBottom: 3, borderRadius: 3,
                  background: C.panel,
                  borderLeft: `3px solid ${SEV[f.severity] ?? C.textMid}`,
                }}>
                  <span style={{
                    fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
                    color: SEV[f.severity] ?? C.textMid,
                    letterSpacing: '0.04em', flexShrink: 0, width: 44,
                  }}>
                    {f.id}
                  </span>
                  <span style={{ flex: 1, fontSize: 10, color: '#8aaccc' }}>{f.name}</span>
                  <span style={{
                    fontSize: 8, fontWeight: 700, letterSpacing: '0.06em',
                    color: SEV[f.severity] ?? C.textMid, flexShrink: 0,
                  }}>
                    {f.severity}
                  </span>
                </div>
              ))}
            </div>

            {/* Risk banner */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginTop: 8, padding: '7px 10px', borderRadius: 4,
              background: '#160a00', border: `1px solid ${C.orange}30`,
            }}>
              <div>
                <div style={{ fontSize: 8, color: C.textDim, letterSpacing: '0.1em' }}>
                  GODFATHER REPORT · AdinKhepra ERT
                </div>
                <div style={{ fontSize: 9, color: C.textMid, marginTop: 2 }}>
                  Unauthenticated Modbus exposes FC05 coil writes to physical actuators
                </div>
              </div>
              <span style={{
                fontFamily: 'monospace', fontSize: 16, fontWeight: 700,
                color: C.yellow, letterSpacing: '0.08em', flexShrink: 0, marginLeft: 12,
              }}>
                {audit?.risk_level ?? '…'} ■
              </span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
