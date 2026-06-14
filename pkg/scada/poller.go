package scada

import (
	"context"
	"log"
	"sync"
	"time"
)

// ── Exact register map from ESP32 firmware (update_sensors) ──────────────────
//
// Holding Registers (FC03, start addr 0, 8 registers total):
//   Reg 0: Temperature × 10   (DHT11, e.g. 230 = 23.0 °C)
//   Reg 1: Humidity × 10      (DHT11, e.g. 380 = 38.0 %)
//   Reg 2: Gas ADC             (adc_gas,   Pin 34, 0–4095)
//   Reg 3: Water level ADC     (adc_water, Pin 32, 0–4095)
//   Reg 4: Distance cm         (HC-SR04,   999 = out of range)
//   Reg 5: MPU-6050 accel mag  (0 if not installed)
//   Reg 6: Sound ADC           (adc_sound, Pin 39, 0–4095)
//   Reg 7: LDR/Light ADC       (adc_ldr,   Pin 36, 0–4095)
//
// Discrete Inputs (FC02, start addr 0, 2 inputs):
//   Discrete 0: IR sensor   (ir_pin,   Pin 19, active-LOW → True = detected)
//   Discrete 1: Flame sensor (flame_do, Pin 13, active-LOW → True = detected)
//
// Output Coils (FC05, addr 0–1):
//   Coil 0: Buzzer           (Pin 25, ON/OFF)
//   Coil 1: RGB LED alarm    (Pin 26/27, Red = ON, Green = OFF)

const (
	numHoldingRegs = 8
	numDiscretes   = 2

	regTempX10 = 0
	regHumX10  = 1
	regGas     = 2
	regWater   = 3
	regDist    = 4
	regMPU     = 5
	regSound   = 6
	regLDR     = 7

	discIR    = 0
	discFlame = 1

	CoilBuzzer = 0
	CoilLED    = 1
)

// SensorData is a fully decoded snapshot of the ESP32 sensors.
type SensorData struct {
	Temperature float64 `json:"temperature"` // °C
	Humidity    float64 `json:"humidity"`    // %
	Gas         int     `json:"gas"`         // ADC 0–4095
	Water       int     `json:"water"`       // ADC 0–4095
	Distance    int     `json:"distance"`    // cm (999 = max range)
	MPU         int     `json:"mpu"`         // accel magnitude (0 if not installed)
	Sound       int     `json:"sound"`       // ADC 0–4095
	LDR         int     `json:"ldr"`         // ADC 0–4095 (higher = brighter)
	IR          bool    `json:"ir"`          // true = object detected (active-low)
	Flame       bool    `json:"flame"`       // true = flame detected (active-low)
}

// PollState is the payload returned by GET /api/scada/live.
type PollState struct {
	Connected bool       `json:"connected"`
	Timestamp time.Time  `json:"timestamp"`
	Sensors   SensorData `json:"sensors"`
	Host      string     `json:"host"`
	Port      int        `json:"port"`
	UnitID    int        `json:"unit_id"`
	Error     string     `json:"error,omitempty"`
}

// Config drives the Modbus connection and poll cadence.
type Config struct {
	Host     string
	Port     int
	UnitID   byte
	Interval time.Duration // defaults to 1 s
}

// Poller continuously reads from the ESP32 and caches the latest state.
// Coil writes are synchronous (call WriteCoilNow from HTTP handler).
type Poller struct {
	cfg   Config
	mu    sync.RWMutex
	state PollState
}

// NewPoller creates a Poller ready to run. Call Run in a goroutine.
func NewPoller(cfg Config) *Poller {
	if cfg.Interval == 0 {
		cfg.Interval = time.Second
	}
	return &Poller{
		cfg: cfg,
		state: PollState{
			Host:   cfg.Host,
			Port:   cfg.Port,
			UnitID: int(cfg.UnitID),
		},
	}
}

// Run polls the ESP32 every cfg.Interval until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	log.Printf("[SCADA] Poller → %s:%d unit_id=%d interval=%s",
		p.cfg.Host, p.cfg.Port, p.cfg.UnitID, p.cfg.Interval)

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[SCADA] Poller stopped")
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

// State returns a copy of the latest poll result (safe for concurrent use).
func (p *Poller) State() PollState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// WriteCoilNow issues an immediate FC05 write to the device (bypasses poll cycle).
func (p *Poller) WriteCoilNow(coilAddr uint16, value bool) error {
	return WriteCoil(p.cfg.Host, p.cfg.Port, p.cfg.UnitID, coilAddr, value)
}

// poll reads holding registers and discrete inputs in two sequential Modbus calls.
func (p *Poller) poll() {
	// ── FC03: 8 holding registers ─────────────────────────────────────────────
	regs, regErr := ReadHoldingRegisters(p.cfg.Host, p.cfg.Port, p.cfg.UnitID, 0, numHoldingRegs)

	// ── FC02: 2 discrete inputs ───────────────────────────────────────────────
	discs, discErr := ReadDiscreteInputs(p.cfg.Host, p.cfg.Port, p.cfg.UnitID, 0, numDiscretes)

	p.mu.Lock()
	defer p.mu.Unlock()

	p.state.Timestamp = time.Now().UTC()
	p.state.Host = p.cfg.Host
	p.state.Port = p.cfg.Port
	p.state.UnitID = int(p.cfg.UnitID)

	if regErr != nil {
		p.state.Connected = false
		p.state.Error = regErr.Error()
		return
	}

	// Discrete errors are non-fatal — some deployments may disable FC02
	ir := false
	flame := false
	if discErr == nil && len(discs) >= numDiscretes {
		ir = discs[discIR]
		flame = discs[discFlame]
	}

	p.state.Connected = true
	p.state.Error = ""
	p.state.Sensors = SensorData{
		// Temperature stored as signed int16 (handles sub-zero readings)
		Temperature: float64(int16(regs[regTempX10])) / 10.0,
		Humidity:    float64(regs[regHumX10]) / 10.0,
		Gas:         int(regs[regGas]),
		Water:       int(regs[regWater]),
		Distance:    int(regs[regDist]),
		MPU:         int(regs[regMPU]),
		Sound:       int(regs[regSound]),
		LDR:         int(regs[regLDR]),
		IR:          ir,
		Flame:       flame,
	}
}
