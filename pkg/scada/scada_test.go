package scada

import (
	"testing"
	"time"
)

// ─── SensorData ─────────────────────────────────────────────────────────────

func TestSensorDataZeroValue(t *testing.T) {
	var s SensorData
	if s.Temperature != 0 || s.Humidity != 0 {
		t.Error("zero-value SensorData should have zero fields")
	}
	if s.IR || s.Flame {
		t.Error("zero-value SensorData should have IR and Flame false")
	}
}

// ─── Poller ─────────────────────────────────────────────────────────────────

func TestNewPoller_DefaultInterval(t *testing.T) {
	p := NewPoller(Config{Host: "192.168.1.100", Port: 502, UnitID: 1})
	if p == nil {
		t.Fatal("NewPoller returned nil")
	}
	// Default interval should be 1 second
	if p.cfg.Interval != time.Second {
		t.Errorf("expected default interval 1s, got %v", p.cfg.Interval)
	}
}

func TestNewPoller_ExplicitInterval(t *testing.T) {
	cfg := Config{
		Host:     "10.0.0.1",
		Port:     502,
		UnitID:   1,
		Interval: 5 * time.Second,
	}
	p := NewPoller(cfg)
	if p.cfg.Interval != 5*time.Second {
		t.Errorf("expected interval 5s, got %v", p.cfg.Interval)
	}
}

func TestPoller_InitialState(t *testing.T) {
	p := NewPoller(Config{Host: "127.0.0.1", Port: 502, UnitID: 1})
	state := p.State()

	// Before the first poll cycle, Connected should be false
	if state.Connected {
		t.Error("expected Connected=false before first poll")
	}
	if state.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", state.Host)
	}
	if state.Port != 502 {
		t.Errorf("expected port 502, got %d", state.Port)
	}
}

// ─── Register Constants ──────────────────────────────────────────────────────

func TestRegisterConstants(t *testing.T) {
	// All registers must be unique 0-indexed addresses in [0, numHoldingRegs)
	regs := []int{regTempX10, regHumX10, regGas, regWater, regDist, regMPU, regSound, regLDR}
	if len(regs) != numHoldingRegs {
		t.Errorf("expected %d register constants, got %d", numHoldingRegs, len(regs))
	}
	seen := map[int]bool{}
	for _, r := range regs {
		if seen[r] {
			t.Errorf("duplicate register address: %d", r)
		}
		if r < 0 || r >= numHoldingRegs {
			t.Errorf("register %d out of range [0, %d)", r, numHoldingRegs)
		}
		seen[r] = true
	}
}

func TestCoilConstants(t *testing.T) {
	if CoilBuzzer == CoilLED {
		t.Error("CoilBuzzer and CoilLED must be distinct")
	}
}

// ─── ModbusFrame helpers (unit-testable without network) ─────────────────────

// TestMBAPFrameLength verifies that the frame size computed by mbapRoundTrip
// would be correct (7 bytes MBAP header + len(PDU)).
// We can't call mbapRoundTrip directly without a server, but we can verify
// the PDU structures that ReadHoldingRegisters would build.
func TestReadHoldingRegisters_ErrorOnNoServer(t *testing.T) {
	// Calling against a port that is certain not to have a Modbus server
	_, err := ReadHoldingRegisters("127.0.0.1", 19999, 1, 0, 8)
	if err == nil {
		t.Error("expected error when no Modbus server is listening")
	}
}

func TestReadDiscreteInputs_ErrorOnNoServer(t *testing.T) {
	_, err := ReadDiscreteInputs("127.0.0.1", 19999, 1, 0, 2)
	if err == nil {
		t.Error("expected error when no Modbus server is listening")
	}
}

func TestWriteCoil_ErrorOnNoServer(t *testing.T) {
	err := WriteCoil("127.0.0.1", 19999, 1, CoilBuzzer, true)
	if err == nil {
		t.Error("expected error when no Modbus server is listening")
	}
}
