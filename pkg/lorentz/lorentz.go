package lorentz

import (
	"time"
)

func StampNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }
