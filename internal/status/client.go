package status

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
)

// dialTimeout bounds how long the client waits for the daemon. The
// socket is local: if it does not answer quickly, it is not answering.
const dialTimeout = 2 * time.Second

// Fetch asks the running daemon for its report.
func Fetch(socket string) (*Report, error) {
	conn, err := net.DialTimeout("unix", socket, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(dialTimeout))

	b, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("malformed report from %s: %w", socket, err)
	}
	return &rep, nil
}

// offline builds the report for a daemon that does not answer.
//
// This is deliberately a thin fallback, not a second state engine: it
// only distinguishes "installed but stopped" from "not installed", by
// looking at whether the configuration file exists and still loads.
func offline(version, cfgPath string, dialErr error) *Report {
	rep := &Report{Version: version}
	rep.Config.Path = cfgPath

	switch cfg, err := config.Load(cfgPath); {
	case err == nil:
		rep.Config.Valid = true
		rep.Config.Warnings = cfg.Warnings
		rep.Nginx.ConfDir = cfg.Nginx.ConfDir
		rep.Add("socket", StatusCritical, "service not running")
	case os.IsNotExist(underlying(err)):
		rep.Add("socket", StatusCritical, "service not running")
		rep.Add("config", StatusCritical, "not installed: run `limen init`")
	default:
		rep.Config.Error = err.Error()
		rep.Add("socket", StatusCritical, "service not running")
		rep.Add("config", StatusCritical, err.Error())
	}
	_ = dialErr
	rep.Finish()
	return rep
}

// underlying unwraps one level of the wrapped os error, which is how
// config.Load reports a missing file.
func underlying(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		if inner := u.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// Run implements the `limen status` command and returns the process
// exit code.
func Run(version, socket, cfgPath string, jsonOut bool, watch time.Duration, out io.Writer) int {
	if watch <= 0 {
		rep := get(version, socket, cfgPath)
		emit(out, rep, jsonOut, nil)
		return rep.ExitCode()
	}
	return runWatch(version, socket, cfgPath, jsonOut, watch, out)
}

func get(version, socket, cfgPath string) *Report {
	rep, err := Fetch(socket)
	if err != nil {
		return offline(version, cfgPath, err)
	}
	if rep.Version == "" {
		rep.Version = version
	}
	return rep
}

func emit(out io.Writer, rep *Report, jsonOut bool, rates *Rates) {
	if jsonOut {
		_ = rep.WriteJSON(out)
		return
	}
	rep.WriteText(out, rates)
}

// runWatch redraws the report every interval, like top. In JSON mode
// it streams one object per tick instead of redrawing, so the output
// can be piped into a collector.
func runWatch(version, socket, cfgPath string, jsonOut bool, every time.Duration, out io.Writer) int {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	var prev *Report
	var prevAt time.Time
	last := ExitUnknown

	for {
		now := time.Now()
		rep := get(version, socket, cfgPath)
		var rates *Rates
		if prev != nil && rep.Live != nil && prev.Live != nil {
			rates = NewRates(prev.Live, rep.Live, now.Sub(prevAt))
		}
		if !jsonOut {
			// Home, then clear: the screen never blanks between
			// frames the way clear-then-draw does.
			fmt.Fprint(out, "\033[H\033[2J")
		}
		emit(out, rep, jsonOut, rates)
		prev, prevAt = rep, now
		last = rep.ExitCode()

		select {
		case <-stop:
			return last
		case <-ticker.C:
		}
	}
}
