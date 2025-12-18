package main

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/yaklabco/stave/pkg/st"
	"github.com/yaklabco/stave/pkg/stave/prettylog"
)

func init() {
	logHandler := prettylog.SetupPrettyLogger(os.Stdout)
	if st.Debug() {
		logHandler.SetLevel(log.DebugLevel)
	}
}
