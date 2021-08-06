// This module implement HTTPS forwarder for passing HTTPS request to responsible process.
// Steps:
// - Load configuration file for request receiving process. See applications.ini file.
// - Always redirect HTTP to HTTPS.
// - When request received, check if host name exist in mappings (mappings populated from configuration file).
// - Forward request to specific process to do the job.
package main

import (
	"flag"
	"onethinglab.com/forwarder"
	"onethinglab.com/logger"
)

var flagApplications = flag.String("apps-file", "~/.https-forwarder-apps.ini",
	"List of applications to forward requests to. Default to ~/.https-forwarder-apps.ini")
var flagVerbose = flag.Bool("verbose", false, "Show verbose output.")

func init() {
	flag.Parse()
	if *flagVerbose {
		for _, log := range []*logger.LLogger{logger.InfoLogger, logger.WarningLogger,
											  logger.ErrorLogger} {
			log.Enable()
		}
	} else {
		for _, log := range []*logger.LLogger{logger.InfoLogger, logger.WarningLogger} {
				log.Disable()
		}
		logger.ErrorLogger.Enable()
	}
}


func main() {
	apps, err := forwarder.LoadApplications(*flagApplications)
	if err != nil {
		logger.ErrorLogger.Printf("Cannot load applications due to error: %s\n", err)
		return
	}
	logger.InfoLogger.Printf("Loaded %d application(s):\n", len(apps))
	for _, app := range apps {
		logger.InfoLogger.Printf("[%s] %s -> %s\n", app.Name, app.UpstreamHost, app.DownstreamHost)
	}
	forwarder.Forward(":443", apps)
}
