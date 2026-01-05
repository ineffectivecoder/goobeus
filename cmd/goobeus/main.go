package main

import (
	"fmt"
	"os"

	"github.com/mjwhitta/cli"
)

// Version info
var version = "0.1.0"

// Exit codes
const (
	ExitSuccess = iota
	ExitError
	ExitMissingArg
)

// Global flags
var flags struct {
	domain   string
	username string
	password string
	ntHash   string
	aes256   string
	ticket   string
	kdc      string
	outfile  string
	format   string
	verbose  bool
}

// Command to run
var command string
var cmdArgs []string

func init() {
	// Configure cli
	cli.Align = true
	cli.Authors = []string{"goobeus authors"}
	cli.Banner = fmt.Sprintf("%s [OPTIONS] <command> [args...]", os.Args[0])
	cli.Info(
		"Goobeus - Go Kerberos Manipulation Library",
		"",
		"A powerful Kerberos toolkit featuring TGT/TGS requests,",
		"S4U delegation, ticket forgery, ADWS enumeration, and more.",
	)
	cli.ExitStatus(
		"0 - Success",
		"1 - Error",
	)

	// Define flags (short, long, default, description)
	cli.Flag(&flags.domain, "d", "domain", "", "Domain name")
	cli.Flag(&flags.username, "u", "user", "", "Username")
	cli.Flag(&flags.password, "p", "pass", "", "Password")
	cli.Flag(&flags.ntHash, "r", "rc4", "", "NT hash")
	cli.Flag(&flags.aes256, "a", "aes", "", "AES256 key")
	cli.Flag(&flags.ticket, "t", "ticket", "", "Ticket file or base64")
	cli.Flag(&flags.kdc, "k", "kdc", "", "KDC address")
	cli.Flag(&flags.outfile, "o", "out", "", "Output file")
	cli.Flag(&flags.format, "f", "format", "kirbi", "Output format")
	cli.Flag(&flags.verbose, "v", "verbose", false, "Verbose output")

	// Commands section
	cli.Section("Commands",
		"  asktgt       Request TGT\n",
		"  asktgs       Request TGS (Kerberoast)\n",
		"  s4u          S4U2Self/Proxy delegation\n",
		"  rbcd         RBCD attack\n",
		"  constrained  Constrained delegation attack\n",
		"  kerberoast   Kerberoast SPNs\n",
		"  asreproast   AS-REP roast users\n",
		"  dcsync       DCSync attack (extract credentials)\n",
		"  golden       Forge golden ticket\n",
		"  silver       Forge silver ticket\n",
		"  diamond      Forge diamond ticket\n",
		"  sapphire     Forge sapphire ticket\n",
		"  describe     View ticket contents\n",
		"  hash         Compute Kerberos keys from password\n",
		"  changepw     Change password via kpasswd\n",
		"  enumerate    ADWS enumeration\n",
		"  ptt          Pass-the-ticket (Windows)\n",
		"  dump         Dump tickets (Windows)\n",
		"  triage       List cached tickets (Windows)\n",
		"  klist        List cached tickets (Windows)\n",
		"  purge        Purge tickets (Windows)\n",
		"  tgtdeleg     Extract TGT via delegation (Windows)\n",
		"  monitor      Monitor for new TGTs (Windows)\n",
		"  harvest      Harvest TGTs (Windows)\n",
		"  currentluid  Get current LUID (Windows)\n",
		"  createnetonly Create network-only process (Windows)",
	)

	cli.Parse()

	// Get command from args
	if cli.NArg() == 0 {
		cli.Usage(ExitMissingArg)
	}

	command = cli.Arg(0)
	if cli.NArg() > 1 {
		cmdArgs = cli.Args()[1:]
	}
}

func main() {
	var err error
	switch command {
	case "asktgt":
		err = cmdAskTGT(cmdArgs)
	case "asktgs":
		err = cmdAskTGS(cmdArgs)
	case "s4u":
		err = cmdS4U(cmdArgs)
	case "kerberoast":
		err = cmdKerberoast(cmdArgs)
	case "asreproast":
		err = cmdASREPRoast(cmdArgs)
	case "golden":
		err = cmdGolden(cmdArgs)
	case "silver":
		err = cmdSilver(cmdArgs)
	case "diamond":
		err = cmdDiamond(cmdArgs)
	case "sapphire":
		err = cmdSapphire(cmdArgs)
	case "describe":
		err = cmdDescribe(cmdArgs)
	case "ptt":
		err = cmdPTT(cmdArgs)
	case "dump":
		err = cmdDump(cmdArgs)
	case "tgtdeleg":
		err = cmdTGTDeleg(cmdArgs)
	case "enumerate", "enum":
		err = cmdEnumerate(cmdArgs)
	case "hash":
		err = cmdHash(cmdArgs)
	case "triage":
		err = cmdTriage(cmdArgs)
	case "klist":
		err = cmdKlist(cmdArgs)
	case "purge":
		err = cmdPurge(cmdArgs)
	case "monitor":
		err = cmdMonitor(cmdArgs)
	case "harvest":
		err = cmdHarvest(cmdArgs)
	case "currentluid":
		err = cmdCurrentLUID(cmdArgs)
	case "createnetonly":
		err = cmdCreateNetOnly(cmdArgs)
	case "changepw":
		err = cmdChangepw(cmdArgs)
	case "dcsync":
		err = cmdDCSync(cmdArgs)
	case "rbcd":
		err = cmdRBCD(cmdArgs)
	case "constrained":
		err = cmdConstrained(cmdArgs)
	case "help":
		cli.Usage(ExitSuccess)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		cli.Usage(ExitError)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(ExitError)
	}
}
