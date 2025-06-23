package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"gopkg.in/yaml.v3"
)

func init() {
	fmt.Println(`               
                __                     
      ___ __ __/ /  ___ ___ ____ ____ _
     (_-</ // / _ \(_-</ _ '/ _ '/ _ '/
    /___/\_,_/_.__/___/\_,_/\_, /\_, / 
                           /___//___/     
    Version 0.1.1

    by xqu3ry
`)
}

type Tool struct {
	Name string   `yaml:"name"`
	Cmd  []string `yaml:"cmd"`
}

type Config struct {
	Tools     []Tool `yaml:"tools"`
	Wordlist  string `yaml:"wordlist"`
	Resolvers string `yaml:"resolvers"`
}

const (
	defaultConfigFile = "subsagg.yaml"
)

var defaultConfig = Config{
	Tools: []Tool{
		{Name: "subfinder", Cmd: []string{"subfinder", "-d", "{domain}", "-silent"}},
		{Name: "assetfinder", Cmd: []string{"assetfinder", "--subs-only", "{domain}"}},
		{Name: "amass", Cmd: []string{"amass", "enum", "-passive", "-d", "{domain}"}},
		{Name: "findomain", Cmd: []string{"findomain", "-t", "{domain}", "--quiet"}},
		{Name: "sublist3r", Cmd: []string{"sublist3r", "-d", "{domain}", "-o", "-"}},
		{Name: "chaos", Cmd: []string{"chaos", "-d", "{domain}", "-silent"}},
		{Name: "crtsh", Cmd: []string{"crtsh", "{domain}"}},
		{Name: "knockpy", Cmd: []string{"knockpy", "-d", "{domain}"}},
		{Name: "shuffledns", Cmd: []string{"shuffledns", "-d", "{domain}", "-list", "{wordlist}", "-r", "{resolvers}", "-silent"}},
	},
	Wordlist:  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	Resolvers: "/etc/resolv.conf",
}



func main() {
	verbose := false
	recursive := false
	depth := 2

	args := os.Args[1:]
	newArgs := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-v", "--verbose":
			verbose = true
		case "-r", "--recursive":
			recursive = true
		case "--depth":
			if i+1 < len(args) {
				d, err := strconv.Atoi(args[i+1])
				if err == nil && d > 0 {
					depth = d
				}
				i++
			}
		default:
			newArgs = append(newArgs, args[i])
		}
	}
	if len(newArgs) < 1 {
		usage()
		return
	}
	cmd := newArgs[0]
	switch cmd {
	case "run":
		runMain(newArgs[1:], verbose, recursive, depth)
	case "config":
		configCmd(newArgs[1:])
	default:
		usage()
		return
	}
}

func runMain(args []string, verbose, recursive bool, depth int) {
	if len(args) < 1 {
		fmt.Println("Type domain. Example: subsagg run example.com")
		return
	}
	domain := args[0]
	config := loadConfig()
	fmt.Printf("~ Collecting subdomains for %s...\n", domain)
	all := map[string]struct{}{}

	if recursive {
		visited := map[string]struct{}{}
		recursiveSubdomains(domain, config, all, visited, verbose, 1, depth)
	} else {
		for _, tool := range config.Tools {
			cmdline := make([]string, len(tool.Cmd))
			for i, c := range tool.Cmd {
				c = strings.ReplaceAll(c, "{domain}", domain)
				c = strings.ReplaceAll(c, "{wordlist}", config.Wordlist)
				c = strings.ReplaceAll(c, "{resolvers}", config.Resolvers)
				cmdline[i] = c
			}
			fmt.Printf("<+> %s: %s\n", tool.Name, strings.Join(cmdline, " "))
			subs, err := runTool(cmdline, verbose)
			if err != nil {
				fmt.Printf("! %s not complete: %v\n", tool.Name, err)
				continue
			}
			if verbose {
				fmt.Printf("[verbose] %s found %d subdomains (raw output)\n", tool.Name, len(subs))
			}
			for _, sub := range subs {
				if isValidDomain(sub) && strings.HasSuffix(sub, domain) {
					all[sub] = struct{}{}
				}
			}
		}
	}

	// Sort
	result := make([]string, 0, len(all))
	for sub := range all {
		result = append(result, sub)
	}
	sort.Strings(result)
	// Save
	outf := fmt.Sprintf("subdomains_%s.txt", domain)
	if err := ioutil.WriteFile(outf, []byte(strings.Join(result, "\n")), 0644); err != nil {
		fmt.Printf("! Error saving: %v\n", err)
	} else {
		fmt.Printf("<+> %d unique subdomains saved to %s\n", len(result), outf)
	}
	if verbose {
		fmt.Printf("[verbose] Done. Total unique subdomains: %d\n", len(result))
	}
}

// recursive search
func recursiveSubdomains(domain string, config Config, all, visited map[string]struct{}, verbose bool, currentDepth, maxDepth int) {
	if _, seen := visited[domain]; seen {
		return
	}
	visited[domain] = struct{}{}
	if verbose {
		fmt.Printf("[verbose] Recursion level %d/%d for %s\n", currentDepth, maxDepth, domain)
	}
	newSubs := []string{}
	for _, tool := range config.Tools {
		cmdline := make([]string, len(tool.Cmd))
		for i, c := range tool.Cmd {
			c = strings.ReplaceAll(c, "{domain}", domain)
			c = strings.ReplaceAll(c, "{wordlist}", config.Wordlist)
			c = strings.ReplaceAll(c, "{resolvers}", config.Resolvers)
			cmdline[i] = c
		}
		fmt.Printf("<+> %s: %s\n", tool.Name, strings.Join(cmdline, " "))
		subs, err := runTool(cmdline, verbose)
		if err != nil {
			fmt.Printf("! %s not complete: %v\n", tool.Name, err)
			continue
		}
		if verbose {
			fmt.Printf("[verbose] %s found %d subdomains (raw output)\n", tool.Name, len(subs))
		}
		for _, sub := range subs {
			if isValidDomain(sub) && strings.HasSuffix(sub, domain) {
				if _, exists := all[sub]; !exists {
					all[sub] = struct{}{}
					newSubs = append(newSubs, sub)
				}
			}
		}
	}
	if currentDepth < maxDepth {
		for _, sub := range newSubs {
			recursiveSubdomains(sub, config, all, visited, verbose, currentDepth+1, maxDepth)
		}
	}
}

func runTool(cmdline []string, verbose bool) ([]string, error) {
	if len(cmdline) == 0 {
		return nil, errors.New("empty command")
	}
	bin, args := cmdline[0], cmdline[1:]
	if verbose {
		fmt.Printf("[verbose] Executing: %s %s\n", bin, strings.Join(args, " "))
	}
	cmd := exec.Command(bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	subs := []string{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if verbose && line != "" {
			fmt.Printf("[verbose] output: %s\n", line)
		}
		if line != "" {
			for _, l := range strings.Split(line, "\n") {
				subs = append(subs, strings.TrimSpace(l))
			}
		}
	}
	cmd.Wait()
	return subs, nil
}

func isValidDomain(s string) bool {
	ok, _ := regexp.MatchString(`^(?:[\w\-\*]{1,63}\.)+[a-zA-Z]{2,}$`, s)
	return ok
}

// --- CONFIG --- //

func configCmd(args []string) {
	if len(args) < 1 {
		configUsage()
		return
	}
	switch args[0] {
	case "add-tool":
		if len(args) < 3 {
			fmt.Println("Example: subsagg config add-tool <name> <cmd1,cmd2,...>")
			return
		}
		addTool(args[1], strings.Split(args[2], ","))
	case "rm-tool":
		if len(args) < 2 {
			fmt.Println("Example: subsagg config rm-tool <name>")
			return
		}
		rmTool(args[1])
	case "set-wordlist":
		if len(args) < 2 {
			fmt.Println("Example: subsagg config set-wordlist <path>")
			return
		}
		setWordlist(args[1])
	case "set-resolvers":
		if len(args) < 2 {
			fmt.Println("Example: subsagg config set-resolvers <path>")
			return
		}
		setResolvers(args[1])
	case "show":
		showConfig()
	case "reset":
		saveConfig(defaultConfig)
		fmt.Println("Config set to default.")
	default:
		configUsage()
	}
}

func loadConfig() Config {
	f, err := ioutil.ReadFile(defaultConfigFile)
	if err != nil {
		saveConfig(defaultConfig)
		return defaultConfig
	}
	var c Config
	yaml.Unmarshal(f, &c)
	// fix for empty fields
	if len(c.Tools) == 0 {
		c.Tools = defaultConfig.Tools
	}
	if c.Wordlist == "" {
		c.Wordlist = defaultConfig.Wordlist
	}
	if c.Resolvers == "" {
		c.Resolvers = defaultConfig.Resolvers
	}
	return c
}

func saveConfig(c Config) {
	bs, _ := yaml.Marshal(&c)
	ioutil.WriteFile(defaultConfigFile, bs, 0644)
}
func showConfig() {
	c := loadConfig()
	bs, _ := yaml.Marshal(&c)
	fmt.Print(string(bs))
}
func addTool(name string, cmd []string) {
	c := loadConfig()
	for _, t := range c.Tools {
		if t.Name == name {
			fmt.Println("That tool is alredy set.")
			return
		}
	}
	c.Tools = append(c.Tools, Tool{Name: name, Cmd: cmd})
	saveConfig(c)
	fmt.Println("Tool added.")
}
func rmTool(name string) {
	c := loadConfig()
	newTools := []Tool{}
	for _, t := range c.Tools {
		if t.Name != name {
			newTools = append(newTools, t)
		}
	}
	c.Tools = newTools
	saveConfig(c)
	fmt.Println("Tool removed.")
}
func setWordlist(path string) {
	c := loadConfig()
	c.Wordlist = path
	saveConfig(c)
	fmt.Println("Wordlist set.")
}
func setResolvers(path string) {
	c := loadConfig()
	c.Resolvers = path
	saveConfig(c)
	fmt.Println("Resolvers set.")
}

func usage() {
	fmt.Printf(`subsagg: subdomain aggregator written in Go

Usage:
  subsagg run <domain> [-v | --verbose] [-r | --recursive] [--depth N]
  subsagg config <action> [arguments]

Config actions:
  add-tool <name> <cmd1,cmd2,...>    - add tool
  rm-tool <name>                     - remove tool
  set-wordlist <path>                - set wordlist
  set-resolvers <path>               - set resolvers file
  show                               - show current config
  reset                              - set to default
`)
}
func configUsage() {
	fmt.Println("Usage: subsagg config <add-tool|rm-tool|set-wordlist|set-resolvers|show|reset> ...")
}
