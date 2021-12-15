package l9l4gfuzz

import (
	"bufio"
	"fmt"
	"github.com/gboddin/goccm"
	"github.com/schollz/progressbar/v3"
	"io"
	"log"
	"os"
	"time"
)

type Scanner struct {
	Timeout        time.Duration `kong:"default='2s'"`
	Wait           time.Duration `kong:"default='1m'"`
	ListenAddress  string        `kong:"short='l',required,help='Listen address (ip:port)'"`
	InputFile      *os.File      `kong:"short='i',required,help='Input file, - for STDIN'"`
	OutputFile     *os.File      `kong:"short='o',help='Output file'"`
	LDAPDebug      *os.File      `kong:"short='L',help='LDAP server debug log file'"`
	MaxConnections int           `kong:"short='m',help='Max connections',default='100'"`
	Quiet          bool          `kong:"short='q',help='No progress bar',default='false'"`
	Debug          bool          `kong:"short='d',help='Debug',default='false'"`
	Psk            string        `kong:"short='k',help='Payload sign key',default='no-payload-check'"`
	Template       string        `kong:"short='t',help='Bypasses protocols and use TCP template (stateless)'"`
	ccm            *goccm.ConcurrencyManager
	outputChannel  FuzzerChannel
	bar            *progressbar.ProgressBar
}

func (cmd *Scanner) displayResults() {
	var writer io.Writer
	if cmd.OutputFile != nil {
		writer = cmd.OutputFile
	} else {
		writer = os.Stdout
	}
	for {
		result, open := <-cmd.outputChannel
		if !open {
			return
		}
		if _, err := writer.Write(
			[]byte(fmt.Sprintf("[ldap-reply] From: %s:%s | Source: %s | Vector: %s | Delay: %s\n",
				result.Ip,
				result.Port,
				result.Token.SourceUrl,
				result.Token.PayloadSource,
				time.Since(result.Token.IssueDate)))); err != nil && cmd.Debug {
			log.Println(err)
		}

	}
}

func (cmd *Scanner) Run() (err error) {
	cmd.outputChannel = make(FuzzerChannel)
	go cmd.displayResults()
	cmdFuzzer, err := NewFuzzer(
		WithListenAddress(cmd.ListenAddress),
		WithTimeout(cmd.Timeout),
		WithLDAPLogOutput(cmd.LDAPDebug),
		WithOutputChannel(cmd.outputChannel),
		WithTokenTranslator(&TokenTranslator{Secret: []byte(cmd.Psk)}),
		WithGenericTemplate(cmd.Template),
	)
	if err != nil {
		return err
	}
	if !cmd.Quiet {
		cmd.bar = progressbar.NewOptions(-1,
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowIts(),
			progressbar.OptionSetWidth(40),
			progressbar.OptionSetDescription("[cyan][1/2][reset] Scanning..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}
	cmd.ccm = goccm.New(cmd.MaxConnections)
	lineReader := bufio.NewScanner(cmd.InputFile)
	for lineReader.Scan() {
		line := lineReader.Text()
		cmd.ccm.Wait()
		go func() {
			defer cmd.ccm.Done()
			if err := cmdFuzzer.FuzzUrl(line); err != nil && cmd.Debug {
				log.Println(err)
			}
			if cmd.bar != nil {
				// #nosec , progress bar can fail
				cmd.bar.Add(1)
			}
		}()
	}
	if cmd.bar != nil {
		cmd.bar.Describe("[cyan][2/2][reset] Waiting...")
	}
	cmd.ccm.WaitAllDone()
	time.Sleep(cmd.Wait)
	close(cmd.outputChannel)
	if cmd.OutputFile != nil {
		return cmd.OutputFile.Close()
	}
	return nil
}
