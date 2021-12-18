package l9l4gfuzz

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/gboddin/goccm"
	"github.com/schollz/progressbar/v3"
	"io"
	"log"
	"os"
	"os/signal"
	"time"
)

type Scanner struct {
	ListenAddress   string   `kong:"short='l',required,help='Listen address (ip:port)'"`
	InputFile       *os.File `kong:"short='i',required,help='Input file, - for STDIN'"`
	OutputFile      *os.File `kong:"short='o',help='Output file'"`
	MaxConnections  int      `kong:"short='m',help='Max connections',default='100'"`
	Psk             string   `kong:"short='k',help='Payload sign key',default='no-payload-check'"`
	RequestTemplate string   `kong:"short='r',help='Uses a custom request template'"`
	PayloadTemplate string   `kong:"short='p',help='Uses a custom payload'"`
	Timeout         int      `kong:"short='t',default='2',help='Timeout (LDAP,http,tcp...)'"`
	Wait            int      `kong:"short='w',default='60',help='Wait for ping after scan is done, < 0 waits forever'"`
	JSON            bool     `kong:"short='j',default='false',help='Output results as JSON'"`
	Quiet           bool     `kong:"short='q',help='No progress bar',default='false'"`
	LDAPDebug       *os.File `kong:"short='L',help='LDAP server debug log file'"`
	Debug           bool     `kong:"short='d',help='Debug',default='false'"`

	ccm           *goccm.ConcurrencyManager
	outputChannel FuzzerChannel
	bar           *progressbar.ProgressBar
}

func (cmd *Scanner) displayResults() {
	var writer io.Writer
	if cmd.OutputFile != nil {
		writer = cmd.OutputFile
	} else {
		writer = os.Stdout
	}
	var jsonEncoder *json.Encoder
	if cmd.JSON {
		jsonEncoder = json.NewEncoder(writer)
	}
	for {
		result, open := <-cmd.outputChannel
		if !open {
			return
		}
		if jsonEncoder != nil {
			if err := jsonEncoder.Encode(result); err != nil {
				log.Fatalln(err)
			}
		} else {
			if _, err := writer.Write(
				[]byte(fmt.Sprintf("[%s-reply] From: %s:%s | Source: %s | Vector: %s | Delay: %s\n",
					result.Protocol,
					result.Ip,
					result.Port,
					result.Token.SourceUrl,
					result.Token.PayloadSource,
					time.Since(result.Token.IssueDate)))); err != nil && cmd.Debug {
				log.Fatalln(err)
			}
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
		WithRequestTemplate(cmd.RequestTemplate),
		WithPayloadTemplate(cmd.PayloadTemplate),
	)
	if err != nil {
		return err
	}
	if !cmd.Quiet {
		cmd.bar = progressbar.NewOptions(-1,
			progressbar.OptionSetWriter(os.Stderr),
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
	if cmd.Wait < 0 {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		//wait for interrupt
		<-c
	} else {
		time.Sleep(time.Duration(cmd.Wait) * time.Second)
	}
	close(cmd.outputChannel)
	if cmd.OutputFile != nil {
		return cmd.OutputFile.Close()
	}
	return nil
}
