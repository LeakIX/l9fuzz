package l9l4gfuzz

import (
	"io"
	"io/ioutil"
	"text/template"
	"time"
)

type FuzzerOption func(f *fuzzer) error

func WithTokenTranslator(tt *TokenTranslator) FuzzerOption {
	return func(f *fuzzer) (err error) {
		f.tokenTranslator = tt
		return nil
	}
}

func WithListenAddress(address string) FuzzerOption {
	return func(f *fuzzer) (err error) {
		f.listenAddress = address
		return nil
	}
}

func WithTimeout(timeout int) FuzzerOption {
	return func(f *fuzzer) error {
		f.timeout = time.Duration(timeout) * time.Second
		return nil
	}
}

func WithLDAPLogOutput(logoutput io.Writer) FuzzerOption {
	return func(f *fuzzer) error {
		f.ldapserverOutput = logoutput
		return nil
	}
}

func WithOutputChannel(outputChannel FuzzerChannel) FuzzerOption {
	return func(f *fuzzer) error {
		f.fuzzerOutputChannel = outputChannel
		return nil
	}
}

func WithRequestTemplate(filePath string) FuzzerOption {
	return func(f *fuzzer) error {
		if filePath == "" {
			return nil
		}
		// #nosec We'll allow the CLI user to read his own files
		fileBytes, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}
		f.requestTemplate, err = template.New("request_template").Parse(string(fileBytes))
		if err != nil {
			return err
		}
		return nil
	}
}

func WithPayloadTemplate(filePath string) FuzzerOption {
	return func(f *fuzzer) error {
		if filePath == "" {
			return nil
		}
		// #nosec We'll allow the CLI user to read his own files
		fileBytes, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}
		f.payloadTemplate, err = template.New("payload_template").Parse(string(fileBytes))
		if err != nil {
			return err
		}
		return nil
	}
}
