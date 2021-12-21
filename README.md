# log4j-quick-scan

Scan your IP network and determine hosts with possible CVE-2021-44228 vulnerability in log4j library.

There are far better and advanced tools for security audit, but many of them requires commercial penetration software or external, 3rd party service or software.

This script is written to be quick and independent little tool. It will not confirm that your servers and devices are 100% safe. Consider it as one of many tools you should use to audit your IT environment. Can be used on private and public IP addresses.

Script is not log4shell exploit demonstration. It will not do any harm or try to execute remote code.

## How test works

Script creates HTTPS (ports ending with 443) or HTTP (all other ports) request, with special string in fields: `User-Agent`, `X-Api-Version` and `X-Forwarded-For`. That special string is in format `${jndi:ldap://some_listen_host:port}` .

If vulnerable log4j library is used to log user activity (our http request) somewhere in path “user -> service | load balancers -> security -> servers -> logging”, it will parse JNDI string and try to establish LDAP session to our `some_listen_host:port`.

If we monitor traffic on `some_listen_host:port` and spot such packets, their source should be examined further.

Default ports where http(s) requests are sent are 80, 8080, 443 and 8443.

## What you need

1.  Linux host where to download and run this Python script. It should have access to your target IP network .
2.  Listen host (preferably Linux) where IP traffic could be monitored. It should be reachable from your target IP network. Avoid any NAT between targeted network and this host, otherwise you could not recognize suspects.

These two hosts can be the same machine.

## How to use (example)

On listen host, start `tcpdump` to catch packets received on some free TCP port. Example:

```bash
tcpdump -nn -i ens160 tcp port 12345
```

On Linux host, run script with required parameters. Example:

```bash
./log4j-quick-scan.py -e 192.168.0.3:12345 192.168.0.0/24"
```

This will test `192.168.0.0/24` network trying to trigger TCP connection to listen host `192.158.0.3` on port `12345`.

Monitor `tcpdump` output on listen host. Targets that are suspects for log4j vulnerability will parse JNDI string and try to establish LDAP connection.

## Notes

It is ineffective and extremely slow to scan all ports. Since log4j library is used in many products, determine first what web ports are used in your environment. Run script with your custom port list.

There are too many elements that can prevent script and other tools from external discovering log4j vulnerability. Some of them are: network and server firewalls, web application firewalls, custom tcp ports, software/service do not log low severity events (like our ordinary http request), script access IP address instead of required hostname, etc…

Always check open source project or software’s vendor notices for details about log4j issue.

## Usage

```text
usage: log4j-quick-scan.py [-h] [-V] -e LISTENHOST [-p PORTS] [-l LOG] target

Scan hosts with log4j+jndi doing external connections.

required arguments:
  -e LISTENHOST, --listenhost LISTENHOST
                        Host[:port] where to monitor tcp connections. It could be the same machine where script is to be run.

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Display version and exit.
  -p PORTS, --ports PORTS
                        Optional, comma separated list of ports on tested hosts. Default: 80,8080,443,8443
  -l LOG, --log LOG     Optional, append output to custom log file. Default: ./log4j-quick-scan.log

positional arguments:
  target                Scan target: IP network in CIDR format.
```
