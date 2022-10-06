import argparse
import nmap3

def scan(address, params):
    return nmap.nmap_version_detection(address, args=params)

#def format(scan_result): #WILL ADD LATER
#    return scan_result

def main(args):
    input_file = args['input_file']
    ips = map(str.strip, open(input_file,"r").readlines())
    scan_args = "-sC"
    if args['vuln_scan'] == True:
        scan_args = "--script vulners --script-args mincvss+5.0"
    scan_results = []
    for ip in ips:
        print(f"[+] Beginning scan on: {ip}")
        scan_results.append(scan(ip,scan_args))
        print(f"[-] Finished scan on: {ip}\n")
    if args['output_file']:
        with open(args['output_file'], 'w') as of:
            for result in scan_results:
                of.write(f'{result}\n')
    else:
        for result in scan_results:
            print(result)

if __name__ == '__main__':
    nmap = nmap3.Nmap()
    parser = argparse.ArgumentParser(description='Runs nmap scans, with the option to do a CVE scan.')
    parser.add_argument('-v','--vuln-scan', help='Adding this runs a vulnerabilty scan as opposed to a standard scan.', action='store_const', const=True, required=False)
    parser.add_argument('-i','--input-file', help='The argument specifies the location of the text file to load your IP list from.', required=True)
    parser.add_argument('-o','--output-file', help='Specify where you want to output the file to.', required=False)
    args = vars(parser.parse_args())
    main(args)
