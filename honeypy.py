# Libraries
import argparse
from ssh_honeypot import honeypot

# Parse Arguments

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)
    parser.add_argument('-s', '--ssh', action="store_true")

    args = parser.parse_args()

   
if args.ssh:
    print("[-] Running SSH Honeypot...")
    honeypot(args.address, args.port, args.username, args.password)          
else:
    print(f"\n[!] Exiting HoneyPY due to error\n")