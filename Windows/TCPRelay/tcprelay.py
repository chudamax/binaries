import pydivert
import argparse
import sys
import signal

def banner():
    print ('')

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit()

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -s 445 -d 8445")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-s', '--src-port', help="source port", type=int, required=True, default = 445)
    parser.add_argument('-d', '--dst-port', help="destination port", type=int, default = 8445)
    
    return parser.parse_args()

def run(src_port, dst_port):
    with pydivert.WinDivert(f"tcp.DstPort == {src_port} or tcp.SrcPort == {dst_port}") as w:
        for packet in w:


            if packet.dst_port == src_port and packet.is_inbound:
                # packet to the server
                print(f"original request: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}, changing dst_port to {dst_port}")
                packet.dst_port = dst_port
                
            elif packet.src_port == dst_port and packet.is_outbound:
                # reply from the server
                print(f"original response: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}, changing src_port to {src_port}")
                packet.src_port = src_port

            else:
                print(f"ignoring packet: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
                

            
            w.send(packet)

def exit_gracefully(signum, frame):
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, exit_gracefully)
    args = parse_args()
    run(src_port=args.src_port, dst_port=args.dst_port)
    
if __name__ == '__main__':
    main()