import sys
import socket
import threading
import base64
import time
import signal
import argparse

def get_args_global():
    description = f'''
    ********************************
    Original tool: https://labs.withsecure.com/tools/tcp-over-file-tunnel
    Migration to Python 3.
    ********************************
    Usage: python3 {sys.argv[0]} --mode 1 --ip_addr 127.0.0.1 --port 8080 --read_file ./test --write_file ./test2
    Chain example: Browser <-> [{sys.argv[0]} --mode 2] <-> File share <-> [{sys.argv[0]} --mode 1] <-> Target website.
    ********************************
    '''
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--mode', '-m', dest='mode', action='store',
                    type=int, 
                    required=True,
                    help='Current mode to operate. 1 - client, 2 - server')
    
    parser.add_argument('--ip_addr', '-i', dest='ip_addr', action='store',
                    type=str,
                    required=True,
                    help='IP Address. Mode 1 - Where to send traffic. Mode 2 - Where to wait for traffic.')
    
    parser.add_argument('--port', '-p', dest='port', action='store',
                    type=int,
                    required=True,
                    help='Port config. Mode 1 - Where to send traffic. Mode 2 - Where to wait for traffic.')
    
    parser.add_argument('--read_file', '-r', dest='read_file', action='store',
                    type=argparse.FileType('w'),
                    required=True,
                    help='Tricky file 1. Check README for explanation.')
    
    parser.add_argument('--write_file', '-w', dest='write_file', action='store',
                    type=argparse.FileType('w'),
                    required=True,
                    help='Tricky file 2. Check README for explanation.')
    
    parser.add_argument('--encrypt', dest='encrypt', action='store_true',
                        help='Encrypt messages in file with provided passphrase. Need some extra libs.')
    
    parser.add_argument('--debug', dest='debug', action='store_true')
    
    try:
        args = parser.parse_args()
        if len(sys.argv) == 1:
            raise Exception
    except Exception as e:
        print(e)
        parser.print_help(sys.stderr)
        exit()

    if args.mode not in [1,2]:
        print('[-] Wrong mode! Use --help!')
        exit()
    
    if args.port not in range(0, 65535):
        print('[-] Wrong port. Use --help!')
        parser.print_help(sys.stderr)
        exit()

    args.read_file.close()
    args.write_file.close()
    
    return args

def sig_handler(signum, frame):
    print("Signal caught, exiting...")
    sys.exit(1)


class main_runner:
    def __init__(self, args):
        self.debug = args.debug
        self.mode = args.mode
        self.ip_addr = args.ip_addr
        self.port = args.port
        self.read_f = open(args.read_file.name, 'r')
        self.write_f = open(args.write_file.name, 'w')
        self.lock = threading.Lock() ### Replace of mutex.lock
        self.buffered_data = {}
        self.encrypt = args.encrypt
        if self.encrypt:
            ### Yeah, some "cool" crypto here!
            ### Check README
            from cryptography.fernet import Fernet
            from getpass import getpass
            self.enc_phrase = getpass(prompt='Enter password to encrypt:\n>')
            if len(self.enc_phrase) == 0: 
                print('[*] Please provide passphrase.')
                exit()
            else:
                if len(self.enc_phrase) < 32:
                    self.enc_phrase = base64.urlsafe_b64encode((self.enc_phrase + 'A' * (32-len(self.enc_phrase))).encode())
                elif len(self.enc_phrase) > 32:
                    print('[*] Key too long. Not supported for now.')
                else:
                    self.enc_phrase.encode()
        if self.debug and self.encrypt: print(self.enc_phrase, 'Len:', len(self.enc_phrase), 'Type:', type(self.enc_phrase))
        if self.encrypt: self.fernet = Fernet(self.enc_phrase)

    def run(self):
        if self.mode == 1:
            print('[*] Running client mode.')
            signal.signal(signal.SIGABRT, sig_handler)
            print("[*] Prese Ctrl-Break to quit")
            t1 = threading.Thread(target = self.file_reader, name="file reader", args=[])
            t1.start()
            while True:
                time.sleep(0.1)
        else:
            print('[*] Running server mode.')
            signal.signal(signal.SIGABRT, sig_handler)
            print("[*] Prese Ctrl-Break to quit")
            t1 = threading.Thread(target = self.connection_accepter, name="connection accepter", args=[])
            t1.start()
            t1 = threading.Thread(target = self.file_reader, name="file reader", args=[])
            t1.start()
            while True:
                time.sleep(0.1)

    def connection_accepter(self):
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.bind((self.ip_addr, self.port))
        next_conn_id = 1

        while True:
            serversocket.listen(5)
            (s, clientaddress) = serversocket.accept()
            conn_id = next_conn_id
            next_conn_id += 1
            print(f"[*] Connection received (ID = {conn_id}) from {clientaddress[0]}:{clientaddress[1]}")
            while(self.lock.acquire() == False):
                pass
            self.write_f.write(f"{conn_id} #CONNECT#$")
            self.write_f.flush()
            self.buffered_data[conn_id] = []
            self.lock.release()
            t = threading.Thread(target = self.socket_reader_thread, name=f"t{conn_id}", args=[conn_id, s])
            t.start()
            t = threading.Thread(target = self.socket_writer_thread, name=f"t{conn_id}", args=[conn_id, s])
            t.start()

    def socket_writer_thread(self, conn_id, s):
        while True:
            if conn_id in self.buffered_data:
                if (len(self.buffered_data[conn_id]) > 0):
                    while(self.lock.acquire() == False):
                        pass
                    try:
                        data = self.buffered_data[conn_id].pop(0)
                    except KeyError as e:
                        self.lock.release()
                        break
                    self.lock.release()
                    s.send(data)
                else:
                    time.sleep(0.001)
            else:
                break

    def socket_reader_thread(self, conn_id, s):
        while True:
            if conn_id in self.buffered_data:
                try:
                    data = s.recv(768)
                except socket.error as e:
                    print(f"[*] (ID = {conn_id}): {e}")
                    while(self.lock.acquire() == False):
                        pass
                    self.write_f.write("%d #DISCONNECT#$" % (conn_id))
                    self.write_f.flush()
                    del self.buffered_data[conn_id]
                    s.close()
                    self.lock.release()
                    break
                while(self.lock.acquire() == False):
                    pass
                if len(data) > 0:
                    encoded_data = base64.b64encode(data)
                    if self.encrypt:
                        encoded_data = self.fernet.encrypt(encoded_data)
                    if self.debug:
                        print('[D] Data to encode:', data, flush=True)
                        print('[D] Encoded data:', encoded_data, flush=True)
                    self.write_f.write(f"{conn_id} {encoded_data}$")
                    self.write_f.flush()
                self.lock.release()
            else:
                s.close()
                break

    def file_reader(self):
        packet_buffer = ""
        while True:
            packet = self.read_f.read(1024)
            if (packet != ''):
                packet_buffer += packet
                while True:
                    (part_before, part_sep, part_after) = packet_buffer.partition("$")
                    if (part_sep == ''):
                        break
                    if self.debug: print('[D] Part before:', part_before)
                    self.process_packet(part_before)
                    packet_buffer = part_after
            else:
                time.sleep(0.001)

    def process_packet(self, packet):
        (conn_id, data) = packet.split(" ")
        conn_id = int(conn_id)
        while(self.lock.acquire() == False):
            pass
        if (data == "#CONNECT#"):
            print(f"[*] Connection request received (ID = {conn_id}). Connecting to {self.ip_addr} on port {self.port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip_addr, self.port))
            self.buffered_data[conn_id] = []
            t = threading.Thread(target = self.socket_reader_thread, name=f"r{conn_id}", args=[conn_id, s])
            t.start()
            t = threading.Thread(target = self.socket_writer_thread, name=f"w{conn_id}", args=[conn_id, s])
            t.start()
        elif (data == "#DISCONNECT#"):
            print(f"[*] Disconnect request received (ID = {conn_id}). Connection terminated.")
            del self.buffered_data[conn_id]
        else:
            data = data[2:len(data)-1]
            if self.debug:
                print('[D] Readed b64data:', data, 'Type:', type(data), flush=True)
            if self.encrypt:
                data = self.fernet.decrypt(data.encode())
            decoded_data = base64.b64decode(data)
            if self.debug:
                print('[D] Decoded data:', decoded_data, flush=True)
            try:
                self.buffered_data[conn_id].append(decoded_data)
            except KeyError as error:
                print('[E] process_packet error:', error)
        self.lock.release()
    
if __name__ == '__main__':
    args = get_args_global()
    new_runner = main_runner(args)
    new_runner.run()
