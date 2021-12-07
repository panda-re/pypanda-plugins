from pandare import PyPlugin

#panda = None



class AbstractSocket():
    '''
    msghdr: pointer | socklen_t | pointer | size_t | pointer | size_t | int
        4 bytes | ??? bytes | 4 bytes | ? bytes| 4 bytes | ? bytes| ? bytes
    '''

    domains = ["AF_UNSPEC", "AF_UNIX", "AF_INET", "AF_IMPLINK", "AF_PUP", "AF_CHAOS", "AF_NS", "AF_ISO", "AF_OSI", "AF_ECMA", "AF_DATAKIT", "AF_CCITT", "AF_SNA", "AF_DECnet", "AF_DLI", "AF_LAT", "AF_HYLINK", "AF_APPLETALK", "AF_ROUTE", "AF_LINK", "pseudo_AF_XTP", ""]
   
    tps = ["SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_RDM", "SOCK_SEQPACKET", '']
    
    def __init__(self, panda, absock_id, creator, phys_addr, init_fd, init_fn, init_domain, init_type, init_prot):
        self.panda = panda
        self.absock_id = absock_id

        self.addr_size = int(self.panda.bits/8)
        self.proc = creator
        self.phys_addrs = [phys_addr]
        self.ifd = init_fd
        self.ifn = init_fn
        if init_domain ==  None or init_domain not in range(0, len(self.domains) ):
            init_domain = -1
        if init_type == None or init_type not in range(0, len(self.tps) ):
            init_type = -1
        if init_prot == None or init_prot not in range(0, len(self.domains) ):
            init_prot = -1
        self.idom = self.domains[init_domain]
        self.itype = self.tps[init_type]
        self.iprot = self.domains[init_prot]
        self.assc_fds = [init_fd]
        self.msgs = []
        self.conns = []

        self.dead_af = b'\xde\xad\x00\xaf'*int(self.addr_size/4)

        self.sock_addr_len = 0
        self.sock_addr_fam = -1
        self.sock_addr_name = None

    def read_msg(self, cpu, proc, msg, length, fn):
        try:
            read = self.panda.virtual_memory_read(cpu, msg, length, fmt="bytearray")
            read_int = self.panda.virtual_memory_read(cpu, msg, length, fmt='int')
            read_str = self.panda.read_str(cpu, msg, length)
        except Exception as e:
            print("Cannot read msg because: %s"%e)
            read = self.dead_af
            read_int = 0xdead00af
            read_str = "dead00af"

        msg_arr = [proc, fn, read, read_int, read_str]
        self.msgs.append(msg_arr)
        return read

    def read_msghdr(self, cpu, proc, msg, fn):
        read_len = 7 * self.addr_size
        try:
            msghdr = self.panda.virtual_memory_read(cpu, msg, read_len, fmt='bytearray')
        except Exception as e:
            print("Cannot read msghdr because: %s"%e)
            msghdr = self.dead_af
        msg_iov = []
        cmsghdr = None
        
        if msghdr != self.dead_af:
            msghdr, msg_iov, cmsghdr = self.parse_msghdr(cpu, msghdr)
        else:
            msghdr = {'name':None, 'name_len':None, 'msg_iov_ptr':None, 'msg_iov':None, 'msg_iov_len':None, 'msg_control':None, 'msg_controllen':None, 'msg_flags':None}

        msgs = []
        smsgs = []
        cmsgs = []
        for msg in msg_iov:
            try:
                read = self.panda.virtual_memory_read(cpu, msg, 4, fmt='int')
            except Exception as e:
                read = 0xdead00af
                if self.addr_size == 8:
                    read = 0xdead00afdead00af
            try:
                sread = self.panda.read_str(cpu, msg)
            except:
                sread = "NOT_A_STRING"
            try:
                cread = self.panda.read_str(cpu, msghdr[msg_control] + 12)
            except:
                cread = "NOT_A_STRING"
            msgs.append(read)
            smsgs.append(sread)
            cmsgs.append(cread)

        msgs = ', '.join(map(hex, msgs))
        self.msgs.append([proc, fn, msghdr, msg_iov, msgs, smsgs, cmsghdr, cmsgs])
        return msghdr, msg_iov, msgs, smsgs, cmsghdr

    def parse_msghdr(self, cpu, data, endian='little'):
      
        data_arr = [ data[i:i+self.addr_size] for i in range(0, len(data), self.addr_size) ]
        name_dat, name_len_dat, msg_iov_dat, msg_iovlen_dat, msg_control_dat, msg_controllen_dat, msg_flags_dat = data_arr

        name = int.from_bytes(name_dat, endian)
        name_len =  int.from_bytes(name_len_dat, endian)
        msg_iov_array = int.from_bytes(msg_iov_dat, endian)
        msg_iovlen = int.from_bytes(msg_iovlen_dat, endian)
        
        msg_control = int.from_bytes(msg_control_dat, endian)
        msg_controllen = int.from_bytes(msg_controllen_dat, endian)
        msg_flags = int.from_bytes(msg_flags_dat, endian)

        try:
            msg_iov = self.panda.virtual_memory_read(cpu, msg_iov_array, msg_iovlen*self.addr_size, fmt='ptrlist')
        except Exception as e:
            print('Issue reading the msg_iov array because %s'%e)
            return

        try:
            cmsghdr = self.panda.virtual_memory_read(cpu, msg_control, msg_controllen*self.addr_size)
        except Exception as e:
            print('Issue reading cmsghdr: %s'%e)
            cmsghdr = b'\xde\xad'

        
        msg_hdr = { 'name'           : name,
                    'name_len'       : name_len,
                    'msg_iov_ptr'    : msg_iov_array,
                    'msg_iov'        : msg_iov,
                    'msg_iovlen'     : msg_iovlen,
                    'msg_control'    : msg_control,
                    'cmsghdr'        : cmsghdr,
                    'msg_controllen' : msg_controllen,
                    'msg_flags'      : msg_flags}
        return msg_hdr, msg_iov, cmsghdr

    def read_sockaddr(self, cpu, addr, addrlen, endian='little'):
        addrlen = 16
        try:
            data = self.panda.virtual_memory_read(cpu, addr, 2)
            name = self.panda.read_str(cpu, addr + 2)
        except Exception as e:
            return
        addr_len = int.from_bytes(data[:1], endian)
        addr_fam = int.from_bytes(data[1:2], endian)

        sock_addr =  {"len": addr_len, "fam": addr_fam, "name": name}
        if self.idom == None:
            self.idom = self.domains[addr_fam]
        if self.iprot == None:
            self.iprot = self.domains[addr_fam]
        if self.sock_addr_name == None:
            self.sock_addr_name = name
            self.sock_addr_len = addr_len
            self.sock_addr_fam = addr_fam

        return sock_addr

    def print_sock(self):
        msgs = self.build_msg_str()
        brk = '#'*100
        ret = f"AbstractSocket {self.absock_id} with phys_addr: {' '.join(map(hex, self.phys_addrs))} | domain: {self.idom} | type: {self.itype} | protocol: {self.iprot}\n"
        ret += f"\tWith sockaddr len: {self.sock_addr_len} | family: {self.domains[self.sock_addr_fam]} | name: {self.sock_addr_name}\n"
        ret += f"\tby function: {self.ifn}\n\tWith associated fds: {self.assc_fds}\n"
        ret += f"\tWith connections to processes: {self.conns}\n\tWith messages passed:\n{msgs}\n{brk}\n\n"

        return ret

    def build_msg_str(self):
        count = 1
        ret = ''
        for msg_arr in self.msgs:
            fn = msg_arr[1]
            if 'msg' in fn:
                proc, fn, header, iovec, iovec_int, iovec_str, cmsghdr, cmsghdr_str = msg_arr

                s = f"\tProc {proc} {fn}s message {count}\tName: {header['name']}\n"
                s += f"\t\tiovector: {iovec}\t{iovec_int}\t{iovec_str}\n"
                s += f"\t\tcmsg: {cmsghdr}\n\t\t\t{cmsghdr_str}\n\n"
                ret += s
                count += 1
            else:
                proc, fn, msg, msg_int, msg_str = msg_arr
                s = f"\tProc {proc} {fn}'s msg {count}\n"
                s += f"\t\tmsg: {msg}\t0x{msg_int:x}\t{msg_str.strip()}\n\n"
                ret += s
                count += 1
        return ret


class SocketSnoop(PyPlugin):

    def __init__(self, pnd):
        self.sockets = []
        self.panda = pnd
        self.addr_size = int(self.panda.bits / 8)
        self.as_count = 0

        if not "syscalls2" in self.panda.plugins:
            print("Did not load syscall2 yet, loading now")
            self.panda.load_plugin("syscalls2", args = {"load-info": True})

        @self.panda.ppp("syscalls2", "on_sys_socket_return")
        def sock_record(cpu, pc, domain, sock_type, protocol):
            proc, proc_obj = self.get_proc_name(cpu)
            fd = self.panda.arch.get_return_value(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fd, "socket", dom=domain, ty=sock_type, prot=protocol) 
            with open("sock.txt", 'a') as f:
                try:
                    first = s.domains[domain]
                except IndexError:
                    first = "err"
                try:
                    second = s.domains[protocol]
                except IndexError:
                    second = "err"
                try:
                    st_str = s.tps[sock_type]
                except IndexError:
                    st_str = "err"
                f.write(f"{proc}: SOCKET(domain: 0x{domain:x} [{first}], type: 0x{sock_type:x} [{st_str}], protocol: 0x{protocol:x} [{second}]) RETURNS fd: 0x{fd:x}\n")
        
        @self.panda.ppp("syscalls2", "on_sys_bind_enter")
        def bind_record(cpu, pc, fd, addr, addrlen):
            proc, proc_obj = self.get_proc_name(cpu)
            sock = self.find_sock(cpu, proc_obj, proc, fd, 'bind', addr=addr, addrlen=addrlen)
            sock_addr = sock.read_sockaddr(cpu, addr, addrlen)
            with open("sock.txt", 'a') as f:
                proc, proc_obj = self.get_proc_name(cpu)
                f.write(f"{proc} BIND(fd: 0x{fd:x}, addr: 0x{addr:x} | {sock_addr})\n")

        @self.panda.ppp("syscalls2", "on_sys_socketpair_return")
        def socket_pair_ret_record(cpu, pc, domain, sock_type, protocol, sv):
            try:
                fds = self.panda.virtual_memory_read(cpu, sv, self.addr_size, fmt="ptrlist")
            except Exception as e:
                print("FAIL READ %s"%e)
                fds = [0xdead00af, 0xbadb00bad]
            pfds = []
            for i in fds:
               pfds.append( f"0x{i:x}")
            proc, proc_obj = self.get_proc_name(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fds, "socketpair", dom=domain, ty=sock_type, prot=protocol)
            for i in fds:
                if i not in s.assc_fds:
                    s.assc_fds.append(i)
            with open("sock.txt", 'a') as f:
                f.write(f"{proc}: SOCKETPAIR(domain: 0x{domain:x} [{s.idom}], type: 0x{sock_type:x} [{s.itype}], protocol: 0x{protocol:x} [{s.iprot}], sv[2]: {sv} [{pfds}])\n")

        @self.panda.ppp("syscalls2", "on_sys_sendto_return")
        def sendto_record(cpu, pc, fd, buf,  length, flags, addr, addr_len):
            proc, proc_obj = self.get_proc_name(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fd, "sendto", addr=addr, addrlen=addr_len)
            read = s.read_msg(cpu, proc, buf, length, "sendto")
            with open("sock.txt", 'a') as f:
                proc, proc_obj = self.get_proc_name(cpu)
                f.write(f"{proc}: SENDTO(fd: 0x{fd:x}, buf: 0x{buf:x} (msg: {read}), length: {length}, flags: 0x{flags:x}, addr: 0x{addr:x}, addr_len: 0x{addr_len:x})\n")

        @self.panda.ppp("syscalls2", "on_sys_recvfrom_return")
        def recvfrom_record(cpu, pc, fd, buf, length, flags, addr, addr_len):
            ret = self.panda.arch.get_return_value(cpu)
            ret = self.tc(ret, self.addr_size*4)
            proc, proc_obj = self.get_proc_name(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fd, "recvfrom")
            read = s.read_msg(cpu, proc, buf, ret, "recvfrom")
            with open("sock.txt", 'a') as f:
                proc, proc_obj = self.get_proc_name(cpu)
                f.write(f"{proc}: RECVFROM(fd:, 0x{fd:x}, buf: 0x{buf:x} (msg: {read}), length: {length}, flags: 0x{flags:x}, addr: 0x{addr:x}, addr_len: 0x{addr_len:x}\n")

        @self.panda.ppp("syscalls2", "on_sys_listen_enter")
        def listen_record(cpu, pc, fd, backlog):
            with open("sock.txt", 'a') as f:
                proc, proc_obj = self.get_proc_name(cpu)
                f.write(f"{proc}: LISTEN(fd: 0x{fd:x})\n")
        

        @self.panda.ppp("syscalls2", "on_sys_getpeername_enter")
        def getpeername_record(cpu, pc, fd, addr, addrlen):
            with open("sock.txt", 'a') as f:
                proc, proc_obj = self.get_proc_name(cpu)
                f.write(f"{proc}: GETPEERNAME(fd: 0x{fd:x}, addr: 0x{addr:x}, addrlen: 0x{addrlen:x})\n")

        @self.panda.ppp("syscalls2", "on_sys_connect_return")
        def connect_record(cpu, pc, fd, addr, addrlen):
            ret = self.panda.arch.get_return_value(cpu)
            l_ret = len(f"{ret:x}")
            if l_ret > 0:
                ret = self.tc(ret, l_ret)
            proc, proc_obj = self.get_proc_name(cpu)
            sock = self.find_sock(cpu, proc_obj, proc, fd, "connect", addr=addr, addrlen=addrlen)
            sock_addr = sock.read_sockaddr(cpu, addr, addrlen)
            with open("sock.txt", 'a') as f:
                f.write(f"{proc}: CONNECT(fd: 0x{fd:x}, addr: 0x{addr:x} | {sock_addr}, addrlen: 0x{addrlen:x}) RETURNS: {ret}\n")

        @self.panda.ppp("syscalls2", "on_sys_sendmsg_enter")
        def sendmsg_record(cpu, pc, fd, msg, flags):
            proc, proc_obj = self.get_proc_name(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fd, "sendmsg")
            msghdr, msg_iov, msgs, smsgs, cmsghdr = s.read_msghdr(cpu, proc, msg, "sendmsg")
            with open("sock.txt", 'a') as f:
                f.write(f"{proc}: SENDMSG(fd: 0x{fd:x}, msg: {msghdr} | {msgs}, cmsg: {cmsghdr}, flags: 0x{flags:x})\n")

        
        @self.panda.ppp("syscalls2", "on_sys_recvmsg_return")
        def recvmsg_record(cpu, pc, fd, msg, flags):
            ret = self.panda.arch.get_return_value(cpu)
            ret = self.tc(ret, 32) 
            proc, proc_obj = self.get_proc_name(cpu)
            s = self.find_sock(cpu, proc_obj, proc, fd, "recvmsg")
            msghdr, msg_iov, msgs, smsgs, cmsghdr = s.read_msghdr(cpu, proc, msg, "recvmsg")

            with open("sock.txt", 'a') as f:
                f.write(f"{proc}: RECVMSG(fd: 0x{fd:x}, msg: {msghdr} | {', '.join(map(hex, msg_iov))} | {msgs} | {', '.join(smsgs)}, cmsg: {cmsghdr}, flags: 0x{flags:x}) RETURNS: {ret}\n")

        # syscalls that aren't on x86
        if self.panda.arch_name not in ['x86_64', 'i386']:
            @self.panda.ppp("syscalls2", "on_sys_socketcall_enter")
            def socket_call_record(cpu, pc, call, args):
                calls = ["socket", "bind", "connect", "listen", "accept", "getsockname", "getpeername", "socketpair", "send", "recv", "sendto", "recvfrom", "shutdown", "setsockopt", "getsockopt", "sendmsg", "recvmsg", "accept4", "recvmmsg", "sendmmsg", '']
                if call > len(calls) - 2:
                    print("CALL OUT OF BOUNDS %d"%call)
                    call = -1
                #proc, proc_obj = self.get_proc_name(cpu)
                #sock = self.find_sock(cpu, proc_obj, proc, 
                with open("sock.txt", 'a') as f:
                    proc, proc_obj = self.get_proc_name(cpu)
                    f.write(f"{proc}: SOCKETCALL(call: 0x{call:x}, args: {args})\n")
            
            @self.panda.ppp("syscalls2", "on_sys_send_enter")
            def send_record(cpu, pc, fd, msg, length, flags):
                try:
                    smsg = self.panda.ffi.read_str(cpu, msg)
                except:
                    smsg = 'ERROR_PANDA'
                with open("sock.txt", 'a') as f:
                    proc, proc_obj = self.get_proc_name(cpu)
                    f.write(f"{proc}: SEND(fd: 0x{fd:x}, msg: 0x{msg:x} [{smsg}], length: 0x{length:x}, flags: 0x{flags:x})\n")

            @self.panda.ppp("syscalls2", "on_sys_recv_enter")
            def recv_record(cpu, pc, fd, msg, length, flags):
                try:
                    smsg = self.panda.ffi.read_str(cpu, msg)
                except:
                    smsg = 'ERROR_PANDA'
                with open("sock.txt", 'a') as f:
                    proc, proc_obj = self.get_proc_name(cpu)
                    f.write(f"{proc}: RECV(fd: 0x{fd:x}, msg: 0x{msg:x} [{smgg}], length: 0x{length:x}, flags: 0x{flags:x})\n")

            #@self.panda.ppp("syscalls2", "on_sys_accept_enter")
            def accept_enter_record(cpu, pc, fd, addr, addrlen):
                proc, proc_obj = self.get_proc_name(cpu)
                s = self.find_sock(cpu, proc_obj, proc, fd, "accept", addr=addr, addrlen=addrlen)
                try:
                    alen = self.panda.virtual_memory_read(cpu, addrlen, self.addr_size, fmt='int')
                except:
                    print("COULD NOT READ ADDRLEN %x IN ACCEPT"%addrlen)
                    return
                sock_addr = s.read_sockaddr(cpu, addr, alen)
                with open("sock.txt", 'a') as f:
                    f.write(f"{proc}: ACCEPT(fd: 0x{fd:x}, addr: 0x{addr:x} | {sock_addr}, addrlen: 0x{addrlen:x}) RETURNS fd: 0x{fd_ret:x}\n")

            @self.panda.ppp("syscalls2", "on_sys_accept_return")
            def accept_record(cpu, pc, fd, addr, addrlen):
                fd_ret =  self.panda.arch.get_return_value(cpu)
                proc, proc_obj = self.get_proc_name(cpu)
                s = self.find_sock(cpu, proc_obj, proc, fd, "accept", addr=addr, addrlen=addrlen)
                if fd_ret not in s.assc_fds:
                    s.assc_fds.append(fd_ret)
                if fd not in s.assc_fds:
                    s.assc_fds.append(fd)
                try:
                    alen = self.panda.virtual_memory_read(cpu, addrlen, self.addr_size, fmt='int')
                except:
                    print("COULD NOT READ ADDRLEN %x IN ACCEPT RETURN"%addrlen)
                    return
                sock_addr = s.read_sockaddr(cpu, addr, alen)
                with open("sock.txt", 'a') as f:
                    f.write(f"{proc}: ACCEPT(fd: 0x{fd:x}, addr: 0x{addr:x} | {sock_addr}, addrlen: 0x{addrlen:x}) RETURNS fd: 0x{fd_ret:x}\n")

    def read_sock_struct(self, cpu, file_struct): 
        try:
            ksa = self.panda.virtual_memory_read(cpu, file_struct, self.addr_size, fmt='int')
            return ksa
        except Exception as e:
            print(f"Could not read kernel socket addr because: {e}")
            return None

    def get_proc_name(self, cpu):
        name = 'error' 
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc != self.panda.ffi.NULL:
            name = self.panda.ffi.string(proc.name).decode()
        return name.replace('/', '-slash-'), proc

    def get_prio(self, sock1, sock2):
        if sock1.absock_id > sock2.absock_id:
            return sock1, sock2
        elif sock2.absock_id > sock1.absock_id:
            return sock2, sock1
        else:
            print("ERROR: two sockets have same absock_id")
            self.panda.end_analysis()

    def decide_name(self, n1, n2):
        if n1 == None or n1 == '':
            return 1
        elif (n2 != None and n2 != '') and n1 != n2:
            return -1
        else:
            return 0

    def merge_lists(self, l1, l2):
        for ele in l2:
            if ele not in l1:
                l1.append(ele)
        return l1

    def merge_socks(self, sock1, sock2):
        s1, s2 = self.get_prio(sock1, sock2)

       
        phys_addrs = self.merge_lists(s1.phys_addrs, s2.phys_addrs)
        s1.phys_addrs = phys_addrs

        assc_fds = self.merge_lists(s1.assc_fds, s2.assc_fds)
        s1.assc_fds = assc_fds

        msgs = self.merge_lists(s1.msgs, s2.msgs)
        s1.msgs = msgs

        conns = self.merge_lists(s1.conns, s2.conns)
        s2.conns = conns

        name_choice = self.decide_name(s1.sock_addr_name, s2.sock_addr_name)
        if name_choice < 0:
            print("BADBADNAME ERROR")
            return
        elif name_choice:
            s1.sock_addr_len = s2.sock_addr_len
            s1.sock_addr_fam = s2.sock_addr_fam
            s1.sock_addr_name = s2.sock_addr_name
        
        domain_choice = self.decide_name(s1.idom, s2.idom)
        type_choice = self.decide_name(s1.itype, s2.itype)
        prot_choice = self.decide_name(s1.iprot, s2.iprot)

        if domain_choice < 0:
            print("BADBAD DOMAIN ERROR")
            return
        elif domain_choice:
            s1.idom = s2.idom
        if type_choice < 0:
            print("BADBAD TYPE ERROR")
            return
        elif type_choice:
            s1.itype = s2.itype
        if prot_choice < 0:
            print("BADBAD PROT ERROR")
            return
        elif prot_choice:
            s1.iprot = s2.iprot


        for sock in self.sockets:
            if sock.absock_id == s2.absock_id:
                self.sockets.remove(sock)
        return s1

    def check_phys_addr(self, proc, addr, sock):
        found = False
        for s in self.sockets:
            if addr in s.phys_addrs:
                found = True
                if proc not in s.conns:
                    s.conns.append(proc)
                if sock.sock_addr_name != None and s.sock_addr_name == None:
                    s.sock_addr_name = sock.sock_addr_name
                    s.sock_addr_len = sock.sock_addr_len
                    s.sock_addr_fam = sock.sock_addr_fam
                return s, found
        return sock, found
    
    def check_sock_addr(self, proc, sock):
        found = False
        for s in self.sockets:
            if s.sock_addr_name == sock.sock_addr_name and s.sock_addr_name != None:
                found = True
                if proc not in s.conns:
                    s.conns.append(proc)
                return s, found
        return sock, found

    def find_sock(self, cpu, proc_obj, proc, fd, fn, addr=None, addrlen=None, dom=None, ty=None, prot=None):
        fname_fd = fd
        fds = []

        
        if not isinstance(fd, int):
            fname_fd = fd[0]
            for ele in fd:
                fds.append(ele)
        else:
            fds = [fd]
        
        file_struct = self.panda.plugins['osi_linux'].ext_get_file_struct_ptr(cpu, proc_obj.taskd, fname_fd)
        phys_addr = self.panda.virt_to_phys(cpu, file_struct)

        try:
            fname_obj = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc_obj, fname_fd)
            if fname_obj != self.panda.ffi.NULL:
                fname = self.panda.ffi.string(fname_obj)
        except Exception as e:
            fname = '[err: %s]'%e
        
        found_sa = False
        
        sa = None
        sock = AbstractSocket(self.panda, self.as_count, proc, phys_addr, fd, fn, dom, ty, prot)
        self.as_count += 1
        
        if addr!=None:
            sa  = sock.read_sockaddr(cpu, addr, addrlen)
            s, found_sa = self.check_sock_addr(proc, sock)
        
        found_pa = False
        
        if found_sa:
            ret_sock = s
        
        s, found_pa = self.check_phys_addr(proc, phys_addr, sock)

        if found_pa and not found_sa:
            ret_sock = s
        if found_pa and found_sa:
            if s.absock_id != ret_sock.absock_id:
                ret_sock = self.merge_socks(s, ret_sock)
        elif not found_pa and not found_sa:
            ret_sock = sock
            self.sockets.append(sock)

        for ele in fds:
            if ele not in ret_sock.assc_fds:
                ret_sock.assc_fds.append(ele)
        return ret_sock

    #Two's compliment conversion for decoding errors
    def tc(self, v, b):
        b = b * 4
        if(v&(1<<(b-1)) != 0):
            v = v-(1<<b)
        return v
    @PyPlugin.ppp_export
    def get_sockets(self):
        return self.sockets
    
