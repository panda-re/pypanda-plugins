#!/usr/bin/env python3
'''
The NetRecv plugin provides a PPP-style callback `incoming_data` which is called whenever data is read from a socket.
The callback is run with arguments (CPUState cpu, string SocketType, guest_ptr_t buf_ptr, int buf_size)
'''

from pandare import PyPlugin

class NetRecv(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.ppp_cb_boilerplate('incoming_data')

        for sc in ['read', 'recv', 'recvfrom', 'recvmsg']:
            try:
                @panda.ppp("syscalls2", f"on_sys_{sc}_return", name="sc_"+sc)
                def sc_ret(cpu, pc, fd, buf_ptr, size, *_):
                    proc = panda.plugins['osi'].get_current_process(cpu)
                    name_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                    name = panda.ffi.string(name_ptr) if name_ptr != panda.ffi.NULL else b'err'
                    if not name.startswith(b'socket:'):
                        return
                    sock_type = name.split(b"socket:")[1].decode()
                    self.ppp_run_cb('incoming_data', cpu, sock_type, buf_ptr, size)
            except panda.ffi.error:
                # Expected - e.g., x86 doesn't have recv
                print(f"No syscall {sc} for this arch")


if __name__ == '__main__':
    '''
    Example useage of NetRecv plugin + callback
    '''
    from pandare import Panda
    panda = Panda(generic='x86_64')

    def on_incoming_data(cpu, sock_type, buf_ptr, size):
        print(f"Socket of {sock_type} with data at {buf_ptr:#x}")
        try:
            data = panda.virtual_memory_read(cpu, buf_ptr, size, fmt='str')
        except ValueError:
            data = None
        print("\tData:", data)

    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        panda.pyplugins.load(NetRecv)
        panda.pyplugins.ppp.NetRecv.ppp_reg_cb('incoming_data', on_incoming_data)
        print("Guest output:", repr(panda.run_serial_cmd('python3 -m http.server 8000 & sleep 15s; curl http://localhost:8000')))
        panda.end_analysis()

    panda.run()
