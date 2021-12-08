from pandare import PyPlugin

class ReadWriteReplace(PyPlugin):
    '''
    Replace strings as they are read/written from/to files.
    '''
    def __init__(self, panda):
        self.panda = panda
        self.replaces = {} # key => value
        self.proc_replaces = {} # procname => key => value
        self.enabled = False
        self.just_clobbered = None

        @panda.ppp("syscalls2", "on_sys_write_enter")
        def handle_write(cpu, pc, fd, buf, count):
            if not len(self.replaces) and not len(self.proc_replaces):
                return
            
            try:
                orig_s = panda.read_str(cpu, buf, count)
            except ValueError:
                return

            s = self.do_replace(cpu, orig_s)

            if s != orig_s:
                clobbered = None
                try:
                    clobbered = panda.virtual_memory_read(cpu, buf, len(s))
                except ValueError:
                    print(f"[ReadWriteReplace] Clobbering {len(s)-len(orig_s)} bytes and unable to cache")

                if panda.virtual_memory_write(cpu, buf, s.encode()):
                    print(f"[ReadWriteReplace] Failed to replace {orig_s} with {s}")
                    clobbered = None
                else:
                    panda.arch.set_arg(cpu, 3, len(s), convention='syscall')

                if clobbered:
                    self.just_clobbered = (buf, clobbered, count)

        @panda.ppp("syscalls2", "on_sys_write_return")
        def handle_write_ret(cpu, pc, fd, buf, count):
            if not self.just_clobbered:
                return

            addr, data, oldcount = self.just_clobbered
            if panda.virtual_memory_write(cpu, addr, data):
                print(f"[ReadWriteReplace] Failed to restore {data}")
            else:
                panda.arch.set_arg(cpu, 3, oldcount, convention='syscall')

            self.just_clobbered = None


        @panda.ppp("syscalls2", "on_sys_read_return")
        def read(cpu, pc, fd, buf, count):
            if not len(self.replaces) and not len(self.proc_replaces):
                return

            
            try:
                orig_s = panda.read_str(cpu, buf, count)
            except ValueError:
                return
            s = self.do_replace(cpu, orig_s, read=True)

            if s != orig_s:
                # Check if new buffer is still < count - is so we're good, otherwise clobber
                # anyway but warn
                if len(s) > count:
                    print(f"[ReadWriteReplace] replacement of {orig_s} is now bigger than count. May cause problems")
                if panda.virtual_memory_write(cpu, buf, s.encode()):
                    print(f"[ReadWriteReplace] Failed to change read result from {orig_s}")
                else:
                    panda.arch.set_arg(cpu, 3, len(s), convention='syscall')

    def do_replace(self, cpu, s, read=False):
        name = "read" if read else "write"

        if len(self.proc_replaces):
            proc = self.panda.plugins['osi'].get_current_process(cpu)
            name = "error"
            if proc != self.panda.ffi.NULL:
                name = self.panda.ffi.string(proc.name).decode(errors='ignore')

            if name in self.proc_replaces:
                for find, replace in self.proc_replaces[name].items():
                    if find in s:
                        match = True
                        s = s.replace(find, replace)

        if len(self.replaces):
            for find, replace in self.replaces.items():
                if find in s:
                    match = True
                    s = s.replace(find, replace)
        return s

    @PyPlugin.ppp_export
    def add(self, key, value):
        self.replaces[key] = value

    @PyPlugin.ppp_export
    def remove(self, key):
        del self.replaces[key]

    @PyPlugin.ppp_export
    def clear(self):
        self.replaces = {}

    @PyPlugin.ppp_export
    def add_proc(self, proc, key, value):
        if proc not in self.proc_replaces:
            self.proc_replaces[proc] = {}

        self.proc_replaces[proc][key] = value

    @PyPlugin.ppp_export
    def remove_proc(self, proc, key):
        del self.proc_replaces[proc][key]
        if len(self.proc_replaces[proc]) == 0:
            del self.proc_replaces[proc]

    @PyPlugin.ppp_export
    def clear_proc(self, proc):
        del self.proc_replaces[proc]

if __name__ == '__main__':
    from pandare import Panda
    panda = Panda(generic="arm")

    panda.pyplugins.load(ReadWriteReplace)
    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")

        panda.pyplugins.ppp.ReadWriteReplace.add("root:x", "BOOT:X")
        out = panda.run_serial_cmd("cat /etc/passwd")
        assert "BOOT:X" in out, f"Unexpected, no BOOT: in {out}"

        panda.pyplugins.ppp.ReadWriteReplace.clear()

        out = panda.run_serial_cmd("cat /etc/passwd")
        assert "root:x" in out, f"Unexpected- no root: in {out}"

        panda.pyplugins.ppp.ReadWriteReplace.add_proc("python", "root", "boot")

        out = panda.run_serial_cmd("cat /etc/passwd")
        assert "root:x" in out, f"Unexpected- no root in cat after python-specific change: in {out}"

        out = panda.run_serial_cmd("python -c 'print(\"root\")'")
        assert "boot" in out, f"Unexpected python should have printed boot, got {out}"

        panda.end_analysis()

    panda.run()
    print("all tests passed")
