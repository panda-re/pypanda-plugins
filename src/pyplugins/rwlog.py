from pandare import PyPlugin

class ReadWriteLog(PyPlugin):
    def __init__(self, panda):
        self.writelog = self.get_arg("writelog") # may be None
        self.readlog = self.get_arg("readlog") # may be None

        for logfile in [self.writelog, self.readlog]:
            if logfile is not None:
                # Clear / create log
                open(logfile, "w").close()

        @panda.ppp("syscalls2", "on_sys_write_enter")
        def write(cpu, pc, fd, buf, count):
            try:
                s = panda.read_str(cpu, buf, count)
            except ValueError:
                s = "error"

            proc = panda.plugins['osi'].get_current_process(cpu)
            if proc != panda.ffi.NULL:
                name = panda.ffi.string(proc.name)
                fd = panda.from_unsigned_guest(fd)
                msg = f"{name} writes to fd {fd}: {repr(s)}\n"

                if self.writelog:
                    with open(self.writelog, "a") as f:
                        f.write(msg)
                else:
                    print(f"[ReadWriteLog] {msg}")

        @panda.ppp("syscalls2", "on_sys_read_return")
        def read(cpu, pc, fd, buf, count):
            try:
                s = panda.read_str(cpu, buf, count)
            except ValueError:
                s = "error"

            proc = panda.plugins['osi'].get_current_process(cpu)
            name = "error"
            fname = "error"
            if proc != panda.ffi.NULL:
                name = panda.ffi.string(proc.name).decode()
                fname_obj = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                if fname_obj != panda.ffi.NULL:
                    fname = panda.ffi.string(fname_obj)

            fd = panda.from_unsigned_guest(fd)
            msg = f"{name} reads {fname}: {repr(s)}\n"
            if self.readlog:
                with open(self.readlog, "a") as f:
                    f.write(msg)
            else:
                print(f"[ReadWriteLog] {msg}")

            # When login reads /etc/passwd we want to replace /bin/false with /bin/bash
            if name == "login" and ":/bin/false" in s:
                new_s = s.replace(":/bin/false", "/bin/sh")
                panda.virtual_memory_write(cpu, buf, new_s.encode())

