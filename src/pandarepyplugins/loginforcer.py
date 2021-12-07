from pandare import PyPlugin
class LoginForcer(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def execve(cpu, pc, fname_ptr, argv_ptr, envp):  
            try:
                fname = self.panda.read_str(cpu, fname_ptr)
                argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 8, fmt='ptrlist')
            except ValueError:
                return

            if argv_buf[1] == 0:
                return # No args - just logging in, not as a user / not checking pass

            # Change /bin/login -- [user] to /bin/login -f [user]
            if fname == "/bin/login":
                panda.virtual_memory_write(cpu, argv_buf[1], b"-f")
