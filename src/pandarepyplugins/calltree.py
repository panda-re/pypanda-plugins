from pandare import PyPlugin

class CallTree(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outfile = self.get_arg("outfile") # may be None

        if self.outfile:
            # Clear / create the file
            open(self.outfile, "w").close()

        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):  
            # Log commands and arguments passed to execve
            try:
                fname = self.panda.read_str(cpu, fname_ptr)
                argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
            except ValueError: return
            argv = []
            for ptr in argv_buf:
                if ptr == 0: break
                try: argv.append(panda.read_str(cpu, ptr))
                except ValueError: argv.append("(error)")

            result = self.get_calltree(cpu) + " => " + ' '.join(argv)
            if self.outfile:
                with open(self.outfile, "a") as f:
                    f.write(result+"\n")
            else:
                print(result)

    def get_calltree(self, cpu):
        # Print the calltree to the current process
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL:
            print("[CallTree] Error determining current process")
            return
        procs = self.panda.get_processes_dict(cpu)
        chain = [{'name': self.panda.ffi.string(proc.name).decode('utf8', 'ignore'),
                  'pid': proc.pid, 'parent_pid': proc.ppid}]
        while chain[-1]['pid'] > 1 and chain[-1]['parent_pid'] in procs.keys():
            chain.append(procs[chain[-1]['parent_pid']])
        return " -> ".join(f"{item['name']} ({item['pid']})" for item in chain[::-1])
