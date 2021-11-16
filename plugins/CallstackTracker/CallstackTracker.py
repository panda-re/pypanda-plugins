from pandare import PyPlugin
from call_stack_info import CallstackInfo

class CallstackTracker(PyPlugin):

    def __init__(self, panda):
        self.panda = panda
        self.skip_libs = self.get_arg('skip_libs')
        if self.skip_libs == None:
            self.skip_libs = []
        self.logging = self.get_arg('log_calls')
        if self.logging == None:
            self.logging = False
        self.show_stack_addr = self.get_arg('show_stack_addr')
        self.procs = []

        if not "syscalls2" in panda.plugins:
            print("Syscalls2 not yet loaded, loading now")
            panda.load_plugin("syscalls2", args = {"load-info":True})

        @panda.ppp("callstack_instr", "on_call")
        def on_call(cpu, func):
            current = self.get_proc_name(cpu)
            proc = self.check_proc(current)
            proc.handle_call(cpu, func)

        @panda.ppp("callstack_instr", "on_ret")
        def on_ret(cpu, func):
            current = self.get_proc_name(cpu)
            proc = self.check_proc(current)
            proc.handle_ret(func)

        if self.show_stack_addr != None:
            @panda.hook(show_stack_addr, kernel = True)
            def show_stack_print(cpu, tb, h):
                current = self.get_proc_name(cpu)
                proc = self.check_proc(current)
                print(f"!!!!!!!! CRASH: SHOWING CALLSTACK FOR {proc.name}")
                proc.print_calls()


    def get_proc_name(self, cpu):
        name = 'error' 
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc != self.panda.ffi.NULL:
            name = self.panda.ffi.string(proc.name).decode()
        return name.replace('/', '-slash-')
    
    def check_proc(self, current):
        found = False
        for proc in self.procs:
            if proc.name == current:
                found = True
                ret = proc
        if not found:
            ret = CallstackInfo(self.panda, current, skip_libraries=self.skip_libs, logging=self.logging)
            self.procs.append(ret)

        return ret
