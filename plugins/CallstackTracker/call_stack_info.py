class CallstackInfo:
    calls = []
    depth = -1
    skip_count = 0
    after_skip = 0
    freeze = -1
    freeze_name = ''

    def __init__(self, panda, proc_name, skip_libraries = [], skip_kernel=True, logging=False, track=10):
        self.panda = panda
        self.addr_size = int(self.panda.bits / 8)
        self.cutoff = 0xc << self.panda.bits
        self.name = proc_name
        self.skip_libs = skip_libraries
        self.skip_kern = skip_kernel
        self.log = logging
        if self.log:
            open(self.name + '.calls', 'w').close()
        self.max = track

    def skip(self, name):
        self.skip_count += 1
        if self.freeze == -1:
            self.freeze = self.depth
            self.freeze_name = name

    def handle_call(self, cpu, addr):
        self.depth += 1
        if self.skip_kern and addr >= self.cutoff:
            self.skip('kernel')
            return
        
        owner, base, offset, skip = self.handle_mappings(cpu, addr)

        if skip:
            return
        
        args = []
        for i in range(0, 4):
            args.append(self.panda.arch.get_arg(cpu, i))

        pre, skip, line = self.build_line(addr, owner, offset, args)
        if self.log:
            with open(self.name+'.calls', 'a') as f:
                f.write(skip)
                f.write(pre + line)
        if len(self.calls) < self.max:
            self.calls.append((line, self.depth))
        else:
            self.calls = self.calls[1:]
            self.calls.append((line, self.depth))

    def handle_ret(self, addr):
        if self.depth < 0:
            #print(f"Error in {self.name}, hit ret before call")
            return
        elif self.depth == 0:
            #print(f"Returning out of {self.name}")
            return
        elif self.depth > 0:
            self.depth-=1
            if self.depth == self.freeze:
                self.freeze = -1
                self.after_skip = 1


    def handle_mappings(self, cpu, addr):
        mappings = self.panda.get_mappings(cpu)
        owner = 'ERROR'
        off = 0xdead
        base = 0xbadbad
        for mapping in mappings:
            if addr in range(mapping.base, mapping.base+mapping.size):
                try:
                    owner = self.panda.ffi.string(mapping.name).decode()
                except:
                    owner = "UNK_LIBRARY_0x%"%mapping.base
                base = mapping.base
        if owner in self.skip_libs:
            self.skip(owner)
            return owner, base, off, True
        
        for mapping in mappings:
            try:
                n = self.panda.ffi.string(mapping.name).decode()
            except:
                pass
            if n == owner:
                if mapping.base < base:
                    base = mapping.base
        
        off = addr - base
        return owner, base, off, False

    def build_line(self, addr, owner, off, args):
        #prefix = '-'*self.depth + '>'
        prefix = f"depth: {self.depth} | "
        fin_args = '('
        fin_str = '['
        for arg in args:
            try:
                argstr = self.panda.ffi.read_str(cpu, arg).decode()
            except:
                argstr = 'N/A'
            if fin_args == '(':
                fin_args = fin_args + f'0x{arg:x}'
                fin_str = fin_str + argstr
            else:
                fin_args = fin_args + ', ' + f'0x{arg:x}'
                fin_str = fin_str + ', ' + argstr
        fin_args = fin_args + ')'
        fin_str = fin_str + ']'

        p_args = fin_args + ' ' + fin_str
        if self.after_skip:
            skip = '-' + prefix + f'skipped {self.freeze_name} ({self.skip_count})\n'
            self.after_skip = 0
        else:
            skip = ''

        line = f"0x{addr:x}" + p_args + f" | {owner} at offset 0x{off:x}\n"

        return prefix, skip, line

    def print_calls(self):
        min_d = 0xffffffff
        for _, depth in self.calls:
            if min_d > depth:
                min_d = depth
        for call, depth in self.calls:
            depth -= min_d
            print("-"*depth + f">{call}")

