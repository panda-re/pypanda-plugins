from pandare import PyPlugin
from json import dumps

'''
Snaptracker v1 
'''


class SnapTracker(PyPlugin):
    def __init__(self, panda):
        # arguments to SnapTracker
        self.trace_kernel = self.get_arg('kernel_mode') or False
        self.trace_memory = self.get_arg('trace_mem') or True
        if self.trace_memory:
            panda.enable_memcb()
        self.hwid = self.get_arg('hwid')

        assert self.hwid, "HWID must be specified for SnapTracker"

        self.panda = panda
        self.cpu = panda.get_cpu()

        self.page_initialized = []
        self.try_initialize = set()
        self.fail_count = {}
        self.reg_events = []
        self.mem_between = {}
        self.mem_events = []
        self.regmap = [reg for reg in panda.arch.registers.keys()]
        self.regvals = {}
        self.tick = 0
        self.counter = 0
        self.has_hit = False

    def is_kernel_address(self,addr):
        # use panda.in_kernel_code_linux once PR #1176 merged
        arch = self.panda.arch_name
        if arch == "x86_64":
            return addr & 0x8000_0000_0000_0000 != 0
        else:
            return addr & 0x8000_0000 != 0
    
    def _check_asid(self):
        return self.get_id() == self.hwid

    def _check_environment(self):
        if not self.trace_kernel and self.is_kernel_address(self.panda.current_pc(self.cpu)):
            return False
        return self._check_asid() 

    @PyPlugin.ppp_export
    def snap(self, label=""):
        if self._check_environment():
            self._rec_event_internal(label)

    def _rec_event_internal(self, label):
        self._address_in_map(self.panda.current_sp(self.cpu))
        self._address_in_map(self.panda.current_pc(self.cpu))
        if not self.reg_events:
            self.vmaw = self.panda.cb_virt_mem_after_write(self.vmaw)

        # only update registers that change
        new_regmap = {}

        for reg in range(len(self.regmap)):
            val = self.panda.arch.get_reg(self.cpu, self.regmap[reg])
            if reg in self.regvals:
                if val != self.regvals[reg]:
                    new_regmap[reg] = val
            else:
                new_regmap[reg] = val
        from copy import deepcopy
        self.reg_events.append({"pc": self.panda.current_pc(self.cpu),
                            "reg": new_regmap, 
                            "mem_between": deepcopy(self.mem_between),
                            "label": label})
        self.mem_between.clear()
        self.regvals.update(new_regmap)

    def finish(self):
        # disable callbacks
        if self.vmaw:
            self.panda.unregister_callback(self.vmaw)

    def _get_maps(self):
        first = not hasattr(self, "mappings")

        self.mappings = [{"name": self.panda.ffi.string(m.name).decode(
        ), "base": m.base, "size": m.size} for m in self.panda.get_mappings(self.cpu) if m.name != self.panda.ffi.NULL]
        if first:
            for m in self.mappings:
                addr = m["base"] & ~0xfff
                while addr < m["base"] + m["size"]:
                    self._initialize_page(addr)
                    addr += 0x1000

    def _initialize_page(self, page):
        if page not in self.page_initialized:
            try:
                print(f"initializing page {page:#x}")
                pagemem = self.panda.virtual_memory_read(self.cpu, page, 0x1000 - 1)
                self.mem_between[page] = [i for i in pagemem]
                self.page_initialized.append(page)
                return True
            except Exception as e:
                self.try_initialize.add(page)
                print("initialize page failed")
                return False
        else:
            return True

    def _in_map(self, addr):
        page = addr & ~0xfff
        if not hasattr(self,"mappings"):
            self._get_maps()
        for m in self.mappings:
            if m["base"] <= addr <= m["base"] + m["size"]:
                self._initialize_page(page)
                return True
        self._get_maps()
        for m in self.mappings:
            if m["base"] <= addr <= m["base"] + m["size"]:
                self._initialize_page(page)
                return True
        return False

    def try_initialize_failed_pages(self):
        '''
        Once fault_hooks is added use that mechanism instead
        '''
        to_remove = []
        for page in self.try_initialize:
            if self._in_map(page):
                if not self._initialize_page(page):
                    fc = self.fail_count.get(page, 0) + 1
                    self.fail_count[page] = fc
                    if fc > 5:
                        to_remove.append(page)
                        self.fail_count[page] = 0
            else:
                to_remove.append(page)
        for page in to_remove:
            print(f"Failed to load page {page:#x}")
            self.try_initialize.discard(page)

    def _address_in_map(self, addr):
        self.try_initialize_failed_pages()
        if self.is_kernel_address(addr):
            return False
        return self._in_map(addr)

    def vmaw(self, cpu, pc, addr, size, buf):
        if not self.is_kernel_address(addr) and self._check_asid():
            self._address_in_map(addr)
            self._address_in_map(self.panda.current_pc(cpu))
            self._address_in_map(self.panda.current_sp(cpu))
            
            # buf does not adjust endianness properly
            buf_val = [i for i in self.panda.virtual_memory_read(cpu, addr, size)]
            for a in list(self.mem_between):
                if a + len(self.mem_between[a]) == addr:
                    self.mem_between[a].extend(buf_val)
                    return
            self.mem_between[addr] = buf_val

    @PyPlugin.ppp_export
    def toJSON(self):
        return dumps({"mapping": self.mappings, "regmap": self.regmap, "reg_events": self.reg_events})
