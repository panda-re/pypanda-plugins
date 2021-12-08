#!/usr/bin/env python3

"""
Protype file faking capability.

When the guest issues a syscall to get a file descriptor related to a file name
we wish to hallucinate, we interpose and ensure a valid file descriptor is created.

When the guest issues a syscall using a file descriptor from such a situation, we
interpose and return customizable results.

The FileFaker class manages this whole process by tracking which filenames should be faked and with what fakers
The FakeDiskState class represents the state of a hallucinated file as it would be if it were stored on disk
The FakeFile class handles syscalls issued on a FD based on a hallucinated file


Could be expanded to support more syscalls in FakeFile class and to support the following special fd arg names:
    long sys_splice(int fd_in ...)
    long sys_tee(int fdin, int fdout, ...)
    long sys_copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, ...)
"""

import logging
import sys
from math import ceil
from os import path

from pandare import PyPlugin

def on_this_syscall_ret(panda, cpu, sys_name, error=True):
    def decorator(func):
        # tid,pid,syscall should be unique
        pid = panda.plugins['osi'].get_current_process(cpu).pid
        tid = panda.plugins['osi'].get_current_thread(cpu).tid
        asid_name = str((sys_name, tid, pid))

        # Debugging - we shouldn't ever have duplicates for this *same thread*
        if asid_name in panda.ppp_registered_cbs:
            if error:
                raise RuntimeError("Duplicate on_ret cb for ", asid_name)
            else:
                return

        @panda.ppp("syscalls2", f"on_sys_{sys_name}_return", name=asid_name)
        def on_ret(cpu, pc, *args):
            pid = panda.plugins['osi'].get_current_process(cpu).pid
            tid = panda.plugins['osi'].get_current_thread(cpu).tid
            inner_name = str((sys_name, tid, pid))

            if inner_name != asid_name: # Not always true for long-blocked things
                return

            try:
                func(cpu, pc, *args)
            except MemoryError:
                # Going to rerun, don't disable
                return

            # No value error - diable callback
            panda.disable_ppp(asid_name)

    return decorator

class FakeDiskState:
    '''
    A simple class to represent the state of a file on disk that we're hallucinating.
    These 'disk-like' files can only be read and written as offsets are tracked by the FD not the disk

    Two or more (distinct) FakeFile classes may have concurrent handles to the same instance of this class.
    If one writes to the file, it should be reflected in the other immeidately
    '''
    def __init__(self, data=b''):
        assert(isinstance(data, bytes))
        self.data = data

    def __repr__(self):
        return self.data.decode()

    def read(self, offset, count):
        read_len = min(count, len(self.data)-offset)
        return self.data[offset:read_len] # XXX: off by 1?

    def write(self, offset, newdata):
        start = self.data[:offset]
        end = self.data[offset+len(newdata):] if len(self.data) < offset+len(newdata) else b''
        self.data = start + newdata + end

class FakeFile:
    '''
    Example class for handling syscalls issued on file descriptors that were generate by syscalls
    that reference a faked file. Implementation will handle read and write syscalls.

    Class will be initialized with args 3+ passed to FileFaker.hallucinate_file: e.g.,
        halcuinate_file("/foo", FakeFile, some_args)  => FakeFile.__init__(some_args)
        halcuinate_file("/foo", FakeFile, arg1, arg2) => FakeFile.__init__(arg1, arg2)

    This class can be subclassed or reimplemented and have its methods overloaded to customize or extend behavior.

    Multiple (asid, fd) tuples should point to a single instance of this class if they are based on dup'd file
    descriptors. Python's garbage collection will free the instance when there are no remaning references to it.

    If this class (or subclass) defines function named handle_[syscall]_enter and handle_[syscall], they'll be called
    by FileFaker.enter_file_descriptor when a FD based off a faked file is passed to those syscalls. The handle
    function will be called with arguments (self, panda, cpu, pc, *syscall_args)
    '''

    def __init__(self, faked_name, fake_file=None, silence_unhandled_errors=True):
        self.fake_file = fake_file
        self.offset = 0
        self.logger = logging.getLogger(f"FakeFD for {faked_name}")
        self.silence_unhandled_errors=silence_unhandled_errors

    def handle_read(self, panda, cpu, pc, fd, buf, count):
        data = self.fake_file.read(self.offset, count)

        if len(data):
            err = panda.virtual_memory_write(cpu, buf, data)
            assert(not err)

        panda.arch.set_retval(cpu, len(data), convention='syscall')
        self.offset += len(data)

    def handle_write(self, panda, cpu, pc, fd, buf, count):
        try:
            write_data = panda.virtual_memory_read(cpu, buf, count)
        except ValueError:
            self.logger.error("Failed to read buffer being written to faked {self.fname} - cannot record")
            # Set retval to 0 indicating no bytes were written - application should then retry the write
            panda.arch.set_retval(cpu, 0, convention='syscall', failure=False)
            return

        self.fake_file.write(self.offset, write_data)

class FileFaker(PyPlugin):
    '''
    A class to halcuinate files

    When FileFaker.replace_file() is called, the FileFaker records a filename to fake, along
    with FakeFile-based class which will be used to manage FD-related syscalls.

    usage:
        panda = Panda(...)
        from pandarepyplugins.FileHallucinator import FileFaker, FakeDiskState, FakeFile

        panda.pyplugins.load(FileFaker)
        my_file = FakeDiskState(b"Hello world")
        panda.pyplugins.ppp.FileFaker.halcuinate_file("/rename_this", FakeFile, my_file)

        # Later contents can be changed:
        panda.pyplugins.ppp.FileFaker.halcuinate_file("/rename_this", FakeFile, my_file)
        panda.pyplugins.ppp.FileFaker.update_file("/rename_this", FakeDiskState(b"New contents"))
    '''

    def __init__(self, panda):
        self.panda = panda
        self.replaced_files = {} # fname: (FakeFD class, FakeFD kwargs)

        backer = self.get_arg('backer')
        if backer is None:
            self.backer = b'/etc/passwd'
        else:
            self.backer = backer if isinstance(backer, bytes) else backer.encode()

        self.active_hooks = {} # asid: fd: (name, FakeFD instance instance)
        self.logger = logging.getLogger("FilenameFaker")

        panda.load_plugin("syscalls2", {"load-info": True}) # Must be set by caller if syscalls was previously loaded
        self.register_callbacks(panda)

    @PyPlugin.ppp_export
    def hallucinate_file(self, path_or_name, faker, *faker_kwargs):
        if not hasattr(faker, '__dict__'): # Build in property for user-defined classes
            raise ValueError(f"File replacing requires a class to use for faking: got {faker}")

        if path_or_name in self.replaced_files:
            raise ValueError(f"Already faking {path_or_name} with {self.replaced_files[path_or_name]}")
        self.replaced_files[path_or_name] = (faker, faker_kwargs)

    @PyPlugin.ppp_export
    def update_file(self, path_or_name, *faker_kwargs):
        '''
        Update the faker class for a previously registered path.

        Note this will only affect *SUBSEQUENT* accesses to the faked file
        '''
        if path_or_name not in self.replaced_files:
            raise ValueError(f"{path_or_name} was not set to be hallucinated")

        faker, _ = self.replaced_files[path_or_name]
        self.replaced_files[path_or_name] = (faker, faker_kwargs)


    def register_callbacks(self, panda):
        # Use on_all_sys_enter2 to get a callback on every syscall with details of args + names
        # dynamically decide if we're going to hook one

        @panda.ppp("syscalls2", "on_all_sys_enter2")
        def syscall_enter(cpu, pc, call, rp):
            '''
            typedef struct {
               int no;
                const char *name;
                int nargs;
                syscall_argtype_t *argt;
                uint8_t *argsz;
                const char* const *argn;
                const char* const *argtn;
                bool noreturn;
            } syscall_info_t;
            '''
            if call == panda.ffi.NULL:
                return

            #for arg_idx in range(call.nargs):
            for arg_idx in range(min(call.nargs, 4)): # For now skip stack based args since they're unhandled by panda for mips/arm
                # Is it a string arg named fd or filename?
                if panda.ffi.string(call.argn[arg_idx]) in [b'fd', b'oldfd']:
                    name = panda.ffi.string(call.name).decode().replace("sys_", "")
                    # Could use rp struct instead of get_arg, but casts are hard in python
                    arg_val = panda.arch.get_arg(cpu, arg_idx+1, convention='syscall') # XXX: +1 because idx 0 is syscall number
                    self.enter_file_descriptor(panda, cpu, arg_idx, arg_val, name)

                elif panda.ffi.string(call.argn[arg_idx]) == b'filename':
                    name = panda.ffi.string(call.name).decode().replace("sys_", "")
                    # Could use rp struct instead of get_arg, but casts are hard in python
                    arg_val = panda.arch.get_arg(cpu, arg_idx+1, convention='syscall') # XXX: +1 because idx 0 is syscall number
                    self.enter_file_name(panda, cpu, arg_idx, arg_val, name)

    def enter_file_name(self, panda, cpu, arg_idx, name_ptr, sc_name):
        '''
        Entering a syscall with fname arg. Determine if it's using a faked file name. If so, swap it out for our backer
        and clean up guest state when the syscall returns.

        If the syscall doesn't return an FD (e.g., fstat), construct a temp instance of the relevant Faker class
        and see if that can handle it
        '''

        returns_fd = "open" in sc_name

        # If filename is null, we won't care about it (see e.g., utimensat)
        if name_ptr == 0:
            return

        try:
            this_fname = panda.read_str(cpu, name_ptr)
        except ValueError:
            self.logger.debug("Failed to read filename when entering syscall %s arg %d addr 0x%x", sc_name, arg_idx, name_ptr)

            @on_this_syscall_ret(panda, cpu, sc_name)
            def missed_fname_fn_ret(cpu, pc, *inner_args):
                try:
                    this_fname = panda.read_str(cpu, name_ptr)
                    self.logger.debug("Filename was %s", this_fname)
                except ValueError:
                    # We could modify this on enter to write the name_ptr to stdout which would page it in, but then
                    # we wouldn't have an FD if it was hooked. Assume this happens for unhooked files more often
                    # than hooked ones so just failing in this case is better (then the unhooked file acceses are ok)
                    self.logger.warning("Failed to read name (arg %d)  in return of %s (addr 0x%x)", arg_idx, sc_name, name_ptr)
                    return

                if this_fname not in self.replaced_files:
                    self.logger.debug("Got lucky - missed filename but it turns out to be %s so we don't care", this_fname)
                    return

                # We *messed up* the guest managed to issue the syscall on the faked file - potentially
                # unacceptable!
                raise RuntimeError("Guest snuck a syscall past us by keeping filename paged out. How rude!")

                # If it was an open, it may have failed to get an FD or it may later try modifying our backer file

                # If it wasn't an open, it may have returned an error or it may be getting info on our backer file

                #If there's an error code, try to get the caller to re-issue the syscall.
                # Send ENOMEM and pray that the guest will retry. In practice, this seems to work out
                # on mips which is the only time the filename is frequently paged out enough to test (about 5% of the time)
                ENOMEM = self.panda.to_unsigned_guest(-12) # ENOMEM
                self.panda.arch.set_retval(cpu, ENOMEM, convention='syscall', failure=True)
                self.logger.warning(f"Failed to read {sc_name} of {this_fname}. Identified it late- trying to force a retry")

            return

        if this_fname not in self.replaced_files: # TODO: resolve directories etc: track DFDs per asid and combine for full names
            return

        if sc_name.startswith('execve'):
            # In an execve, the kernel reads the file so there's no chance for us to fake the actual contents
            self.logger.error(f"Guest {sc_name}'d faked {this_fname}. This won't work, it will run {self.backer}")
            return

        try:
            old_data = panda.virtual_memory_read(cpu, name_ptr, len(self.backer)+1)
        except ValueError:
            self.logger.warning("%s: failed to read old data when trying to clobber %d bytes in fname pointer 0x%x",
                                sc_name, len(self.backer), name_ptr)
            return

        err = panda.virtual_memory_write(cpu, name_ptr, self.backer+b"\x00")
        if err:
            self.logger.warning("%s: failed to write backer to fname pointer 0x%x", sc_name, name_ptr)
            return

        # Special cases - if we're in an open or an openat zero the flags (user might have RO access to backer)
        flag_idx, orig_flag_val = None, None

        handled_flags = {'open': 2, 'openat': 3} # sys name, 1-indexed flags position

        if sc_name in handled_flags:
            flag_idx = handled_flags[sc_name]
            try:
                orig_flag_val = panda.arch.get_arg(cpu, flag_idx, convention='syscall')
            except ValueError:
                self.logger.warning(f"Failed to record old flags in {sc_name} - zeroing anyway")
            panda.arch.set_arg(cpu, flag_idx, 0, convention='syscall')

        self.logger.info("Hooked filename %s passed to %s", this_fname, sc_name)

        if returns_fd:
            @on_this_syscall_ret(panda, cpu, sc_name)
            def fn_ret_fd(cpu, pc, *inner_args):
                rv = self.panda.from_unsigned_guest(self.panda.arch.get_retval(cpu, convention='syscall'))
                if rv < 0:
                    self.logger.error("Faked filename in %s but return value was %d", sc_name, rv)

                # Restore old input data
                if panda.virtual_memory_write(cpu, name_ptr, old_data):
                    self.logger.warning("%s: failed to restore old data after clobbering %d bytes in fname pointer 0x%x",
                            sc_name, len(self.backer), name_ptr)

                # Restore old flag data (if applicable)
                if orig_flag_val is not None and flag_idx is not None:
                    try:
                        panda.arch.set_arg(cpu, flag_idx, orig_flag_val, convention='syscall')
                    except ValueError:
                        self.logger.warning("%s failed to restore old flags after zeroing 0x%x", sc_name, orig_flag_val)

                # Success - Store (asid, fd) so we know to fake it for FD references
                asid = panda.current_asid(cpu)
                if asid not in self.active_hooks:
                    self.active_hooks[asid] = {} # fd: (faked_name, reference to faker)

                # Generate a new FdFaker backed by the provided FileFaker

                # Initalize an object of the provided faker class
                faker_class, faker_kwargs = self.replaced_files[this_fname]
                self.logger.debug("Initialize a faker using %s", type(faker_class).__name__)
                faker = faker_class(this_fname, *faker_kwargs) # Create an instance of FakeFD
                self.active_hooks[asid][rv] = (this_fname, faker)
        else:
            @on_this_syscall_ret(panda, cpu, sc_name)
            def fn_ret_nofd(cpu, pc, *inner_args):
                # Doesn't return an FD - e.g., stat. Let's see if the faker class can help us out
                rv = self.panda.from_unsigned_guest(self.panda.arch.get_retval(cpu, convention='syscall'))
                faker_class, faker_kwargs = self.replaced_files[this_fname]
                tmp_faker = faker_class(this_fname, *faker_kwargs)

                # Restore old input data, even if it doesn't return an FD - e.g., stat(fname)
                if panda.virtual_memory_write(cpu, name_ptr, old_data):
                    self.logger.warning("%s: failed to restore old data after clobbering %d bytes in fname pointer 0x%x",
                            sc_name, len(self.backer), name_ptr)

                if hasattr(tmp_faker, f"handle_{sc_name}"):
                    # We know how to handle this syscall!
                    self.logger.info(f"Using {type(tmp_faker).__name__} to handle return of {sc_name} called on {this_fname}")
                    getattr(tmp_faker, f"handle_{sc_name}")(panda, cpu, pc, *inner_args)
                elif rv < 0 and hasattr(tmp_faker, 'silence_unhandled_errors') and tmp_faker.silence_unhandled_errors:
                    # Unhandled and it's returning an error - zero depending on silence_unhandled_errors
                    self.logger.info(f"{sc_name} on {this_fname} wants to return {rv}. Zeroing error")
                    self.panda.arch.set_retval(cpu, 0, convention='syscall', failure=False)

    def enter_file_descriptor(self, panda, cpu, arg_idx, this_fd, sc_name):
        '''
        Entering a syscall with FD arg. Determine if it's using a faked FD (per asid). If so, co-opt the syscall/return
        '''
        asid = panda.current_asid(cpu)

        if asid not in self.active_hooks or not len(self.active_hooks[asid]):
            # No hooks for this asid
            return

        if this_fd not in self.active_hooks[asid]:
            # This FD not hooked
            return

        # We're in a hooked FD - we can either
        #   A) modify it now to do nothing (e.g., getpid), then place fake data in buffer on return, or
        #   B) do nothing now and just setup the data on return.

        # Let's generally go with option B because it's more likely to result in the args we care about getting paged in
        # but give faker a chance to change this with an _enter function. Note enter doesn't get args in the same way as return
        self.logger.debug("Hooked (asid,fd) (0x%x, %d) passed to %s", asid, this_fd, sc_name)

        # If the faker has an _enter method, we'll call that
        realname, faker = self.active_hooks[asid][this_fd]
        if hasattr(faker, f"handle_{sc_name}_enter"):
            pc = panda.current_pc(cpu)
            self.logger.info(f"Using {type(faker).__name__} to handle enter of {sc_name} called on fd {this_fd} based off of {realname}")
            getattr(faker, f"handle_{sc_name}_enter")(panda, cpu, pc)

        @on_this_syscall_ret(panda, cpu, sc_name)
        def fd_ret(cpu, pc, *inner_args):
            realname, faker = self.active_hooks[asid][this_fd]

            # Call faker function if it exists
            if hasattr(faker, f"handle_{sc_name}"):
                self.logger.info(f"Using {type(faker).__name__} to handle return of {sc_name} called on fd {this_fd} based off of {realname}")
                getattr(faker, f"handle_{sc_name}")(panda, cpu, pc, *inner_args)

            rv = self.panda.from_unsigned_guest(self.panda.arch.get_retval(cpu, convention='syscall'))

            # Special cases for hook management. Allow faker a chance to handle these if it wants, but we're always going to run
            # these to ensure our active_hooks dict is up to date
            if sc_name == 'close':
                # Remove this FD from our list of hooked FDs for this asid. No cleanup is necessary in the FakeFile
                if rv == 0:
                    del self.active_hooks[asid][this_fd]
                else:
                    self.logger.info(f"Guest failed to close a hooked FD {rv}")
                return
            elif sc_name in ['dup', 'dup2', 'dup3']:
                # All return newfd
                if rv >= 0:
                    self.logger.info("Dup (%x, %d) => (%x, %d)", asid, this_fd, asid, rv)
                    self.active_hooks[asid][rv] = self.active_hooks[asid][this_fd]
                return

            # If there's no handler and it's not a special case, warn and fix error depending on
            if not hasattr(faker, f"handle_{sc_name}"):
                if rv < 0:
                    if hasattr(faker, 'silence_unhandled_errors') and faker.silence_unhandled_errors:
                        # Just handle one special case: write syscall shouldn't return 0 but instad # bytes 'written'.
                        # Maybe this shouldn't even be here.
                        if sc_name == 'write':
                            new_r = inner_args[2] # tell it that it wrote count bytes successfully
                            self.logger.info(f"{sc_name} on faked {realname} wants to return {rv}. Insead ret {new_r}")
                            self.panda.arch.set_retval(cpu, new_r, convention='syscall', failure=False)
                        else:
                            new_r = 0
                            self.logger.info(f"{sc_name} on faked {realname} wants to return {rv}. Zeroing error")
                        self.panda.arch.set_retval(cpu, new_r, convention='syscall', failure=False)

                    else:
                        self.logger.warning(f"Unhandled syscall {sc_name} returning error {rv} (faking disabled)")
                else:
                    self.logger.debug(f"Unhandled syscall {sc_name} returning {rv}. Leaving unchanged")


if __name__ == '__main__':
    from sys import argv
    from pandare import Panda

    if len(argv) > 1:
        arch = argv[1]
        if arch not in ["x86_64", "arm", "mips"]:
            raise ValueError("Unknown arch")
    else:
        arch = "x86_64"

    panda = Panda(generic=arch)

    # Create a FileFaker instance which will make the guest
    # hallucinate two files for us
    panda.pyplugins.load(FileFaker)

    # File #1) Normal example
    # First initialize a fake file
    initial_contents = b"Hello world. This is data generated from python!"
    my_fake_file = FakeDiskState(initial_contents)

    # Then tell the FileFaker to make the guest halcuinate my_fake_file when it reads /foo
    panda.pyplugins.ppp.FileFaker.hallucinate_file("/foo", FakeFile, my_fake_file)
    # / Normal example

    # File #2) Just an IOCTL handler
    globals()['ioctl_faker_ran'] = None
    class SimpleIoctlFaker():
        def __init__(self, filename):
            self.filename = filename

        def handle_ioctl(self, panda, cpu, pc, fd, request, vargs):
            if panda.arch.get_retval(cpu, convention="syscall") == -25:
                print(f"Fake an ioctl for {self.filename}")
                panda.arch.set_retval(cpu, 0, failure=False)
                global ioctl_faker_ran # Just for testing
                ioctl_faker_ran = self.filename

    # Tell the FileFaker to use our class to manage the hallucinations of /dev/missing
    panda.pyplugins.ppp.FileFaker.hallucinate_file("/dev/missing", SimpleIoctlFaker)
    # / IOCTL example

    new_data = "This is some new data"
    @panda.queue_blocking
    def driver():
        panda.revert_sync('root')
        data = panda.run_serial_cmd("cat /foo") # note run_serial_cmd must end with a blank line and our fake file doesn't
        if initial_contents.decode() != data:
            raise RuntimeError(f"Failed to read fake file /foo: {data}")

        panda.run_serial_cmd(f'echo -n {new_data} | tee /foo; echo') # -n to avoid adding a trailing \n
        foo_data = panda.run_serial_cmd("cat /foo")

        if new_data != foo_data:
            raise RuntimeError(f"Failed to update fake file /foo: Got {foo_data}. Expected: {new_data}")

        print(panda.run_serial_cmd("""perl -e 'require "sys/ioctl.ph"; open(FH, "<", "/dev/missing") or die $!; ioctl(FH, 0, 1); close(FH);'"""))

        panda.end_analysis()

    panda.run()

    print("At end, fook_file contains:", repr(my_fake_file))
    assert(new_data == my_fake_file.data.decode()), "Fake file does not contain expected data"
    global ioctl_faker_ran
    assert(ioctl_faker_ran == "/dev/missing"), "Ioctl faker didn't run"
