PyPANDA Plugins
====

Standalone Python plugins for [PANDA](https://github.com/panda-re/panda)'s Python Interface.

They are separated into two directories:

* plugins - snake_hook-compaible pypanda plugins
* scripts - libraries and scripts designed for use with standalone pypanda scripts

## Plugins

### Basic Block Count (bb_count.py)

A plugin that provides a live-updating basic block count.

Webpage url: https://localhost:8080/BasicBlockCount

### Live Process Graph (proc_graph.py)

A plugin that provides a live-updating process graph.

Webpage url: https://localhost:8080/LiveProcGraph

![Process Graph](https://raw.githubusercontent.com/lacraig2/panda_webserver_process_graph/master/images/example.png)

## Scripts

### FileHook
When the guest attempts to access a file, silently redirect the access to another file.

```py
hook = FileHook(panda)
hook.rename_file("/does_not_exist", "/etc/issue")
```

### FileFaker
** Currently broken **
When the guest attempts to read from a file which may or may not exist, provide fake contents.
```py
fake = FileFaker(panda)
faker.replace_file("/does_not_exist", FakeFile("Hello World")
```

### IoctlFaker
When the guest issues an IOCTL that returns `-ENOTTY` (i.e., no driver has registered this IOCTL), silence the error.

```py
iofaker = IoctlFaker(panda)
panda.run()

print(iofaker.get_forced_returns())
```

### ModeFilter
Class of decorators to simplify state machines in PyPANDA scripts.

### ProcWriteCapture
Whenever a guest process writes data, record it to the host disk.

```py
ProcWriteCapture(panda)
panda.run()
# Local files will be created when guest programs write output
```

Status
====
These plugins are unversioned.
