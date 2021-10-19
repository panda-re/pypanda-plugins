#!/usr/bin/env python3

# Example script to use proc_graph from a pypanda script
from pandare import Panda
panda = Panda(generic="x86_64")

panda.pyplugin.enable_flask(host='0.0.0.0')
LiveProcGraph = panda.pyplugin.load_plugin_class("proc_graph.py", 'LiveProcGraph')
panda.pyplugin.register(LiveProcGraph)
# Alternatively, just register the (path, classname) directly
#panda.pyplugin.register(("proc_graph.py", 'LiveProcGraph'))
panda.pyplugin.serve()

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    assert(panda.run_serial_cmd("apt-get update -yy > /dev/null; sleep 10"))
    panda.end_analysis()

panda.run()
