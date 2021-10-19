#!/usr/bin/env python3

# Example script to use proc_graph from a pypanda script
from pandare import Panda
from pandare.extras import Snake, PandaPlugin

panda = Panda(generic="x86_64")

s = Snake(panda, flask=True, host='0.0.0.0')

LiveProcGraph = s.load_plugin_class("proc_graph.py", 'LiveProcGraph')
s.register(LiveProcGraph)

# Alternatively, just register the (path, classname) directly
#s.register(("proc_graph.py", 'LiveProcGraph'))

s.serve()

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    assert(panda.run_serial_cmd("apt-get update -yy > /dev/null; sleep 10"))
    panda.end_analysis()

panda.run()
