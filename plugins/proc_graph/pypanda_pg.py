#!/usr/bin/env python3

# Example script to use proc_graph from a pypanda script
from proc_graph import LiveProcGraph

from pandare import Panda
panda = Panda(generic="x86_64")

panda.pyplugins.enable_flask(host='0.0.0.0')
panda.pyplugins.load(LiveProcGraph)
panda.pyplugins.serve()

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    assert(panda.run_serial_cmd("apt-get update -yy > /dev/null; sleep 10"))
    panda.end_analysis()

panda.run()
