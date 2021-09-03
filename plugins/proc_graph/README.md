# Live Process Graph

Shows a live-updating process graph using panda, flask, socketio and graphviz.

Tested with Python 3.9.5 using the dependency versions specified by requirements.txt.

Original written by Luke Craig, more info can be found [on his blog](https://www.lukecraig.com/process_list/). Ported for use with `snake_hook`.


### Example usage

Run the following command:

```
panda-system-x86_64 -panda "snake_hook:files=proc_graph.py,flask=1" \
    -nographic -os linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr \
    -loadvm root -m 1G ~/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow
```

(**Note:** this uses the x86_64 bionic qcow located [here](https://panda.re/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2) however it may have already been downloaded for you in . Tested against the [head of PANDA's dev branch](https://github.com/panda-re/panda/commit/1a9d9ad51f10c8b7890447383df1b5d6ed8e38dd).

Then navigate to http://localhost:8080/LiveProcGraph/ to view the process graph.
