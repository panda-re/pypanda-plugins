# Current Design:
On PRs and pushs:
  Fetch latests `pandare/panda` container and run all tests. Each test clones container and downloads a generic qcow from panda-re.mit.edu


# Better design
One task to fetch container and pre-stage generic qcow. Then run each test in parallel using that container + qcow.
