Helper programs that are compiled into clubconnect go in this folder.

The release workflow (.github/workflows/build.yml) copies aether, psiphon-tunnel-core, lyrebird
and snowflake-client for the target platform here BEFORE it builds clubconnect, so the finished
program is one file: on start it unpacks them into <data_dir>/bin and uses them from there.

A normal "go build" with this folder empty is fine - clubconnect then looks for the helpers
next to itself, as before.
