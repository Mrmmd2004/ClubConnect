Helper programs that are compiled into clubconnect go in this folder.

The release workflow (.github/workflows/build.yml) copies these into this folder
BEFORE it builds clubconnect, so the finished program is one self-contained file:

  - aether              (MASQUE / gool / mim / noize WARP engine)
  - psiphon-tunnel-core (Psiphon)
  - tor                 (Tor daemon)
  - lyrebird            (obfs4 / meek / webtunnel transport)
  - snowflake-client    (Snowflake transport)
  - *.dll               (Windows libraries required by tor, when present)

On start, clubconnect unpacks them into <data_dir>/bin and uses them from there.

A normal "go build" with this folder empty is fine - clubconnect then looks for
the helpers next to itself or on PATH, and the built-in WireGuard WARP still works.
