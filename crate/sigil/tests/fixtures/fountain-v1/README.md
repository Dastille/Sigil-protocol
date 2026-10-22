# fountain-v1 fixtures (old `.rq` packets, SGFT version 1)

Written by the Rust CLI on `main` @ `bc96b5a` (before random symbol IDs and
per-packet checksums), so the reader for old packets stays tested:

```
sigil seal --mode seal -o mark.sg1 plain.bin
sigil deluge mark.sg1 --fountain --extra 2 -o rain     # rain-00000.rq .. rain-00007.rq
```

`plain.bin` is 40 000 pseudo-random bytes (Python `random.seed(6330)`).
