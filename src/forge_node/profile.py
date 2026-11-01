"""Build profile of this tree. The source tree is `full`; the release builder writes `t0` into the zipapp of a T0-only artifact (Design 13.D: g1 and g4 get no T1/T2 code)."""
PROFILE = "full"
RELEASE = "source-tree"                                      # the release builder writes the release name (the audit `release_switch` record needs to tell two releases of one __version__ apart)
