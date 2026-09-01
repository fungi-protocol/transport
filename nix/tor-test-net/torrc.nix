# Per-role tor settings for the private test network (dax_dev tutorial
# ported to services.tor.settings). IPs come from the NixOS test framework.
#
# Adaptations from the tutorial's plain torrc, forced by
# services.tor.settings' typed submodule (see nixpkgs
# nixos/modules/services/security/tor.nix):
#   - `Nickname` is validated with `strMatching "^[a-zA-Z0-9]{1,19}$"` (no
#     hyphens), so the DA nicknames below are "testda1"/"testda2"/"testda3"
#     rather than the tutorial's "test-da1" etc. Callers of daSettings /
#     relaySettings must pass alphanumeric-only nicknames for the same
#     reason.
#   - the SOCKS port option is spelled `SOCKSPort` (not `SocksPort`) and is
#     `listOf`, so disabling it is `SOCKSPort = [ 0 ];` rather than a bare 0.
{ fingerprints }:
rec {
  daIp = i: "192.168.1.1${toString i}";

  common = daIps: {
    TestingTorNetwork = true;
    AssumeReachable = true;
    AddressDisableIPv6 = true;
    # All test nodes share one /24, so without this the distinct-subnet path
    # rule leaves no relay for hop #2 and no circuit (or onion rendezvous)
    # forms. TestingTorNetwork does NOT relax it on its own (empirically: with
    # this removed, every relay spammed "Failed to find node for hop #2"), so
    # set it explicitly.
    EnforceDistinctSubnets = false;
    # Onion-service circuits use vanguards-lite by default, which pins the
    # circuit's layer-2 hops to a small diverse set (the internal
    # _HSLayer2Nodes). This net is too small to populate that set, so the
    # hidden-service rendezvous circuits fail ("Failed to find node for hop
    # #2 ... Pre-built vanguard circuit"). Turn it off: a closed test net has
    # no guard-discovery adversary to defend against. (The arti peer already
    # has no vanguards — its `vanguards` cargo feature is off.)
    VanguardsLiteEnabled = false;
    DirAuthority = [
      "testda1 orport=9001 no-v2 v3ident=${fingerprints.da1.v3ident} ${builtins.elemAt daIps 0}:9030 ${fingerprints.da1.relayFingerprint}"
      "testda2 orport=9001 no-v2 v3ident=${fingerprints.da2.v3ident} ${builtins.elemAt daIps 1}:9030 ${fingerprints.da2.relayFingerprint}"
      "testda3 orport=9001 no-v2 v3ident=${fingerprints.da3.v3ident} ${builtins.elemAt daIps 2}:9030 ${fingerprints.da3.relayFingerprint}"
    ];
  };

  daSettings = { daIps, ip, nickname }: common daIps // {
    Address = ip;
    Nickname = nickname;
    ContactInfo = "${nickname} AT localhost";
    AuthoritativeDirectory = true;
    V3AuthoritativeDirectory = true;
    ORPort = 9001;
    DirPort = 9030;
    SOCKSPort = [ 0 ];
    TestingDirAuthVoteGuard = "*";
    TestingDirAuthVoteHSDir = "*";
    # v3 onion HSDir placement depends on the consensus shared-random value,
    # which only becomes real (num_reveals > 0) after a full commit+reveal
    # cycle (~24 voting rounds). At TestingTorNetwork's 5-minute cadence that
    # is ~2h; a fresh net publishes a 0-reveal fallback SRV meanwhile, and the
    # arti client and C-tor service derive different HSDirs from it (cross-impl
    # 404s). Vote every minute so the real SRV lands within a run. Still well
    # inside the regime TestingTorNetwork already runs during bootstrap
    # (150s), with VoteDelay+DistDelay (20s) < interval.
    V3AuthVotingInterval = "1 minute";
    V3AuthVoteDelay = "10 seconds";
    V3AuthDistDelay = "10 seconds";
    # Fast voting shortens each consensus's validity (default 3 intervals = 3
    # min here); the CPU-starved arti peer then can't re-fetch in time, loses
    # its directory, and marks all guards down mid-dial. Keep each consensus
    # valid for ~20 intervals so the client stays bootstrapped through the run.
    V3AuthNIntervalsValid = 20;
    # The v3 onion HSDir ring assumes the time period equals the shared-random
    # period: on the real net both are 24h (voting=1h -> SRV period=24x1h=24h =
    # default hsdir_interval). arti derives the SRV lifetime as 24x the voting
    # interval and, if the time period is longer, cannot pair an SRV with the
    # period start and falls back to the *disaster* SRV — while C-tor uses the
    # real one, so they compute different HSDirs (cross-impl 404). Our voting is
    # 1 minute, so the SRV period is 24 min; set hsdir_interval to match. A
    # consensus param needs a majority of authorities, so every DA votes it.
    # hsdir_interval=24 aligns the onion time period to the SRV period (above).
    # cbtdisabled=1 + cbtinitialtimeout=120000 turn off arti's adaptive
    # circuit-build-timeout (which learns fast real-network build times and
    # abandons the CPU-starved VM rendezvous circuits early) and pin a generous
    # fixed 120s build timeout so slow circuits still complete.
    ConsensusParams = "hsdir_interval=24 cbtdisabled=1 cbtinitialtimeout=120000";
  };

  relaySettings = { daIps, ip, nickname }: common daIps // {
    Address = ip;
    Nickname = nickname;
    ContactInfo = "${nickname} AT localhost";
    ORPort = 9001;
    SOCKSPort = [ 0 ];
  };

  clientSettings = { daIps }: common daIps // {
    # No SOCKSPort here: peer nodes get their SocksPort (127.0.0.1:9050)
    # from NixOS's services.tor.client.enable, which contributes its own
    # SOCKSPort entry. Setting one here too would concatenate into two
    # binds on the same port, which is fatal at tor startup.
    #
    # Full server descriptors instead of microdescriptors: at this net's
    # 1-minute voting cadence each consensus re-references churning
    # microdescs faster than a client fetches them, so directory info
    # decays (half the microdescs held, ~1/3 of paths buildable) until a
    # late-run onion rendezvous cannot complete.
    UseMicrodescriptors = false;
    ControlPort = 9051;
    # Null control auth on localhost: matches the backend's ControlAuth::Null.
    CookieAuthentication = false;
    HashedControlPassword = null;
  };
}
