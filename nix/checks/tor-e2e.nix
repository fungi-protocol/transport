# Cross-backend Tor end-to-end VM test as its own flake-parts module.
# Defined only for x86_64-linux, where the NixOS VM test runs.
{ inputs, ... }:
{
  # Always define `checks` (static output shape); only its contents are
  # system-conditional, so flake-parts' formatter heuristic stays happy.
  perSystem = { system, self', ... }: {
    checks = inputs.nixpkgs.lib.optionalAttrs (system == "x86_64-linux") (
      let
        # Plain nixpkgs: the VM test needs testers/netcat/tor, not the rust overlay.
        pkgs = inputs.nixpkgs.legacyPackages.${system};
      in
      {
      tor-e2e = pkgs.testers.runNixOSTest {
        name = "fungi-tor-e2e";
        # The onion dial happens in the disaster-SRV window, before the first
        # real shared-random value publishes, so the script finishes in minutes
        # rather than waiting out the ~48-min commit+reveal cycle. The per-step
        # timeouts below are the fail-fast mechanism — a stuck dial fails at its
        # own deadline; globalTimeout is only the outer backstop. Keep it above
        # the sum of the per-step budgets, so a slow-but-passing run fails at a
        # clean per-step timeout rather than being cut off mid-step as an opaque
        # global timeout.
        # The gossip step adds up to ~3000s of per-node budget on the listening
        # node (wiring accepts and dials, then convergence and drain) on top of
        # the dial steps.
        globalTimeout = 7200;
        nodes = let
          fingerprints = import ../tor-test-net/fingerprints.nix;
          torrc = import ../tor-test-net/torrc.nix { inherit fingerprints; };
          daIps = [ "192.168.1.11" "192.168.1.12" "192.168.1.13" ];
          mkDa = i: { ... }: {
            networking.interfaces.eth1.ipv4.addresses = [{ address = builtins.elemAt daIps (i - 1); prefixLength = 24; }];
            networking.firewall.enable = false;
            # A test-net tor node is light; cap RAM so the larger relay set fits
            # the 16 GB runner.
            virtualisation.memorySize = 512;
            services.tor = {
              enable = true;
              # relay.enable is required or the module force-clears ORPort/DirPort
              # from settings (its guard against accidentally relaying); an
              # authority is a relay that also votes, so role = "relay".
              relay.enable = true;
              relay.role = "relay";
              settings = torrc.daSettings {
                inherit daIps;
                ip = builtins.elemAt daIps (i - 1);
                nickname = "testda${toString i}";
              };
            };
            # Pre-seed the fixture identity keys before tor starts. This
            # runs as User=tor (systemd's ExecStartPre inherits the unit's
            # User=), and the unit's SystemCallFilter denies chown(), so
            # ownership must already be correct as written rather than
            # fixed up after the fact with chown -R.
            systemd.services.tor.preStart = ''
              install -d -m 700 /var/lib/tor/keys
              cp ${../tor-test-net}/da${toString i}/keys/* /var/lib/tor/keys/
              cp ${../tor-test-net}/da${toString i}/fingerprint* /var/lib/tor/ 2>/dev/null || true
              chmod 600 /var/lib/tor/keys/*
            '';
          };
          mkRelay = i: { ... }: {
            networking.interfaces.eth1.ipv4.addresses = [{ address = "192.168.1.2${toString i}"; prefixLength = 24; }];
            networking.firewall.enable = false;
            # Relays build the onion rendezvous circuits; 512 MB with no swap
            # starved tor and it dropped most circuits. 1 GB keeps them reliable
            # (3x512 DA + 6x1024 relay + 3x1024 peer = ~10.7 GB, fits the runner).
            virtualisation.memorySize = 1024;
            services.tor = {
              enable = true;
              # Same as the authorities: without relay.enable the module
              # force-clears the ORPort, so the relay would never relay.
              relay.enable = true;
              relay.role = "relay";
              settings = torrc.relaySettings {
                inherit daIps;
                ip = "192.168.1.2${toString i}";
                nickname = "testrelay${toString i}";
              };
            };
          };
        in {
          da1 = mkDa 1; da2 = mkDa 2; da3 = mkDa 3;
          # Onion services need path diversity: the dax_dev reference net uses
          # ~8 relays. Six mid/guard relays give the client and hidden-service
          # rendezvous circuits enough distinct nodes to form (3 relays could not).
          relay1 = mkRelay 1; relay2 = mkRelay 2; relay3 = mkRelay 3;
          relay4 = mkRelay 4; relay5 = mkRelay 5; relay6 = mkRelay 6;
          peer_socks = { ... }: {
            networking.interfaces.eth1.ipv4.addresses = [{ address = "192.168.1.31"; prefixLength = 24; }];
            networking.firewall.enable = false;
            services.tor = { enable = true; client.enable = true; settings = torrc.clientSettings { inherit daIps; }; };
            environment.systemPackages = [ pkgs.netcat ];
          };
          peer_arti = { ... }: {
            networking.interfaces.eth1.ipv4.addresses = [{ address = "192.168.1.32"; prefixLength = 24; }];
            networking.firewall.enable = false;
          };
          peer_socks2 = { ... }: {
            networking.interfaces.eth1.ipv4.addresses = [{ address = "192.168.1.33"; prefixLength = 24; }];
            networking.firewall.enable = false;
            services.tor = { enable = true; client.enable = true; settings = torrc.clientSettings { inherit daIps; }; };
            environment.systemPackages = [ pkgs.netcat ];
          };
        };
        testScript = ''
          e2e = "${self'.packages.harness}/bin/harness"
          # The harness drives each backend as a capnp PLUGIN subprocess: it
          # spawns these binaries and speaks the plugin protocol over their
          # stdio, rather than building the backend in-process.
          socks5h_plugin = "${self'.packages.fungi-socks5h-plugin}/bin/fungi-socks5h-plugin"
          arti_plugin = "${self'.packages.fungi-arti-plugin}/bin/fungi-arti-plugin"

          start_all()

          for da in [da1, da2, da3]:
              da.wait_for_unit("tor.service")
          da1.wait_until_succeeds("curl -s http://192.168.1.11:9030/tor/status-vote/current/consensus >/dev/null", timeout=300)

          # The consensus gate is >=8 of the 9 nodes (3 DAs + 6 relays), so one
          # slow node does not fail it.
          for r in [relay1, relay2, relay3, relay4, relay5, relay6]:
              r.wait_for_unit("tor.service")
          da1.wait_until_succeeds(
              "test $(curl -s http://192.168.1.11:9030/tor/status-vote/current/consensus | grep -c '^r ') -ge 8",
              timeout=600,
          )

          # No shared-random wait: on a fresh net, before the first real SRV
          # publishes (~24 min at 1-minute voting), the consensus carries no
          # SRV, so arti and C-tor both fall back to the *same* deterministic
          # disaster SRV for this time period and compute the same HSDir ring.
          # Dialing now, well inside that window, resolves the onion cross-impl
          # in minutes. (Waiting until both real SRVs publish also works but
          # costs ~48 min; the window between, where only the current SRV
          # exists, is the cross-impl 404.)

          # Compose the arti private-net file from runtime relay identities.
          lines = []
          import json
          import shlex
          # Single-quoted: this testScript is itself a Nix indented string,
          # where a doubled single-quote is the escape for a literal
          # doubled single-quote, so a lone single Nix quote on each side
          # yields one literal Python quote (JSON emits no bare single
          # quotes, so this is safe).
          fps = '${builtins.toJSON (import ../tor-test-net/fingerprints.nix)}'
          f = json.loads(fps)
          for name in ["da1", "da2", "da3"]:
              lines.append(f"authority test{name} {f[name]['v3ident']}")
          for machine, ip in [(da1, "192.168.1.11"), (da2, "192.168.1.12"), (da3, "192.168.1.13")]:
              rsa = machine.succeed("cat /var/lib/tor/fingerprint").split()[-1]
              ed = machine.succeed("cat /var/lib/tor/fingerprint-ed25519").split()[-1]
              lines.append(f"fallback {rsa} {ed} {ip}:9001")
          netfile = "\n".join(lines)
          peer_arti.succeed(f"printf '%s\\n' {shlex.quote(netfile)} > /tmp/private-net")

          peer_socks.wait_for_unit("tor.service")
          peer_socks.wait_until_succeeds("nc -z 127.0.0.1 9051", timeout=120)
          peer_socks.succeed(
              f"({e2e} listen --plugin {socks5h_plugin} --virt-port 9735 > /tmp/listen.log 2>/tmp/listen.err; echo $? > /tmp/listen.code) </dev/null >/dev/null 2>&1 &"
          )
          peer_socks.wait_until_succeeds("grep -q READY /tmp/listen.log", timeout=300)
          onion = peer_socks.succeed("grep ONION= /tmp/listen.log").strip().split("=", 1)[1]

          # Let the onion service establish its introduction points, upload its
          # descriptor, and the small CPU-starved net settle before the dialer
          # stresses it — otherwise the service can lose its descriptor mid-run.
          peer_socks.sleep(90)

          # wait_until_succeeds retries the whole dial: absorbs the onion-descriptor
          # publication race (spec: "with retries on failure").
          # Every arti run here is a fresh peer with its own identity, but they
          # all live on one network directory: --cache-dir shares what the first
          # bootstrap downloaded, so a later phase is not a cold client on a
          # CPU-starved VM while its peers are already dialing it.
          arti_cache = "--cache-dir /tmp/arti-shared"
          # Arti's own account of a dial, on the plugin's stderr, which each
          # phase already collects. Scoped to the onion-service client: a bare
          # `info` buries the interesting lines under bootstrap chatter.
          arti_log = "RUST_LOG=warn,arti_client=info,tor_hsclient=debug"
          peer_arti.wait_until_succeeds(
              f"{e2e} dial --plugin {arti_plugin} --private-net /tmp/private-net --state-dir /tmp/arti-dial {arti_cache} {onion}",
              timeout=900,
          )
          # The dialer's OK already proves the channel both ways: it sends four
          # messages and verifies every echo. The echo listener is not required
          # to exit cleanly, it blocks in recv waiting for the peer to depart,
          # and on a freshly-booted net the onion circuit teardown that surfaces
          # that departure is unreliable. Record its log, then stop it.
          peer_socks.execute("cat /tmp/listen.err >&2 || true")
          peer_socks.execute("pkill -f 'harness listen' || true")

          # The listener must outlive its first peer: it serves the default
          # dial below plus the two isolated dials after it, sequentially.
          peer_arti.succeed(
              f"({e2e} listen --plugin {arti_plugin} --private-net /tmp/private-net --state-dir /tmp/arti-listen {arti_cache} --virt-port 9735 --peers 3 > /tmp/listen.log 2>/tmp/listen.err; echo $? > /tmp/listen.code) </dev/null >/dev/null 2>&1 &"
          )
          peer_arti.wait_until_succeeds("grep -q READY /tmp/listen.log", timeout=600)
          onion2 = peer_arti.succeed("grep ONION= /tmp/listen.log").strip().split("=", 1)[1]
          # Same settling as the socks5h onion above: let the arti onion service
          # publish and the net stabilize before socks5h dials it.
          peer_arti.sleep(90)
          peer_socks.wait_until_succeeds(f"{e2e} dial --plugin {socks5h_plugin} {onion2}", timeout=900)

          # The circuit-isolation id's text form is the SOCKS username, and the daemon
          # (IsolateSOCKSAuth, on by default) must keep distinct credentials
          # on distinct circuits. circuit-status reports each circuit's
          # SOCKS_USERNAME, and circuits outlive their streams, so the
          # separation is asserted post-facto with no timing race. The arti
          # side has no equivalent window: nothing stable enumerates its
          # circuits, so its isolation stays covered by the offline
          # token-wiring tests.
          for sess in ["4242-1", "4242-2"]:
              peer_socks.wait_until_succeeds(
                  f"{e2e} dial --plugin {socks5h_plugin} --circuit-isolation {sess} {onion2}", timeout=300
              )
          status = peer_socks.succeed(
              "printf 'AUTHENTICATE\\r\\nGETINFO circuit-status\\r\\nQUIT\\r\\n' | nc -w 5 127.0.0.1 9051"
          )
          assert 'SOCKS_USERNAME="4242-1"' in status, f"no circuit for isolation group 4242-1:\n{status}"
          assert 'SOCKS_USERNAME="4242-2"' in status, f"no circuit for isolation group 4242-2:\n{status}"
          for line in status.splitlines():
              assert not ("4242-1" in line and "4242-2" in line), f"isolation groups share a circuit:\n{line}"

          # As with the socks5h listener above: the dialer's OK is the proof, so
          # the arti echo listener need not exit cleanly. Record its log, stop it.
          peer_arti.execute("cat /tmp/listen.err >&2 || true")
          peer_arti.execute("pkill -f 'harness listen' || true")

          # Gossip convergence on a LINE topology: A(socks5h) — B(socks5h) — C(arti).
          # Only B publishes an onion; A and C dial it. A's message can reach C
          # only through B's forwarding — plain multicast cannot serve this graph.
          #
          # The hub is the socks5h peer, not the arti one, because the hub is
          # the only node whose descriptor the others must resolve, and the
          # arti-published descriptor is the artifact this test keeps losing:
          # both red runs died fetching one, minutes after a C-tor-published
          # one resolved. Cross-backend is unchanged — C still speaks arti, and
          # its messages still reach A only through B — and the arti side still
          # publishes once, in the P2P phase above, which is where the claim
          # that arti can be dialed cross-impl actually lives.
          session_hex = "01" * 32
          session_args = f"--protocol-session {session_hex} --protocol-version 1 --max-message-size 1048576"
          peer_socks2.wait_for_unit("tor.service")
          peer_socks2.wait_until_succeeds("nc -z 127.0.0.1 9051", timeout=120)
          peer_socks.succeed(
              f"({e2e} gossip --plugin {socks5h_plugin} --virt-port 9736 --listen-peers 2 {session_args} --message-type psbt --message from-b --extension 1:optional --duplicate --expect 3 > /tmp/gossip.log 2>/tmp/gossip.err; echo $? > /tmp/gossip.code) </dev/null >/dev/null 2>&1 &"
          )
          peer_socks.wait_until_succeeds("grep -q READY /tmp/gossip.log", timeout=600)
          gossip_onion = peer_socks.succeed("grep ONION= /tmp/gossip.log").strip().split("=", 1)[1]
          # Same onion-settling pause as the dial steps above.
          peer_socks.sleep(90)
          # Each dialer carries BOTH identities at once: the shared protocol
          # session every member is constructing, and its own transport-local
          # circuit-isolation group. Neither substitutes for the other.
          for node, plugin, extra, kind, own, isolation in [
              (peer_socks2, socks5h_plugin, "", "payment", "from-a", "1-1"),
              (peer_arti, arti_plugin, f"--private-net /tmp/private-net --state-dir /tmp/arti-gossip {arti_cache}", "confirmation", "from-c", "1-2"),
          ]:
              prefix = arti_log if plugin == arti_plugin else ""
              node.succeed(
                  f"({prefix} {e2e} gossip --plugin {plugin} {extra} --dial {gossip_onion} {session_args} --circuit-isolation {isolation} --message-type {kind} --message {own} --expect 3 > /tmp/gossip.log 2>/tmp/gossip.err; echo $? > /tmp/gossip.code) </dev/null >/dev/null 2>&1 &"
              )
          try:
              # A node that has already exited cannot go on to print OK, so stop
              # waiting the moment its exit code lands: the failure is then the
              # missing OK plus the stderr below, in a minute, instead of a
              # fifteen-minute timeout that says only that time passed.
              for node in [peer_socks, peer_socks2, peer_arti]:
                  node.wait_until_succeeds(
                      "grep -qx OK /tmp/gossip.log || test -s /tmp/gossip.code", timeout=900
                  )
                  node.succeed("grep -qx OK /tmp/gossip.log")
              nodes = [peer_socks, peer_socks2, peer_arti]
              message_sets = []
              commitments = []
              for node in nodes:
                  messages = sorted(node.succeed("grep '^MSG=' /tmp/gossip.log").split())
                  assert len(messages) == 3, f"message count mismatch on {node.name}: {messages}"
                  assert node.succeed("grep '^COUNT=' /tmp/gossip.log").strip() == "COUNT=3"
                  commitment = node.succeed("grep '^COMMITMENT=' /tmp/gossip.log").strip()
                  assert len(commitment) == len("COMMITMENT=") + 64, commitment
                  for message in messages:
                      identity, encoded = message.removeprefix("MSG=").split(":", 1)
                      assert len(identity) == 64, message
                      assert encoded in [
                          session_hex + "000100010666726f6d2d6201086f7074696f6e616c",
                          session_hex + "000100030666726f6d2d61",
                          session_hex + "000100050666726f6d2d63",
                      ], message
                  message_sets.append(messages)
                  commitments.append(commitment)
              assert message_sets[0] == message_sets[1] == message_sets[2], message_sets
              assert commitments[0] == commitments[1] == commitments[2], commitments
          finally:
              # On failure the harness's stderr (dial retries, transport
              # errors) is the only record of what each gossip node saw;
              # dump it unconditionally, not just on the success path.
              for node in [peer_socks, peer_socks2, peer_arti]:
                  node.execute("cat /tmp/gossip.err >&2 || true")

          # A peer with a mismatched exact protocol version is rejected during
          # the connection-local binding, before either side constructs gossip.
          # What this proves is a handshake rule, not a publication: the
          # listener is the socks5h peer for the same reason the gossip hub is.
          peer_socks.succeed(
              f"({e2e} gossip --plugin {socks5h_plugin} --virt-port 9737 --listen-peers 1 {session_args} --message-type psbt --message listener --expect 2 > /tmp/mismatch.log 2>/tmp/mismatch.err; echo $? > /tmp/mismatch.code) </dev/null >/dev/null 2>&1 &"
          )
          peer_socks.wait_until_succeeds("grep -q READY /tmp/mismatch.log", timeout=600)
          mismatch_onion = peer_socks.succeed("grep ONION= /tmp/mismatch.log").strip().split("=", 1)[1]
          peer_socks.sleep(90)
          peer_arti.succeed(
              f"({arti_log} {e2e} gossip --plugin {arti_plugin} --private-net /tmp/private-net --state-dir /tmp/arti-mismatch {arti_cache} --dial {mismatch_onion} --protocol-session {session_hex} --protocol-version 2 --max-message-size 1048576 --message-type payment --message dialer --expect 2 > /tmp/mismatch.log 2>/tmp/mismatch.err; echo $? > /tmp/mismatch.code) </dev/null >/dev/null 2>&1 &"
          )
          try:
              # Wait on the DIALER, which always terminates: it is rejected, or
              # its own retry budget ends. The listener leaves accept() only
              # once a peer arrives, so waiting on it first turns every dial
              # failure into a silent timeout with nothing to read.
              peer_arti.wait_until_succeeds("test -s /tmp/mismatch.code", timeout=900)
              # Then the listener, which the rejection releases — a check by
              # now, not a wait.
              peer_socks.wait_until_succeeds("test -s /tmp/mismatch.code", timeout=300)
              for node in [peer_socks, peer_arti]:
                  assert node.succeed("cat /tmp/mismatch.code").strip() != "0"
                  node.succeed("grep -q 'protocol version' /tmp/mismatch.err")
                  node.succeed("test ! -s /tmp/mismatch.log || ! grep -q '^MSG=' /tmp/mismatch.log")
          finally:
              for node in [peer_socks, peer_arti]:
                  node.execute("cat /tmp/mismatch.err >&2 || true")
        '';
      };
      }
    );
  };
}
