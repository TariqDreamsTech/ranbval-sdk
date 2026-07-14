"""The first use of a credential must be reported even if the process dies a moment later.

It wasn't. `emit_telemetry(background=True)` dispatched on a *daemon* thread, and Python kills daemon
threads at interpreter shutdown — so a short-lived process dropped the event mid-POST.

The first use is the event a canary fires on. And a credential theft is a smash-and-grab:

    python -c "print(decrypt_key('SECRET_X').use())"

which is exactly the shape that exits too fast to send. The alarm was silent in precisely the case
it exists for. Verified against production: the canary alert only arrived when a sleep() was added
before exit.
"""

import subprocess
import sys
import textwrap
import threading
import time

from ranbval_sdk.telemetry import client


def test_a_background_emit_is_tracked_so_it_can_be_waited_for():
    slow = threading.Thread(target=lambda: time.sleep(0.3), daemon=True)
    with client._inflight_lock:
        client._inflight.add(slow)
    slow.start()

    client.flush_inflight(timeout=2.0)
    assert not slow.is_alive(), "flush_inflight must wait for an in-flight emit to land"

    with client._inflight_lock:
        client._inflight.discard(slow)


def test_the_wait_is_bounded_so_a_dead_control_plane_cannot_hang_the_process():
    """A security tool that can freeze your app on exit gets removed. The join must give up."""
    hang = threading.Thread(target=lambda: time.sleep(30), daemon=True)
    with client._inflight_lock:
        client._inflight.add(hang)
    hang.start()

    started = time.monotonic()
    client.flush_inflight(timeout=0.4)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"flush_inflight blocked for {elapsed:.1f}s — it must be bounded"

    with client._inflight_lock:
        client._inflight.discard(hang)


def test_atexit_joins_in_flight_emits():
    """End to end: a process that emits and exits immediately must still finish the POST."""
    script = textwrap.dedent(
        """
        import threading, time, sys
        from ranbval_sdk.telemetry import client

        landed = []
        t = threading.Thread(target=lambda: (time.sleep(0.4), landed.append(1)), daemon=True)
        with client._inflight_lock:
            client._inflight.add(t)
        t.start()

        import atexit
        atexit.register(lambda: sys.stdout.write("LANDED\\n" if landed else "LOST\\n"))

        # sampling's atexit hook runs flush_inflight; import it so it is registered.
        import ranbval_sdk.telemetry.sampling  # noqa: F401
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert "LANDED" in out.stdout, f"the emit was dropped on exit: {out.stdout!r} {out.stderr[-300:]}"
