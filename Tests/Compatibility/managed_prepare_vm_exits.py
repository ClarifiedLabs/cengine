"""Native exit proof for a held VM owner, optionally with two active ACK owners.

The parent owns SIGKILL authority and calls delivered() only after audited storage
signal success. This observer never signals, infers causation, or dates an exit.
"""
from dataclasses import replace
import select
import signal
import time

import harness
import managed_prepare_faults as p
import managed_storage_recovery as r


class VMExposedOwnerExits:
    def __init__(self, owners, processes, remaining, record):
        self.owners = tuple(owners)
        p.require(len(self.owners) in (1, 3), "one held owner or three ACK-exposed owners")
        self._owners = self._census(self.owners)
        self._pinned = self._owners.copy()
        self._api_refreshed = False
        self.processes, self.remaining, self.record = processes, remaining, record
        self._queue = None
        self._entered = self._ready = self._delivered = False
        self._events, self._exited = set(), set()

    @staticmethod
    def _census(values):
        values = tuple(values)
        for value in values:
            p.require(type(value) is harness.RuntimeProcess, "original native RuntimeProcess required")
            p.native_proof(value)
        p.require(len({value.pid for value in values}) == len(values), "duplicate process census")
        return {value.pid: value for value in values}

    def _budget(self):
        budget = self.remaining()
        p.require(budget > 0, "exposed owner exit deadline")
        return budget

    def __enter__(self):
        p.require(not self._entered, "single exposed exit context")
        self._entered = True
        try:
            self._alive()
            self._queue = select.kqueue()
            changes = [select.kevent(owner.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT) for owner in self.owners]
            p.require(not self._queue.control(changes, 0, 0), "no registration exit receipts")
            self.before_signal()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        queue, self._queue = self._queue, None
        if queue is not None:
            queue.close()

    def _alive(self):
        self._budget()
        for owner in self.owners:
            p.require(harness._kernel_process(owner.pid) == owner, "same live exposed owner before storage signal")

    def _drain(self):
        if self._queue is None:
            raise r.ProofFailure("open exposed exit context")
        events = self._queue.control(None, len(self.owners), 0)
        p.require(not events or self._delivered, "exposed exit event before storage delivery")
        for event in events:
            p.require(event.ident in self._owners and event.ident not in self._events
                and event.filter == select.KQ_FILTER_PROC
                and not event.flags & (select.KQ_EV_ERROR | 0x40)  # Darwin EV_RECEIPT, not exported by Python.
                and event.fflags == select.KQ_NOTE_EXIT, "exact independent exposed NOTE_EXIT")
            self._events.add(event.ident)

    def before_signal(self):
        p.require(not self._delivered, "storage signal not yet delivered")
        self._ready = False
        self._drain()
        self._alive()
        self._drain()
        self._ready = True

    def delivered(self):
        p.require(self._queue is not None and self._ready and not self._delivered,
            "one audited storage SIGKILL delivery after prekill validation")
        # The audited signal may synchronously cause exits before this call.
        # Queued events have no timestamp: this gate asserts delivery, not causation.
        self._delivered = True

    def api_joined_refresh(self, daemon, api, expected_census):
        """Refresh live lineage once, only after the exact API SIGKILL join.

        Original exposed tuples remain historical exit/ACK evidence. Only live
        census pins may adopt an observed direct-child reparenting to launchd.
        """
        p.require(self._queue is not None and self._delivered and not self._api_refreshed,
            "one post-delivery API survivor refresh")
        expected = self._census(expected_census)
        p.require(expected.get(api.pid) == api and api.pid not in self._owners
            and daemon.process.pid == api.pid and daemon.process.returncode == -signal.SIGKILL
            and r.exact_exit(api, harness._kernel_process(api.pid)),
            "joined exact API exit before survivor refresh")
        p.require(all(expected.get(pid) == owner for pid, owner in self._owners.items()),
            "expected census retains all original exposed owners")
        self._budget()
        actual = self._census(self.processes())
        pinned = self._pinned.copy()
        for pid, observed in actual.items():
            previous = pinned.get(pid, expected.get(pid))
            p.require(pid != api.pid and pid not in self._exited and previous is not None,
                "extra or previously exited runtime process at API join")
            p.require(observed == previous or (previous.parent_pid == api.pid
                and observed == replace(previous, parent_pid=1)),
                "exact survivor or killed API child reparented to PID 1")
            if pid in pinned:
                pinned[pid] = observed
            else:
                expected[pid] = observed
        self._pinned = pinned
        self._api_refreshed = True
        # Normal observation still requires preregistered exit events, rejects
        # missing protected owners and validates every current native survivor.
        self.observe([value for pid, value in expected.items() if pid != api.pid], "api-exit-joined")
        return list(expected.values())

    def observe(self, expected_census, phase):
        """Return exact current survivors, keeping original owners in expectations.

        Only a newly proven selected exit can make a census stale and justify a
        retry. Inspection errors, replacements and missing protected owners never
        become retries. The caller supplies protected owners for this exact phase.
        """
        p.require(self._delivered, "audited storage SIGKILL delivery required")
        expected = self._census(expected_census)
        p.require(all(expected.get(pid) == owner for pid, owner in self._owners.items()),
            "expected census retains all original exposed owners")
        expected.update(self._pinned)
        protected = {pid: owner for pid, owner in expected.items() if pid not in self._owners}
        while True:
            self._budget()
            self._drain()
            actual = self._census(self.processes())
            p.require(all(expected.get(pid) == owner for pid, owner in actual.items()),
                "extra or changed runtime process")
            p.require(all(actual.get(pid) == owner for pid, owner in protected.items()),
                "missing protected runtime process")
            for pid, owner in protected.items():
                p.require(harness._kernel_process(pid) == owner, "changed protected native process")
            current = {pid: harness._kernel_process(pid) for pid in self._owners}
            self._drain()
            newly_exited = set()
            for pid, owner in self._owners.items():
                dead = r.exact_exit(owner, current[pid])
                if dead:
                    p.require(pid in self._events, "native absence without preregistered NOTE_EXIT")
                    if pid not in self._exited:
                        self.record("storage-exposed-owner-exit-observed",
                            native=p.native_proof(owner), observedAt=phase)
                        self._exited.add(pid)
                        newly_exited.add(pid)
                else:
                    p.require(pid not in self._exited and current[pid] == self._pinned[pid],
                        "changed or revived exposed native process")
                    p.require(actual.get(pid) == self._pinned[pid], "live exposed owner missing from census")
            stale = self._exited.intersection(actual)
            p.require(stale <= newly_exited, "previously exited owner in runtime census")
            if stale:
                # At most three monotonic transitions, each with both proofs.
                continue
            for pid, owner in protected.items():
                p.require(harness._kernel_process(pid) == owner, "changed protected native process")
            return list(actual.values())

    def join_all(self, expected_census, phase):
        expected_census = tuple(expected_census)
        while True:
            survivors = self.observe(expected_census, phase)
            if len(self._exited) == len(self.owners):
                return survivors
            time.sleep(min(0.025, self._budget()))
