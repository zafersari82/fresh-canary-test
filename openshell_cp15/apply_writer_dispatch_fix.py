#!/usr/bin/env python3
"""Apply the dispatch-time writer fence after observing the CP15 negative control."""
from pathlib import Path
import sys


def replace_once(s, old, new):
    if s.count(old) != 1:
        raise SystemExit('writer-fence source mismatch: '+old[:80])
    return s.replace(old, new, 1)


p = Path(sys.argv[1])/'crates/openshell-supervisor-network/src/durable_egress.rs'
s = p.read_text()
method = '''    fn with_current_writer<T>(&self, dispatch: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut fence_file = self.fence_file.lock()
            .map_err(|_| miette::miette!("BLACKBOX writer fence lock poisoned"))?;
        file_lock_exclusive(&fence_file).into_diagnostic()?;
        let result = (|| {
            let current = read_writer_token(&mut fence_file).into_diagnostic()?;
            if current != self.writer_token {
                return Err(miette::miette!("BLACKBOX stale writer rejected at dispatch admission"));
            }
            // Writer takeover and dispatch admission share this kernel lock.
            // An operation admitted before takeover may finish under v1 semantics.
            dispatch()
        })();
        let unlock = file_lock_release(&fence_file).into_diagnostic();
        let value = result?;
        unlock?;
        Ok(value)
    }

'''
s = replace_once(s, '    fn append_and_sync(&self, permit: &DurableEgressPermit) -> io::Result<()> {',
                 method+'    fn append_and_sync(&self, permit: &DurableEgressPermit) -> io::Result<()> {')
old = '''        self.authority.linearize_dispatch(
            opa,
            permit.policy_generation,
            &permit.supervisor_session_id,
            permit.supervisor_session_epoch,
        )'''
new = '''        self.store.with_current_writer(|| self.authority.linearize_dispatch(
            opa,
            permit.policy_generation,
            &permit.supervisor_session_id,
            permit.supervisor_session_epoch,
        ))'''
s = replace_once(s, old, new)
p.write_text(s)
print('CP15 dispatch admission now shares the durable writer fencing lock')
