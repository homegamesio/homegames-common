// One idle policy for Docker and fork children. The process manager owns
// supervision/port cleanup; the child owns its directly observed occupancy.
// Time is supplied by the caller so delayed checks measure elapsed time,
// rather than pretending every health poll arrived on schedule.
class SessionLifetime {
    constructor({ gracePeriodMs = 30000, heartbeatTimeoutMs = 5000 } = {}) {
        this.gracePeriodMs = gracePeriodMs;
        this.heartbeatTimeoutMs = heartbeatTimeoutMs;
        this.emptySince = null;
    }

    check({ hasPlayers, persistent, forked, lastHeartbeat }, now = Date.now()) {
        // Pinning keeps an idle game alive, but cannot orphan a fork whose
        // parent has gone away. Connected players are also protected against
        // a transient delayed heartbeat; IPC disconnect handles parent death.
        if (forked && !hasPlayers && lastHeartbeat != null && now - lastHeartbeat > this.heartbeatTimeoutMs) {
            return 'parent heartbeat expired';
        }
        if (hasPlayers || persistent) {
            this.emptySince = null;
            return null;
        }
        if (this.emptySince === null) this.emptySince = now;
        return now - this.emptySince >= this.gracePeriodMs ? 'session idle' : null;
    }
}

module.exports = SessionLifetime;
