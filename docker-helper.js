const Docker = require('dockerode');
const tar = require('tar');
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Shared Docker client — auto-detects the platform-appropriate transport:
//   Linux/macOS: /var/run/docker.sock
//   Windows:     //./pipe/docker_engine
// ---------------------------------------------------------------------------
const docker = new Docker();

// ---------------------------------------------------------------------------
// Cache Docker availability for the process lifetime.
// ---------------------------------------------------------------------------
let _dockerAvailable = null;

const isDockerAvailable = async () => {
    if (_dockerAvailable !== null) return _dockerAvailable;

    try {
        await docker.ping();
        _dockerAvailable = true;
    } catch (err) {
        _dockerAvailable = false;
    }

    return _dockerAvailable;
};

// ---------------------------------------------------------------------------
// Check whether the homegames-runner image exists locally.
// ---------------------------------------------------------------------------
const isImageBuilt = async (imageName = 'homegames-runner') => {
    try {
        const images = await docker.listImages({
            filters: { reference: [imageName] },
        });
        return images.length > 0;
    } catch (err) {
        return false;
    }
};

// ---------------------------------------------------------------------------
// Build the homegames-runner image from a Dockerfile directory.
//
// Uses the Docker Engine API directly via a tar stream of the build context.
// No bash/shell dependency — works on Windows, macOS, and Linux.
// ---------------------------------------------------------------------------
const buildImage = async (dockerfilePath, imageName = 'homegames-runner') => {
    const dir = path.resolve(dockerfilePath);

    const stream = await docker.buildImage(tar.c({ cwd: dir }, fs.readdirSync(dir)), { t: imageName });

    return new Promise((resolve, reject) => {
        docker.modem.followProgress(stream, (err, output) => {
            if (err) {
                reject(new Error(`Docker build failed: ${err.message}`));
            } else {
                // Check the last message for an error object (build failures
                // sometimes surface here rather than in the callback error).
                const last = output && output[output.length - 1];
                if (last && last.error) {
                    reject(new Error(`Docker build failed: ${last.error}`));
                } else {
                    resolve();
                }
            }
        });
    });
};

// ---------------------------------------------------------------------------
// Ensure the image is built. Build it if missing.
// ---------------------------------------------------------------------------
const ensureImage = async (dockerfilePath, imageName = 'homegames-runner') => {
    if (await isImageBuilt(imageName)) return;
    return buildImage(dockerfilePath, imageName);
};

// ---------------------------------------------------------------------------
// Run a game inside a Docker container for live game sessions.
//
// Options:
//   codePath         — absolute path to a directory containing the game code
//   port             — host port to map (also used as container port)
//   squishVersion    — squish version string
//   saveDataPath     — absolute path to host directory for game save data (optional)
//   certPath         — absolute path to host directory containing homegames.key
//                      and homegames.cert; mounted read-only so the session
//                      serves wss/https (optional)
//   imageName        — Docker image name (default: 'homegames-runner')
//   memoryLimit      — memory limit in bytes or string (default: '256m')
//   cpuLimit         — CPU limit as a string (default: '1')
//   gameEntryRelative — relative path to the entry file inside the mounted code dir
//
// Returns: { containerId, port }
// ---------------------------------------------------------------------------
const runGameContainer = async ({
    codePath,
    port,
    squishVersion,
    saveDataPath,
    certPath = null,
    assetCachePath = null,
    imageName = 'homegames-runner',
    memoryLimit = '196m',
    cpuLimit = '1',
    gameEntryRelative = null,
    noFrame = false,
    extraEnv = {},
}) => {
    const env = [
        `GAME_PORT=${port}`,
        `SQUISH_VERSION=${squishVersion}`,
        `NO_FRAME=${noFrame ? '1' : ''}`,
    ];

    // Pass through extra environment variables from the host
    for (const key in extraEnv) {
        if (extraEnv[key] !== undefined && extraEnv[key] !== null) {
            env.push(`${key}=${extraEnv[key]}`);
        }
    }

    if (gameEntryRelative) {
        env.push(`GAME_ENTRY=${gameEntryRelative}`);
    }

    // On macOS and Windows (Docker Desktop) host.docker.internal is provided
    // automatically. On Linux we need to add it explicitly.
    const extraHosts = [];
    if (process.platform === 'linux') {
        extraHosts.push('host.docker.internal:host-gateway');
    }
    env.push('DOCKER_HOST_HOSTNAME=host.docker.internal');

    // Run the container as the host process's uid/gid so mounted files carry
    // the same access the fork path has. CapDrop ALL below removes
    // CAP_DAC_OVERRIDE, so container root cannot read files the host user
    // owns with restrictive modes (e.g. a 600 TLS key) — running as the host
    // user can. No getuid on Windows; Docker Desktop maps ownership there.
    const hostUser = typeof process.getuid === 'function'
        ? `${process.getuid()}:${process.getgid()}`
        : null;
    // Non-root has no writable /root; point HOME at the tmpfs instead so
    // getAppDataPath()-style writes (~/.homegames) still work.
    const containerHome = hostUser ? '/tmp' : '/root';
    env.push(`HOME=${containerHome}`);

    const binds = [
        `${path.resolve(codePath)}:/app/game:ro`,
    ];

    if (saveDataPath) {
        const resolved = path.resolve(saveDataPath);
        if (!fs.existsSync(resolved)) {
            fs.mkdirSync(resolved, { recursive: true });
        }
        binds.push(`${resolved}:/app/save:rw`);
    }

    // Mount host TLS certs read-only. child_game_server.js reads CERT_PATH
    // and expects homegames.key / homegames.cert inside it (same layout as
    // the host's hg-certs directory).
    if (certPath) {
        binds.push(`${path.resolve(certPath)}:/certs:ro`);
        env.push('CERT_PATH=/certs');
    }

    // Mount the host's asset cache so containers share downloaded assets
    if (assetCachePath) {
        const resolved = path.resolve(assetCachePath);
        if (!fs.existsSync(resolved)) {
            fs.mkdirSync(resolved, { recursive: true, mode: 0o777 });
        } else {
            fs.chmodSync(resolved, 0o777);
        }
        binds.push(`${resolved}:${containerHome}/.homegames/asset-cache:rw`);
    }

    // Parse memory limit to bytes if it's a human string (e.g. '256m')
    const memoryBytes = parseMemoryString(memoryLimit);

    const container = await docker.createContainer({
        Image: imageName,
        Cmd: ['container-entry.js'],
        ...(hostUser ? { User: hostUser } : {}),
        Env: env,
        Labels: {
            'homegames-session': 'true',
            'homegames-port': String(port),
        },
        ExposedPorts: {
            [`${port}/tcp`]: {},
        },
        HostConfig: {
            AutoRemove: true,
            Binds: binds,
            PortBindings: {
                [`${port}/tcp`]: [{ HostPort: String(port) }],
            },
            Memory: memoryBytes,
            NanoCpus: parseCpuLimit(cpuLimit),
            PidsLimit: 64,
            CapDrop: ['ALL'],
            Tmpfs: {
                '/tmp': 'rw,size=160m',
            },
            ExtraHosts: extraHosts,
        },
    });

    await container.start();

    return { containerId: container.id, port };
};

// ---------------------------------------------------------------------------
// Run game validation in a Docker container (for homedome).
// No networking, no port mapping, no save directory.
//
// Returns: { success: boolean, squishVersion?: string, error?: string }
// ---------------------------------------------------------------------------
const validateGame = async ({
    codePath,
    squishVersion,
    imageName = 'homegames-runner',
    timeoutMs = 30000,
    memoryLimit = '256m',
}) => {
    const memoryBytes = parseMemoryString(memoryLimit);

    let container;
    try {
        container = await docker.createContainer({
            Image: imageName,
            Cmd: ['validate.js'],
            Env: [
                `SQUISH_VERSION=${squishVersion}`,
            ],
            HostConfig: {
                Binds: [
                    `${path.resolve(codePath)}:/app/game:ro`,
                ],
                Memory: memoryBytes,
                NanoCpus: 0.5e9,
                PidsLimit: 32,
                CapDrop: ['ALL'],
                ReadonlyRootfs: true,
                Tmpfs: { '/tmp': 'rw,noexec,size=32m' },
                NetworkMode: 'none',
            },
        });

        await container.start();

        // Wait for the container to exit, with a timeout.
        const waitPromise = container.wait();
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Validation timed out')), timeoutMs)
        );

        let exitResult;
        try {
            exitResult = await Promise.race([waitPromise, timeoutPromise]);
        } catch (err) {
            // Timed out — kill and remove
            try { await container.stop({ t: 0 }); } catch (_) {}
            try { await container.remove({ force: true }); } catch (_) {}
            return { success: false, error: err.message || 'Container timeout' };
        }

        // Collect stdout logs (validate.js writes JSON to stdout).
        const logs = await container.logs({ stdout: true, stderr: true, follow: false });
        const output = demuxDockerLogs(logs);

        // Remove the container (equivalent of --rm).
        try { await container.remove(); } catch (_) {}

        if (!output.stdout) {
            return {
                success: false,
                error: output.stderr ? output.stderr.trim().slice(-500) : 'No output from validation',
            };
        }

        try {
            return JSON.parse(output.stdout.trim());
        } catch (parseErr) {
            return {
                success: false,
                error: `Failed to parse validation output: ${output.stdout.slice(0, 200)}`,
            };
        }
    } catch (err) {
        // If container was created but we error out, try to clean up.
        if (container) {
            try { await container.stop({ t: 0 }); } catch (_) {}
            try { await container.remove({ force: true }); } catch (_) {}
        }
        return {
            success: false,
            error: err.message || 'Container error',
        };
    }
};

// ---------------------------------------------------------------------------
// Stop and remove a running container by ID.
// ---------------------------------------------------------------------------
const stopContainer = async (containerId) => {
    const container = docker.getContainer(containerId);
    try { await container.stop({ t: 5 }); } catch (_) {}
    try { await container.remove({ force: true }); } catch (_) {}
};

// ---------------------------------------------------------------------------
// Check if a container is still running.
// ---------------------------------------------------------------------------
const isContainerRunning = async (containerId) => {
    try {
        const info = await docker.getContainer(containerId).inspect();
        return info.State.Running === true;
    } catch (err) {
        return false;
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse a Docker-style memory string ('256m', '1g', '512000') to bytes.
 */
const parseMemoryString = (mem) => {
    if (typeof mem === 'number') return mem;
    const str = String(mem).trim().toLowerCase();
    const match = str.match(/^(\d+(?:\.\d+)?)\s*([kmgt]?)b?$/);
    if (!match) return 256 * 1024 * 1024; // default 256MB

    const value = parseFloat(match[1]);
    const unit = match[2];
    const multipliers = { '': 1, 'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3, 't': 1024 ** 4 };
    return Math.round(value * (multipliers[unit] || 1));
};

/**
 * Parse a CPU limit string ('1', '0.5', '2') to NanoCpus.
 * Docker NanoCpus: 1 CPU = 1e9 nanoseconds.
 */
const parseCpuLimit = (cpu) => {
    const value = parseFloat(cpu);
    if (isNaN(value) || value <= 0) return 1e9;
    return Math.round(value * 1e9);
};

/**
 * Demux Docker multiplexed stream output into stdout and stderr strings.
 * Docker container logs use an 8-byte header per frame:
 *   byte 0: stream type (0=stdin, 1=stdout, 2=stderr)
 *   bytes 4-7: big-endian uint32 payload size
 */
const demuxDockerLogs = (buffer) => {
    let stdout = '';
    let stderr = '';

    // If it's a string, dockerode sometimes returns raw strings for TTY containers.
    if (typeof buffer === 'string') {
        return { stdout: buffer, stderr: '' };
    }

    const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
    let offset = 0;

    while (offset + 8 <= buf.length) {
        const streamType = buf[offset];
        const payloadSize = buf.readUInt32BE(offset + 4);
        offset += 8;

        if (offset + payloadSize > buf.length) break;

        const payload = buf.slice(offset, offset + payloadSize).toString('utf-8');
        if (streamType === 1) {
            stdout += payload;
        } else if (streamType === 2) {
            stderr += payload;
        }
        offset += payloadSize;
    }

    return { stdout, stderr };
};

/**
 * Stream logs from a running container.
 * Returns a readable stream that emits { stream: 'stdout'|'stderr', data: string } objects.
 * Caller should listen for 'data' and 'end'/'error' events.
 */
const streamContainerLogs = async (containerId) => {
    const container = docker.getContainer(containerId);
    const logStream = await container.logs({
        follow: true,
        stdout: true,
        stderr: true,
        timestamps: true,
        since: 0,
    });
    return { logStream, demuxDockerLogs };
};

module.exports = {
    isDockerAvailable,
    isImageBuilt,
    buildImage,
    ensureImage,
    runGameContainer,
    validateGame,
    stopContainer,
    isContainerRunning,
    streamContainerLogs,
    parseMemoryString,
};
