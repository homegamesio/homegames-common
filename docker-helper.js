const { execSync, exec, execFile, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Cache Docker availability for the process lifetime.
// ---------------------------------------------------------------------------
let _dockerAvailable = null;

const isDockerAvailable = () => {
    if (_dockerAvailable !== null) return _dockerAvailable;

    try {
        execSync('docker info', { stdio: 'ignore', timeout: 5000 });
        _dockerAvailable = true;
    } catch (err) {
        _dockerAvailable = false;
    }

    return _dockerAvailable;
};

// ---------------------------------------------------------------------------
// Check whether the homegames-runner image exists locally.
// ---------------------------------------------------------------------------
const isImageBuilt = (imageName = 'homegames-runner') => {
    try {
        const result = execSync(`docker images -q ${imageName}`, { encoding: 'utf-8', timeout: 5000 });
        return result.trim().length > 0;
    } catch (err) {
        return false;
    }
};

// ---------------------------------------------------------------------------
// Build the homegames-runner image from a Dockerfile directory.
// ---------------------------------------------------------------------------
const buildImage = (dockerfilePath, imageName = 'homegames-runner') => new Promise((resolve, reject) => {
    const dir = path.resolve(dockerfilePath);

    // If build-image.sh exists, use it — it handles copying homegames-common
    // into the build context before running docker build.
    const buildScript = path.join(dir, 'build-image.sh');
    let cmd, args, opts;

    if (fs.existsSync(buildScript)) {
        cmd = 'bash';
        args = [buildScript];
        opts = { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] };
    } else {
        cmd = 'docker';
        args = ['build', '-t', imageName, '.'];
        opts = { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] };
    }

    const proc = spawn(cmd, args, opts);

    let stderr = '';
    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    proc.stdout.on('data', () => {}); // drain stdout

    proc.on('close', (code) => {
        if (code === 0) {
            resolve();
        } else {
            reject(new Error(`Docker build failed (exit ${code}): ${stderr.slice(-500)}`));
        }
    });

    proc.on('error', reject);
});

// ---------------------------------------------------------------------------
// Ensure the image is built. Build it if missing.
// ---------------------------------------------------------------------------
const ensureImage = (dockerfilePath, imageName = 'homegames-runner') => {
    if (isImageBuilt(imageName)) return Promise.resolve();
    return buildImage(dockerfilePath, imageName);
};

// ---------------------------------------------------------------------------
// Run a game inside a Docker container for live game sessions.
//
// Options:
//   codePath      — absolute path to a directory containing the game code
//   port          — host port to map (also used as container port)
//   squishVersion — squish version string
//   saveDataPath  — absolute path to host directory for game save data (optional)
//   imageName     — Docker image name (default: 'homegames-runner')
//   memoryLimit   — memory limit (default: '256m')
//   cpuLimit      — CPU limit (default: '1')
//
// Returns: { containerId, port }
// ---------------------------------------------------------------------------
const runGameContainer = ({
    codePath,
    port,
    squishVersion,
    saveDataPath,
    imageName = 'homegames-runner',
    memoryLimit = '256m',
    cpuLimit = '1',
    gameEntryRelative = null,
}) => new Promise((resolve, reject) => {
    const args = [
        'run', '-d',
        '--cap-drop=ALL',
        `--memory=${memoryLimit}`,
        `--cpus=${cpuLimit}`,
        '--pids-limit=64',
        '--tmpfs', '/tmp:rw,size=64m',
        '-v', `${path.resolve(codePath)}:/app/game:ro`,
        '-p', `${port}:${port}`,
        '-e', `GAME_PORT=${port}`,
        '-e', `SQUISH_VERSION=${squishVersion}`,
    ];

    if (gameEntryRelative) {
        args.push('-e', `GAME_ENTRY=${gameEntryRelative}`);
    }

    // Allow the container to reach services on the Docker host (e.g. Homenames)
    args.push('--add-host', 'host.docker.internal:host-gateway');
    args.push('-e', 'DOCKER_HOST_HOSTNAME=host.docker.internal');



    console.log('yoofosdfoighdsiof');

    if (saveDataPath) {
        if (!fs.existsSync(saveDataPath)) {
            fs.mkdirSync(saveDataPath, { recursive: true });
        }
        args.push('-v', `${path.resolve(saveDataPath)}:/app/save:rw`);
    }

    args.push(imageName, 'container-entry.js');

    console.log('[docker-helper] docker run args:', JSON.stringify(args));

    execFile('docker', args, { timeout: 30000 }, (err, stdout, stderr) => {
        if (stderr) console.log('[docker-helper] stderr:', stderr);
        if (err) {
            reject(new Error(`Failed to start container: ${stderr || err.message}`));
            return;
        }

        const containerId = stdout.trim();
        if (!containerId) {
            reject(new Error(`Docker run produced no container ID. stderr: ${stderr}`));
            return;
        }

        resolve({ containerId, port });
    });
});

// ---------------------------------------------------------------------------
// Run game validation in a Docker container (for homedome).
// No networking, no port mapping, no save directory.
//
// Returns: { success: boolean, squishVersion?: string, error?: string }
// ---------------------------------------------------------------------------
const validateGame = ({
    codePath,
    squishVersion,
    imageName = 'homegames-runner',
    timeoutMs = 30000,
    memoryLimit = '256m',
}) => new Promise((resolve, reject) => {
    const args = [
        'run', '--rm',
        '--network=none',
        '--cap-drop=ALL',
        `--memory=${memoryLimit}`,
        '--cpus=0.5',
        '--pids-limit=32',
        '--read-only',
        '--tmpfs', '/tmp:rw,noexec,size=32m',
        '-v', `${path.resolve(codePath)}:/app/game:ro`,
        '-e', `SQUISH_VERSION=${squishVersion}`,
        imageName,
        'validate.js',
    ];

    execFile('docker', args, { timeout: timeoutMs }, (err, stdout, stderr) => {
        // validate.js writes JSON to stdout and exits 0 or 1.
        // On timeout or other error, treat as failure.
        if (err && !stdout) {
            resolve({
                success: false,
                error: stderr ? stderr.trim().slice(-500) : (err.message || 'Container error'),
            });
            return;
        }

        try {
            const result = JSON.parse(stdout.trim());
            resolve(result);
        } catch (parseErr) {
            resolve({
                success: false,
                error: `Failed to parse validation output: ${stdout.slice(0, 200)}`,
            });
        }
    });
});

// ---------------------------------------------------------------------------
// Stop a running container by ID.
// ---------------------------------------------------------------------------
const stopContainer = (containerId) => new Promise((resolve, reject) => {
    execFile('docker', ['stop', containerId], { timeout: 15000 }, (err) => {
        // --rm flag means the container is removed on stop.
        // If the container already stopped, docker stop may error — that's fine.
        resolve();
    });
});

// ---------------------------------------------------------------------------
// Check if a container is still running.
// ---------------------------------------------------------------------------
const isContainerRunning = (containerId) => {
    try {
        const result = execSync(
            `docker inspect -f '{{.State.Running}}' ${containerId}`,
            { encoding: 'utf-8', timeout: 5000 }
        );
        return result.trim() === 'true';
    } catch (err) {
        return false;
    }
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
};
