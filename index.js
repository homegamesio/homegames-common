const https = require('https');
const http = require('http');
const readline = require('readline');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const unzipper = require('unzipper');
const crypto = require('crypto');
const { Readable } = require('stream');
const os = require('os');
const process = require('process');

const DEFAULT_CONFIG = {
    "HTTPS_ENABLED": true,
    "LINK_ENABLED": true,
    "HOMENAMES_PORT": 7400,
    "HOME_PORT": 9801,
    "LOG_LEVEL": "INFO",
    "GAME_SERVER_PORT_RANGE_MIN": 8300,
    "GAME_SERVER_PORT_RANGE_MAX": 8400,
    "IS_DEMO": false,
    "BEZEL_SIZE_X": 9,
    "BEZEL_SIZE_Y": 9,
    "HOTLOAD_ENABLED": false,
    "PERFORMANCE_PROFILING": false,
    "DOWNLOADED_GAME_DIRECTORY": "hg-games",
    "LOG_PATH": "homegames_log.txt",
    "PUBLIC_GAMES": true,
    "ERROR_REPORTING": true,
    "ERROR_REPORTING_ENDPOINT": "https://api.homegames.io/bugs",
    "CERT_DOMAIN": "homegames.link",
    "TESTS_ENABLED": true,
    "API_URL": "https://api.homegames.io",
    "LINK_PROXY_URL": "wss://public.homegames.link:81",
    "LINK_URL": "wss://homegames.link",
    "MAP_ENABLED": true,
    "CHILD_SESSION_MEMORY_LIMIT": "128m"
};

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const getUrl = (url, headers = {}) => new Promise((resolve, reject) => {
    const getModule = url.startsWith('https') ? https : http;

    getModule.get(url, { headers }, (res) => {
        const bufs = [];
        res.on('data', (chunk) => { bufs.push(chunk); });
        res.on('end', () => {
            if (res.statusCode > 199 && res.statusCode < 300) {
                resolve(Buffer.concat(bufs));
            } else {
                reject(Buffer.concat(bufs));
            }
        });
    }).on('error', reject);
});

const postUrl = (url, urlPath, _payload, headers = {}) => new Promise((resolve, reject) => {
    const payload = JSON.stringify(_payload);

    let module, hostname, port;
    if (url.startsWith('https')) {
        module = https;
        port = 443;
        hostname = url.replace('https://', '');
    } else {
        module = http;
        port = 80;
        hostname = url.replace('http://', '');
    }

    Object.assign(headers, {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
    });

    let responseData = '';
    const req = module.request({ hostname, path: urlPath, port, method: 'POST', headers }, (res) => {
        res.on('data', (chunk) => { responseData += chunk; });
        res.on('end', () => { resolve(responseData); });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
});

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

const guaranteeDir = (dir) => new Promise((resolve) => {
    fs.exists(dir, (exists) => {
        if (exists) {
            resolve();
        } else {
            fs.mkdir(dir, { recursive: true }, () => { resolve(); });
        }
    });
});

const getAppDataPath = () => {
    if (!process) return '';

    let _path;
    switch (process.platform) {
        case "darwin":
            _path = process.env.HOME ? path.join(process.env.HOME, "Library", "Application Support", "homegames") : __dirname;
            break;
        case "win32":
            _path = process.env.APPDATA ? path.join(process.env.APPDATA, "homegames") : __dirname;
            break;
        case "linux":
            _path = process.env.HOME ? path.join(process.env.HOME, ".homegames") : __dirname;
            break;
        default:
            console.log("Unsupported platform!");
            process.exit(1);
    }

    if (!fs.existsSync(_path)) {
        fs.mkdirSync(_path, { recursive: true });
    }

    return _path;
};

const log = {
    info: (msg) => console.log(msg),
    error: (msg) => console.error(msg),
    debug: (msg) => console.log(msg),
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const getConfigValue = (key, _default = undefined) => {
    const config = getConfig();

    let envValue = process.env[key] && `${process.env[key]}`;
    if (envValue !== undefined) {
        if (envValue === 'true') envValue = true;
        else if (envValue === 'false') envValue = false;
        log.info(`Using environment value: ${envValue} for key: ${key}`);
        return envValue;
    }

    if (config[key] === undefined && _default === undefined) {
        throw new Error(`No value for ${key} found in config`);
    } else if (config[key] === undefined && _default !== undefined) {
        log.info(`Using default value (${_default}) for ${key}`);
        return DEFAULT_CONFIG[key] || _default;
    }
    log.info(`Found value ${config[key]} for ${key} in config`);
    return config[key];
};

let cachedConfig = {};

const getConfig = () => {
    if (Object.keys(cachedConfig).length > 0) return cachedConfig;

    const options = [getAppDataPath(), process.cwd()];
    try { options.push(path.dirname(require.main.filename)); } catch (e) {}
    try { options.push(path.dirname(process.mainModule.filename)); } catch (e) {}
    options.push(__dirname);

    let _config = null;
    for (let i = 0; i < options.length; i++) {
        try {
            if (fs.existsSync(`${options[i]}/config.json`)) {
                log.info(`Found config at ${options[i]}`);
                _config = JSON.parse(fs.readFileSync(`${options[i]}/config.json`));
                break;
            }
        } catch (e) {}
    }

    if (!_config) _config = DEFAULT_CONFIG;

    cachedConfig = _config;
    return _config;
};

// ---------------------------------------------------------------------------
// Shared modules
// ---------------------------------------------------------------------------

const gameLoader = require('./game-loader');
const dockerHelper = require('./docker-helper');
const GameSession = require('./game-session');
const GameSessionManager = require('./game-session-manager');

const getHash = (input) => {
    return crypto.createHash('md5').update(input).digest('hex');
};


// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
    // Utilities
    guaranteeDir,
    getUrl,
    getConfigValue,
    log,
    getAppDataPath,
    getHash,

    // Game loading
    gameLoader,
    squishMap: gameLoader.squishMap,
    DEFAULT_SQUISH_VERSION: gameLoader.DEFAULT_SQUISH_VERSION,

    // Docker
    dockerHelper,

    // Sessions
    GameSession,
    GameSessionManager,
};
