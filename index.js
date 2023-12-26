const https = require('https');
const readline = require('readline');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const unzipper = require('unzipper');
const crypto = require('crypto');
const { Readable } = require('stream');
const os = require('os');
const process = require('process');

const getUserHash = (username) => {
    return crypto.createHash('md5').update(username).digest('hex');
};

const DEFAULT_CONFIG = {
    "LINK_ENABLED": true,
    "HTTPS_ENABLED": true,
    "HOMENAMES_PORT": 7400,
    "HOME_PORT": 9801,
    "LOG_LEVEL": "INFO",
    "GAME_SERVER_PORT_RANGE_MIN": 8300,
    "GAME_SERVER_PORT_RANGE_MAX": 8400,
    "IS_DEMO": false,
    "BEZEL_SIZE_Y": 15,
    "BEZEL_SIZE_X": 15,
    "PUBLIC_GAMES": true,
    "DOWNLOADED_GAME_DIRECTORY": "hg-games",
    "LOG_PATH": "hg_log.txt"
}

const getLocalIP = () => {
    const ifaces = os.networkInterfaces();
    let localIP;

    Object.keys(ifaces).forEach((ifname) => {
        ifaces[ifname].forEach((iface) => {
            if ('IPv4' !== iface.family || iface.internal) {
                return;
            }
            localIP = localIP || iface.address;
        });
    });

    return localIP;
};

const getUrl = (url, headers = {}) => new Promise((resolve, reject) => {
    const getModule = url.startsWith('https') ? https : http;

    let responseData = '';

    getModule.get(url, { headers } , (res) => {
        const bufs = [];
        res.on('data', (chunk) => {
            bufs.push(chunk);
        });

        res.on('end', () => {
            if (res.statusCode > 199 && res.statusCode < 300) {
                resolve(Buffer.concat(bufs));
            } else {
                reject(Buffer.concat(bufs));
            }
        });
    }).on('error', error => {
        reject(error);
    });
 
});

const postUrl = (url, path, _payload, headers = {}) => new Promise((resolve, reject) => {
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

    const options = {
        hostname,
        path,
        port,
        method: 'POST',
        headers
    };

    let responseData = '';
    
    const req = module.request(options, (res) => {
        res.on('data', (chunk) => {
            responseData += chunk;
        });

        res.on('end', () => {
            resolve(responseData);
        });
    });

    req.write(payload);
    req.end();
});

const guaranteeDir = (dir) => new Promise((resolve, reject) => {
    fs.exists(dir, (exists) => {
        if (exists) {
            resolve();
        } else {
            fs.mkdir(dir, (thing) => {
                resolve();
            });
        }
    });
});

const guaranteeCertFiles = (dir) => new Promise((resolve, reject) => {

    let certPath, keyPath;

    fs.readdir(dir, (err, files) => {
        files.forEach(file => {
            if (file === 'cert.pem') {
                certPath = path.join(dir, file);
            }

            if (file === 'key.pem') {
                keyPath = path.join(dir, file);
            }
        });
    
        if (!certPath) {
            reject('Could not find cert.pem');
        }

        if (!keyPath) {
            reject('Could not find key.pem');
        }

        resolve({
            certPath,
            keyPath
        });
    });

});

const validateCertData = (certPaths, username, accessToken) => new Promise((resolve, reject) => {
	// one day
	resolve(JSON.stringify({success: true}));
//    postUrl('https://certifier.homegames.io', '/verify', {
//        checksum: ''
//    },
//    {
//        'hg-username': username,
//        'hg-access-token': accessToken
//    }).then(data => {
//        resolve(data);
//    }).catch(err => {
//        reject({
//            message: err.toString()
//        });
//    });

});

const validateExistingCerts = (certPath, username, accessToken) => new Promise((resolve, reject) => {
    guaranteeDir(certPath).then(() => {
        guaranteeCertFiles(certPath).then((certPaths) => {
            validateCertData(certPath, username, accessToken).then((response) => {
                const data = JSON.parse(response);
                if (data.success) {
                    resolve(); 
                } else {
                    getCertData(username, accessToken).then(certData => {
                        validateCertData(certPath, username, accessToken).then((response) => {
                            const data = JSON.parse(response);
                            if (data.success) {
                                storeCertData(certData, certPath).then(() => {
                                    resolve(); 
                                });
                            } else {
                                reject(data);
                            }
                        });
                    });
                }
            }).catch(err => {
                console.log(err);
                reject(err);
            });
        }).catch(err => {
            console.log(err);
            getCertData(username, accessToken).then(certData => {
                validateCertData(certPath, username, accessToken).then((response) => {
                    const data = JSON.parse(response);
                    if (data.success) {
                        storeCertData(certData, certPath).then(() => {
                            resolve(); 
                        });
                    } else {
                        reject(data);
                    }
                });
            });
        });
    });
});

const guaranteeLoginFile = (loginPath) => new Promise((resolve, reject) => {
    fs.exists(path.join(loginPath, 'config'), (exists) => {
        if (exists) {
            resolve();
        } else {
            reject();
        }
    });
});

const validateLoginData = (loginPath) => new Promise((resolve, reject) => {
    guaranteeDir(loginPath).then(() => {
        guaranteeLoginFile(loginPath).then((loginData) => {
            resolve(loginData);
        }).catch(() => {
            reject('could not find login file');
        });
    });
});

const certInit = (certPath, loginPath) => new Promise((resolve, reject) => {
    validateExistingCerts(certPath).then((certData) => {
    }).catch(err => {
        validateLoginData(loginPath).then((loginData) => {
            getUrl('https://certifier.homegames.io/get-certs').then(data => {
                resolve(data);
            }).catch(err => {
            });
        }).catch(err => {
            reject(err);
        });
    });
});

const signup = (username, email, password) => new Promise((resolve, reject) => {
    postUrl('https://auth.homegames.io', '/', {
        email,
        username,
        password,
        type: 'signUp'
    }).then(data => {
        resolve(data);
    });
});

const confirmUser = (username, code) => new Promise((resolve, reject) => {
    postUrl('https://auth.homegames.io', '/', {
        username,
        code,
        type: 'confirmUser'
    }).then(data => {
        resolve(data);
    });
});

const login = (username, password) => new Promise((resolve, reject) => {
    postUrl('https://auth.homegames.io', '/', {
        type: 'login',
        username,
        password
    }).then(_data => {
        const data = JSON.parse(_data);
        if (data.errorType) {
            reject(data);
        } else {
            resolve(data);
        }
    });
});

const refreshAccessToken = (username, tokens) => new Promise((resolve, reject) => {
    postUrl('https://auth.homegames.io', '/', {
        type: 'refresh',
        username, 
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        idToken: tokens.idToken
    }).then(_data => {
        const data = JSON.parse(_data);
        if (data.accessToken && data.refreshToken) {
            resolve(data);
        } else {
            reject();
        }
    });
});

const verifyAccessToken = (username, accessToken) => new Promise((resolve, reject) => {
    postUrl('https://auth.homegames.io', '/', {
        type: 'verify',
        username, 
        accessToken
    }).then(_data => {
        const data = JSON.parse(_data);
        if (data.errorType) {
            reject(data);
        } else {
            resolve(data);
        }
    });
});

const getLoginInfo = (authPath) => new Promise((resolve, reject) => {
    fs.exists(authPath, (exists) => {
        if (exists) {
            fs.readFile(authPath, (err, _data) => {
                let data;

                if (!_data) {
                    reject({type: 'DATA_NOT_FOUND'});
                }

                try {
                    data = JSON.parse(_data);
                    if (!data.username || !data.tokens || data.errorType) {
                        throw new Error();
                    }
                } catch (err) {
                    reject({
                        type: 'DATA_READ_ERROR',
                        message: err
                    });
                }

                if (err) {
                    reject({
                        type: 'DATA_READ_ERROR',
                        message: err
                    });
                }

                resolve(data);
            });
        } else {
            reject({type: 'DATA_NOT_FOUND'});
        }
    });
});

const getCertData = (username, accessToken) => new Promise((resolve, reject) => {

    getUrl('https://certifier.homegames.io/get-cert', {

        'hg-username': username,
        'hg-token': accessToken
    }).then(data => {
        resolve(data);
    }).catch(err => {
	    console.log(err.toString());
	    console.log('that was an error');
    });
});

const bufToStream = (buf) => {
    return new Readable({
        read() {
            this.push(buf);
            this.push(null);
        }
    });
};

// unzip a cert bundle to the given path
const storeCertData = (certBundle, path) => new Promise((resolve, reject) => {
    const certStream = bufToStream(certBundle);

    const unzip = unzipper.Extract({ path });
    certStream.pipe(unzip);

    unzip.on('close', resolve);
});

const storeTokens = (path, username, tokens) => new Promise((resolve, reject) => {
    const pathPieces = path.split('/');
    let pathParent = [];
    for (let x in pathPieces) {
        if (x == pathPieces.length - 1) {
            break
        } else {
            pathParent.push(pathPieces[x]);
        }
    }

    guaranteeDir(pathParent.join('/')).then(() => {
        const authData = {
            username,
            tokens
        };
        fs.writeFile(path, JSON.stringify(authData), (err) => {
            if (err) {
                reject('Failed to store tokens');
            } else {
                resolve();
            }
        });
    });
});

const guaranteeCerts = (authPath, certPath) => new Promise((resolve, reject) => {

    authWorkflow(authPath).then(authInfo => {
        getCertData(authInfo.username, authInfo.tokens.accessToken).then(certData => {
            validateCertData(certPath, authInfo.username, authInfo.tokens.accessToken).then((response) => {
                const data = JSON.parse(response);
                if (data.success) {
                    storeCertData(certData, certPath).then(() => {
                        resolve({
                            certPath: `${certPath}/cert.pem`,
                            keyPath: `${certPath}/key.pem`,
                        }); 
                    });
                } else {
                    reject(data);
                }
            });
        }).catch(err => {
            reject({message: err});
        });
    }).catch(err => {
        console.log(err);
    });
});

const linkInit = (authPath) => new Promise((resolve, reject) => {

    getLoginInfo(authPath).then((loginInfo) => {
        const client = new WebSocket('wss://homegames.link:7080');

        client.on('open', () => {
            console.log('opened connection to link');
            client.send(JSON.stringify({
                ip: getLocalIP(),
                username: loginInfo.username,
                accessToken: loginInfo.tokens.accessToken
            }));
        });

        client.on('error', (err) => {
            console.log('some error happened');
            console.log(err);
        });
    });

});

const promptLogin = () => new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    }); 

    rl.question('username:\n', (username) => {
        rl.question('password:\n', (password) => {
            resolve({
                username,
                password
            });
        });
    });
});

const lockFile = (path) => new Promise((resolve, reject) => {
    
    let _interval;

    const acquireLock = () => {
        const lockPath = `${path}.hglock`;
        fs.exists(lockPath, (exists) => {
            if (!exists) {
const pathPieces = path.split('/');
    let pathParent = [];
    for (let x in pathPieces) {
        if (x == pathPieces.length - 1) {
            break
        } else {
            pathParent.push(pathPieces[x]);
        }
    }

    guaranteeDir(pathParent.join('/')).then(() => {
	    console.log("writing lock file");
	    console.log(lockPath);
                fs.writeFile(lockPath, 'lock', 'utf-8', () => {
                    clearInterval(_interval);
                    fs.readFile(lockPath, (err, data) => {
                        if (err) {
                            console.log(err);
                            reject(err);
                        } else {
                                resolve();
                        }
                    });
                });
    });
            } else {
		    console.log('waiting for lock');
                const { birthtime } = fs.statSync(lockPath);
                const fiveMinsAgo = Date.now() - ( 1000 * 60 * 5 );
                console.log(birthtime);
                if (new Date(birthtime).getTime() < fiveMinsAgo) {
                    fs.unlink(lockPath, (err) => {
                        console.log(err);
                        console.log('deleted');
                    });
                }
            }
        });
        
    };

    _interval = setInterval(acquireLock, 1000);
});

const unlockFile = (path) => new Promise((resolve, reject) => {
    const lockPath = `${path}.hglock`;

    fs.readFile(lockPath, (err, data) => {
            fs.unlink(lockPath, (err) => {
                if (!err) {
                    resolve();
                } else {
                    reject('Could not delete lock');
                }
            });
    });
});

const authWorkflow = (authPath) => new Promise((resolve, reject) => {
    if (!authPath) {
        reject(`No authPath provided`);
    }

    const _doLogin = () => {
        promptLogin().then((loginInfo) => {
            login(loginInfo.username, loginInfo.password).then(tokens => {
                storeTokens(authPath, loginInfo.username, tokens).then(() => {
                    verifyAccessToken(loginInfo.username, tokens.accessToken).then(() => {
                        unlockFile(authPath).then(() => {
                            resolve({
                                username: loginInfo.username,
                                tokens
                            });
                        });
    
                    });
                }).catch(err => {
                    console.log('Failed to store auth tokens');
                    reject(err);
                });
            }).catch(err => {
                console.log('Failed to login');
                reject(err);
            });
        });
    };

	console.log('about to lock ' + authPath);
    lockFile(authPath).then(() => {
        getLoginInfo(authPath).then((loginInfo) => {
            verifyAccessToken(loginInfo.username, loginInfo.tokens.accessToken).then(() => {
                unlockFile(authPath).then(() => {
                    resolve(loginInfo);
                });
            }).catch(err => {
                console.log('failed to verify access token');
                _doLogin();
            });
        }).catch((err) => {
            console.log(err);
            if (err.type === 'DATA_NOT_FOUND') {
                _doLogin(); 
            }
        });
    }).catch(err => {
        console.log(err);
        console.log("Failed to acquire lock");
    });
});

const getConfigValue = (key, _default = undefined) => {
    const config = getConfig();

    let envValue = process.env[key] && `${process.env[key]}`;
    if (envValue !== undefined) {
        if (envValue === 'true') {
            envValue = true;
        } else if (envValue === 'false') {
            envValue = false;
        }
        console.log(`Using environment value: ${envValue} for key: ${key}`);
        return envValue;
    }
        if (config[key] === undefined && _default === undefined) {
            throw new Error(`No value for ${key} found in config`);
        } else if (config[key] === undefined && _default !== undefined) {
            return _default;
        }
        console.log(`Found value ${config[key]} in config`);
        return config[key];
};

let cachedConfig = {};

const getConfig = () => {

    if (Object.keys(cachedConfig).length > 0) {
        return cachedConfig;
    }

    const options = [process.cwd(), require.main.filename, process.mainModule.filename, __dirname]
    let _config = null;
    
    for (let i = 0; i < options.length; i++) {
        if (fs.existsSync(`${options[i]}/config.json`)) {
            console.log(`Using config at ${options[i]}`);
            _config = JSON.parse(fs.readFileSync(`${options[i]}/config.json`));
            break;
        }
    }

    if (!_config) {
        _config = DEFAULT_CONFIG;
    }

    console.log('Using config: ');
    console.log(_config);

    cachedConfig = _config;

    return _config;
}


const getLogLevel = (logLevel = null) => {
    const _logLevel = logLevel || getConfigValue('LOG_LEVEL', 'INFO');
    const levelList = ['DISABLED', 'INFO', 'DEBUG'];

    return levelList.indexOf(_logLevel);
};

const msgToString = (msg) => {
    return typeof msg === 'object' ? JSON.stringify(msg) : msg;
};

let electronLogger = null;

if (process.env.LOGGER_LOCATION) {
    try {
        electronLogger = require(process.env.LOGGER_LOCATION);
    } catch (err) { 
        console.log('Logger not using electron. Logging to file.');
    }
}

const log = {
    info: (msg, explanation = null) => {
        if (electronLogger) {
            electronLogger.info(msgToString(msg));
        }// else {
            const logLevel = getLogLevel();
            const required = getLogLevel('INFO');

            if (logLevel < required) {
//                return;
            }

            const logPath = path.join(getAppDataPath(), 'hg-log.txt');//getConfigValue('LOG_PATH', 'hg_log.txt');

            const msgString = `[HOMEGAMES-INFO][${new Date().toTimeString()}] ${msgToString(msg)}${explanation ? ':' + os.EOL + msgToString(explanation) : ''}${os.EOL}${os.EOL}`;
            fs.appendFile(logPath, msgString, (err) => {
                if (err) {
                    console.error('failed log');
                    console.log(err);
                }
            });
        //}
    },
    error: (msg, explanation) => {
        if (electronLogger) {
            electronLogger.error(msgToString(msg));
        }// else {
            const logLevel = getLogLevel();
            const required = getLogLevel('INFO');

            if (logLevel < required) {
            //    return;
            }

            //const logPath = getConfigValue('LOG_PATH', 'hg_log.txt');
            const logPath = path.join(getAppDataPath(), 'hg-log.txt');//getConfigValue('LOG_PATH', 'hg_log.txt');

            const msgString = `[HOMEGAMES-ERROR][${new Date().toTimeString()}] ${msgToString(msg)}${explanation ? ':' + os.EOL + msgToString(explanation) : ''}${os.EOL}${os.EOL}`;
            fs.appendFile(logPath, msgString, (err) => {
                if (err) {
                    console.error('failed log');
                    console.log(err);
                }
            });
        //}
    },
    debug: (msg, explanation) => {
        const logLevel = getLogLevel();
        const required = getLogLevel('DEBUG');

        const logPath = getConfigValue('LOG_PATH', 'hg_log.txt');
        
        if (logLevel < required) {
            return;
        }

        const msgString = `[HOMEGAMES-DEBUG][${new Date().toTimeString()}] ${msgToString(msg)}${explanation ? ':' + os.EOL + msgToString(explanation) : ''}${os.EOL}${os.EOL}`;
        fs.appendFile(logPath, msgString, (err) => {
            if (err) {
                console.error('failed log');
                console.log(err);
            }
        });

    }

}

const getAppDataPath = () => {
  if (!process) {
    // this shouldnt be called if running in browser
    return '';
  }

  switch (process.platform) {
    case "darwin": {
      return process.env.HOME ? path.join(process.env.HOME, "Library", "Application Support", "homegames") : __dirname;
    }
    case "win32": {
      return process.env.APPDATA ? path.join(process.env.APPDATA, "homegames") : __dirname;
    }
    case "linux": {
      return process.env.HOME ? path.join(process.env.HOME, ".homegames") : __dirname;
    }
    default: {
      console.log("Unsupported platform!");
      process.exit(1);
    }
  }
}

module.exports = {
    signup,
    login,
    confirmUser,
    getLoginInfo,
    verifyAccessToken,
    refreshAccessToken,
    linkInit,
    getUserHash,
    authWorkflow,
    guaranteeDir,
    getUrl,
    getConfigValue,
    log,
    getAppDataPath
};

