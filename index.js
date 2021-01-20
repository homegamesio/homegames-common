const https = require('https');
const readline = require('readline');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const AWS = require('aws-sdk');
const unzipper = require('unzipper');
const crypto = require('crypto');
const { Readable } = require('stream');
const os = require('os');

const getUserHash = (username) => {
    return crypto.createHash('md5').update(username).digest('hex');
};

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
            if (file === 'fullchain.pem') {
                certPath = path.join(dir, file);
            }

            if (file === 'privkey.pem') {
                keyPath = path.join(dir, file);
            }
        });
    
        if (!certPath) {
            reject('Could not find fullchain.pem');
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
    postUrl('https://certifier.homegames.link', '/verify', {
        checksum: ''
    },
    {
        'hg-username': username,
        'hg-access-token': accessToken
    }).then(data => {
        resolve(data);
    }).catch(err => {
        reject({
            message: err.toString()
        });
    });

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
            getUrl('https://certifier.homegames.link/get-certs').then(data => {
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

    getUrl('https://certifier.homegames.link/get-certs', {

        'hg-username': username,
        'hg-access-token': accessToken
    }).then(data => {
        resolve(data);
    }).catch(err => {
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

    certStream.pipe(unzipper.Extract({ path }));

    resolve();
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

    getLoginInfo(authPath).then(info => {
        validateExistingCerts(certPath, info.username, info.tokens.accessToken).then(() => {
            resolve({
                certPath: certPath + '/fullchain.pem',
                keyPath: certPath + '/privkey.pem'
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
        const client = new WebSocket('wss://www.homegames.link:7080');

        client.on('open', () => {
            console.log('opened connection to link');
            client.send(JSON.stringify({
                ip: getLocalIP(),
                username: loginInfo.username,
                accessToken: loginInfo.tokens.accessToken
            }));
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

module.exports = {
    guaranteeCerts,
    certInit,
    getCertData,
    signup,
    login,
    confirmUser,
    validateExistingCerts,
    getLoginInfo,
    verifyAccessToken,
    refreshAccessToken,
    storeCertData,
    linkInit,
    storeTokens,
    promptLogin,
    getUserHash
};
