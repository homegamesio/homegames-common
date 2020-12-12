const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const AWS = require('aws-sdk');

const getUrl = (url) => new Promise((resolve, reject) => {
    const getModule = url.startsWith('https') ? https : http;

    let responseData = '';

    getModule.get(url, (res) => {
        res.on('data', (chunk) => {
            responseData += chunk;
        });

        res.on('end', () => {
            if (res.statusCode > 199 && res.statusCode < 300) {
                resolve(responseData);
            } else {
                reject(responseData);
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

    const options = {
        hostname,
        path,
        port,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length
        }
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

const validateCertData = (certPaths) => new Promise((resolve, reject) => {
    console.log('need to check');
    console.log(certPaths.certPath);
    console.log(certPaths.keyPath);

});

const validateExistingCerts = (certPath) => new Promise((resolve, reject) => {
    guaranteeDir(certPath).then(() => {
        guaranteeCertFiles(certPath).then((certPaths) => {
            validateCertData(certPaths).then(() => {
                resolve();
            }).catch(err => {
                reject(err);
            });
        }).catch(err => {
            reject(err);
        });
    }).catch(err => {
        reject(err);
    });
});

const guaranteeLoginFile = (loginPath) => new Promise((resolve, reject) => {
    fs.exists(path.join(loginPath, 'config'), (exists) => {
        console.log('exists');
        if (exists) {
            resolve();
        } else {
            reject();
        }
    });
});

const validateLoginData = (loginPath) => new Promise((resolve, reject) => {
    guaranteeDir(loginPath).then(() => {
        console.log("made login path");
        guaranteeLoginFile(loginPath).then((loginData) => {
            console.log('guarantyeed ogin fie');
            resolve(loginData);
        }).catch(() => {
            reject('could not find login file');
        });
    });
});

const certInit = (certPath, loginPath) => new Promise((resolve, reject) => {
    validateExistingCerts(certPath).then((certData) => {
        console.log("GOT CERT DATA AT ");
        console.log(certData);
    }).catch(err => {
        console.log("ERRRRO");
        console.log(err);
        validateLoginData(loginPath).then((loginData) => {
            console.log("LOGIN DATA");
            console.log(loginData);
            getUrl('https://certifier.homegames.link/get-certs').then(data => {
                console.log("GOT AHT");
                console.log(data);
                resolve();
            }).catch(err => {
                console.error("Could not fetch cert");
                console.error(err);
            });
        }).catch(err => {
            reject(err);
        });
    });
});

const invokeLambda = (functionName, region, _params) => new Promise((resolve, reject) => {
    console.log("REGION");
    console.log(region);
    const lambda = new AWS.Lambda({ region });

    const params = {
        FunctionName: functionName,
        Payload: JSON.stringify(_params)
    };

    lambda.invoke(params, (err, _data) => {
        if (err) {
            reject(err);
        } else {
            resolve(_data.Payload);
        }
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
    console.log('dsfdsfdsbn');
    postUrl('https://auth.homegames.io', '/', {
        type: 'login',
        username,
        password
    }).then(data => {
        console.log(data);
        resolve(JSON.parse(data));
    });
    
});



module.exports = {
    certInit,
    signup,
    login,
    confirmUser
};
