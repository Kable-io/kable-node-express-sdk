
const axios = require('axios');
const NodeCache = require("node-cache");

const KABLE_ENVIRONMENT_HEADER_KEY = 'KABLE-ENVIRONMENT';
const KABLE_CLIENT_ID_HEADER_KEY = 'KABLE-CLIENT-ID';
const X_CLIENT_ID_HEADER_KEY = 'X-CLIENT-ID';
const X_API_KEY_HEADER_KEY = 'X-API-KEY';
const AUTHORIZATION_KEY = 'Authorization';

function kable(config) {
  return new Kable(config).authenticate;
}

class Kable {

  constructor(config) {

    console.log("Initializing Kable");

    if (!config) {
      // throw new Error('Failed to initialize Kable: config not provided');
      console.error('Failed to initialize Kable: config not provided');
    }

    this.environment = config.environment;
    this.kableClientId = config.clientId;
    this.kableClientSecret = config.clientSecret;
    this.baseUrl = config.baseUrl;

    if (!this.environment) {
      // throw new Error('Failed to initialize Kable: environment not provided');
      console.error('Failed to initialize Kable: environment not provided');
    }
    if (!this.kableClientId) {
      // throw new Error('Failed to initialize Kable: clientId not provided');
      console.error('Failed to initialize Kable: clientId not provided');
    }
    if (!this.kableClientSecret) {
      // throw new Error('Failed to initialize Kable: clientSecret not provided');
      console.error('Failed to initialize Kable: clientSecret not provided');
    }
    if (!this.baseUrl) {
      // throw new Error('Failed to initialize Kable: baseUrl not provided');
      console.error('Failed to initialize Kable: baseUrl not provided');
    }

    this.validCache = new NodeCache({ stdTTL: 10, maxKeys: 1000, checkperiod: 120 });
    this.invalidCache = new NodeCache({ stdTTL: 10, maxKeys: 1000, checkperiod: 120 });

    this.kableEnvironment = this.environment.toLowerCase() === 'live' ? 'live' : 'test';

    axios({
      url: `https://${this.kableEnvironment}.kableapi.com/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment,
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId,
        [X_CLIENT_ID_HEADER_KEY]: this.kableClientId,
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret,
        [AUTHORIZATION_KEY]: `Bearer ${this.kableClientSecret}`
      }
    })
      .then(response => {
        if (response.status === 200) {
          // proceed with initialization
        } else if (response.status === 401) {
          // throw new Error('Failed to initialize Kable: Unauthorized');
          console.error('Failed to initialize Kable: Unauthorized');
        } else {
          // throw new Error('Failed to initialize Kable: Something went wrong');
          console.error('Failed to initialize Kable: Something went wrong');
        }

        console.log("Kable initialized successfully");
      })
      .catch(error => {
        // throw new Error('Failed to initialize Kable: Something went wrong');
        console.error('Failed to initialize Kable: Something went wrong', error);
      });
  }


  authenticate(req, res, next) {
    // const method = req.method;
    const xClientId = req.get(X_CLIENT_ID_HEADER_KEY);
    let secretKey = req.get(X_API_KEY_HEADER_KEY);
    if (!secretKey) {
      if (req.headers && req.headers.authorization) {
        const authorizationParts = req.headers.authorization.split(' ');
        if (authorizationParts.length == 2) {
          const scheme = authorizationParts[0];
          const credentials = authorizationParts[1];
          if (/^Bearer$/i.test(scheme)) {
            secretKey = credentials;
          }
        }
      }
    }

    if (!this.environment || !this.kableClientId) {
      return res.status(500).json({ message: 'Failed to initialize Kable: Configuration invalid' });
    }

    if (/*!this.environment || !this.kableClientId ||*/ !xClientId || !secretKey) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId) {
      return next(req);
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    axios({
      url: `https://${this.kableEnvironment}.kableapi.com/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment,
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId,
        [X_CLIENT_ID_HEADER_KEY]: xClientId,
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret,
        [AUTHORIZATION_KEY]: `Bearer: ${secretKey}`
      },
      data: req.body
    })
      .then(response => {
        if (response.status % 100 == 2) {
          this.validCache.set(secretKey, xClientId);
          return next(req);
        }

        if (response.status % 100 == 4) {
          this.invalidCache.set(secretKey, xClientId);
          return res.status(401).json({ message: 'Unauthorized' });
        }

        return res.status(response.status).json({ message: 'Unexpected response' });
      })
      .catch(error => {
        return res.status(500).json({ message: 'Something went wrong' });
      });
  }

}

module.exports = {
  kable
}
