const NodeCache = require("node-cache");

const KABLE_ENVIRONMENT_HEADER_KEY = 'KABLE-ENVIRONMENT';
const KABLE_CLIENT_ID_HEADER_KEY = 'KABLE-CLIENT-ID';
const X_CLIENT_ID_HEADER_KEY = 'X-CLIENT-ID';
const X_API_KEY_HEADER_KEY = 'X-API-KEY';
const AUTHORIZATION_KEY = 'Authorization';


// const kable = (config) => {
//   return new Kable(config);
// }
function kable(config) {
  return new Kable(config);
}

class Kable {

  constructor(config) {
    if (!config) {
      throw new Error('Failed to initialize Kable: config not provided');
    }

    this.environment = config.environment;
    this.kableClientId = config.clientId;
    this.kableClientSecret = config.clientSecret;
    this.baseUrl = config.baseUrl;

    if (!this.environment) {
      throw new Error('Failed to initialize Kable: environment not provided');
    }
    if (!this.kableClientId) {
      throw new Error('Failed to initialize Kable: clientId not provided');
    }
    if (!this.kableClientSecret) {
      throw new Error('Failed to initialize Kable: clientSecret not provided');
    }
    if (!this.baseUrl) {
      throw new Error('Failed to initialize Kable: baseUrl not provided');
    }

    this.validCache = new NodeCache({ stdTTL: 10, maxKeys: 1000, checkperiod: 120 });
    this.invalidCache = new NodeCache({ stdTTL: 10, maxKeys: 1000, checkperiod: 120 });

    this.kableEnvironment = this.environment.toLowerCase() === 'production' ? 'live' : 'test';

    fetch(`https://${this.kableEnvironment}.kableapi.com/api/authenticate`, // TODO: maybe call a different endpoint for kableClient initialization
      {
        method: 'POST',
        headers: {
          [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment,
          [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId,
          [X_CLIENT_ID_HEADER_KEY]: this.kableClientId,
          [X_API_KEY_HEADER_KEY]: this.kableClientSecret,
          [AUTHORIZATION_KEY]: `Bearer: ${this.kableClientSecret}`
        },
        // credentials: 'include',
        // body: req.body,
      })
      .then(response => {
        if (response.status === 200) {
          // proceed with initialization
        } else if (response.status === 401) {
          throw new Error('Failed to initialize Kable: Unauthorized');
        } else {
          throw new Error('Failed to initialize Kable: Something went wrong');
        }
      })
      .catch(error => {
        throw new Error('Failed to initialize Kable: Something went wrong');
      });
  }


  authenticate(req, res, next) {
    const method = req.method;
    const xClientId = req.get(X_CLIENT_ID_HEADER_KEY);
    const xApiKey = req.get(X_API_KEY_HEADER_KEY);
    const secretKey = xApiKey ? xApiKey : getBearerToken(req);

    if (/*!this.environment || !this.kableClientId ||*/ !xClientId || !secretKey) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId) {
      // return res.status(200).json({ client_id: validCacheClientId });
      return next();
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    return fetch(`https://${this.kableEnvironment}.kableapi.com/api/authenticate`,
      {
        method: method,
        headers: {
          [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment,
          [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId,
          [X_CLIENT_ID_HEADER_KEY]: xClientId,
          [AUTHORIZATION_KEY]: `Bearer: ${secretKey}`
        },
        credentials: 'include',
        body: req.body,
      })
      .then(response => {
        if (response.status % 100 == 2) {
          this.validCache.set(secretKey, xClientId);
          // return res.status(200).json({ client_id: xClientId });
          return next();
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


  getBearerToken(req) {
    if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          return credentials;
        }
      }
    }
    return null;
  }

}

module.exports = {
  kable
}
