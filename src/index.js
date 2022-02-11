const packageJson = require('../package.json')
const axios = require('axios');
const uuidv4 = require("uuid4");
const NodeCache = require("node-cache");

const KABLE_ENVIRONMENT_HEADER_KEY = 'KABLE-ENVIRONMENT';
const KABLE_CLIENT_ID_HEADER_KEY = 'KABLE-CLIENT-ID';
const X_CLIENT_ID_HEADER_KEY = 'X-CLIENT-ID';
const X_API_KEY_HEADER_KEY = 'X-API-KEY';
const X_USER_ID_KEY = 'X-USER-ID';
const X_REQUEST_ID_HEADER_KEY = 'X-REQUEST-ID';

function kable(config) {
  return new Kable(config).authenticate;
}

class Kable {

  constructor(config) {

    console.log("Initializing Kable");

    if (!config) {
      throw new Error('Failed to initialize Kable: config not provided');
      // console.error('Failed to initialize Kable: config not provided');
    }

    this.environment = config.environment;
    this.kableClientId = config.clientId;
    this.kableClientSecret = config.clientSecret;
    this.baseUrl = config.baseUrl;

    if (!this.environment) {
      throw new Error('Failed to initialize Kable: environment not provided');
      // console.error('Failed to initialize Kable: environment not provided');
    }
    if (!this.kableClientId) {
      throw new Error('Failed to initialize Kable: clientId not provided');
      // console.error('Failed to initialize Kable: clientId not provided');
    }
    if (!this.kableClientSecret) {
      throw new Error('Failed to initialize Kable: clientSecret not provided');
      // console.error('Failed to initialize Kable: clientSecret not provided');
    }
    if (!this.baseUrl) {
      throw new Error('Failed to initialize Kable: baseUrl not provided');
      // console.error('Failed to initialize Kable: baseUrl not provided');
    }

    this.queue = [];
    this.queueFlushInterval = 10000; // 10 seconds
    this.queueMaxCount = 10; // 10 requests

    this.validCache = new NodeCache({ stdTTL: 30, maxKeys: 1000, checkperiod: 300 });
    this.invalidCache = new NodeCache({ stdTTL: 30, maxKeys: 1000, checkperiod: 300 });


    this.kableEnvironment = this.environment.toLowerCase() === 'live' ? 'live' : 'test';

    axios({
      url: `https://${this.kableEnvironment}.kableapi.com/api/authenticate`,
      // url: `http://localhost:8080/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
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
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            console.error('Failed to initialize Kable: Unauthorized');
          } else {
            console.warn(`Failed to initialize Kable: Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
          }
        } else {
          console.error('Failed to initialize Kable: Something went wrong');
        }
      });
  }


  authenticate = (req, res, next) => {
    // const method = req.method;
    const clientId = req.get(X_CLIENT_ID_HEADER_KEY);
    const secretKey = req.get(X_API_KEY_HEADER_KEY);
    const requestId = uuidv4();

    this.enqueueMessage(clientId, requestId, req);

    if (!this.environment || !this.kableClientId) {
      return res.status(500).json({ message: 'Unauthorized. Failed to initialize Kable: Configuration invalid' });
    }

    if (!clientId || !secretKey) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId && validCacheClientId === clientId) {
      // console.debug("Valid Cache Hit");
      res.locals.requestId = requestId;
      return next();
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId && invalidCacheClientId === clientId) {
      // console.debug("Invalid Cache Hit");
      return res.status(401).json({ message: 'Unauthorized' });
    }

    // console.debug("Authenticating at server");
    axios({
      url: `https://${this.kableEnvironment}.kableapi.com/api/authenticate`,
      // url: `http://localhost:8080/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_CLIENT_ID_HEADER_KEY]: clientId || '',
        [X_API_KEY_HEADER_KEY]: secretKey || '',
        [X_REQUEST_ID_HEADER_KEY]: requestId || '',
      },
      data: req.body
    })
      .then(response => {
        const status = response.status;

        if (status >= 200 && status < 300) {
          this.validCache.set(secretKey, clientId);
          res.locals.requestId = requestId;
          return next();
        }

        console.warn(`Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
        return res.status(401).json({ message: 'Unauthorized' });
      })
      .catch(error => {
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            this.invalidCache.set(secretKey, clientId);
            return res.status(401).json({ message: 'Unauthorized' });
          }

          console.warn(`Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
          return res.status(500).json({ message: 'Something went wrong' });
        }
        else return res.status(500).json({ message: 'Something went wrong' });
      });
  }

  enqueueMessage = (clientId, requestId, req) => {
    const message = {};
    message['library'] = packageJson.name;
    message['libraryVersion'] = packageJson.version;
    message['created'] = new Date();
    message['requestId'] = requestId;

    message['environment'] = this.environment;
    message['kableClientId'] = this.kableClientId;
    message['clientId'] = clientId;
    const xUserId = req.get(X_USER_ID_KEY);
    if (xUserId) {
      message['userId'] = xUserId;
    }

    const request = {};
    request['url'] = req.url;
    request['method'] = req.method;
    // request['headers'] = req.headers;
    // request['body'] = req.body;
    message['request'] = request;

    this.queue.push(message);

    if (this.queue.length >= this.queueMaxCount) {
      this.flushQueue();
      return;
    }

    if (this.queueFlushInterval && !this.timer) {
      this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
    }
  }

  flushQueue = () => {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.queue.length) {
      const messages = this.queue.splice(0, this.queueMaxCount);

      axios({
        url: `https://${this.kableEnvironment}.kableapi.com/api/requests`,
        // url: `http://localhost:8080/api/requests`,
        method: 'POST',
        headers: {
          [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
          [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
        },
        data: messages
      })
        .then(() => {
          console.debug(`Successfully sent ${messages.length} messages to Kable server`);
        })
        .catch(error => {
          console.error(`Failed to send ${messages.length} messages to Kable server`);
        })
    } else {
      // console.debug('...no messages to flush...');
    }

    this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
  }

}


module.exports = {
  kable
}
