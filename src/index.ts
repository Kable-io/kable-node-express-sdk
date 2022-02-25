import packageJson from '../package.json'
import express from "express";
import axios from "axios";
import NodeCache from "node-cache";

const KABLE_ENVIRONMENT_HEADER_KEY = 'KABLE-ENVIRONMENT';
const KABLE_CLIENT_ID_HEADER_KEY = 'KABLE-CLIENT-ID';
const KABLE_CLIENT_SECRET_HEADER_KEY = 'KABLE-CLIENT-SECRET';
const X_CLIENT_ID_HEADER_KEY = 'X-CLIENT-ID';
const X_API_KEY_HEADER_KEY = 'X-API-KEY';

class Kable {

  private environment: string;
  private kableClientId: string;
  private kableClientSecret: string;
  private baseUrl: string;
  private debug: boolean;
  private disableCache: boolean;
  private recordAuthentication: boolean;

  private queue: any[];
  private queueFlushInterval: number;
  private queueMaxCount: number;
  private validCache: any;
  private invalidCache: any;
  private timer: any;

  constructor(config: any) {

    console.log("Initializing Kable");

    if (!config) {
      throw new Error('Failed to initialize Kable: config not provided');
      // console.error('Failed to initialize Kable: config not provided');
    }

    this.environment = config.environment;
    this.kableClientId = config.clientId;
    this.kableClientSecret = config.clientSecret;
    this.baseUrl = config.baseUrl;
    this.debug = config.debug || false;
    this.disableCache = config.disableCache || false;
    if (this.debug) {
      console.log("Starting Kable with debug enabled");
    }

    if (this.disableCache) {
      console.log("Starting Kable with disableCache enabled");
    }

    this.recordAuthentication = true;
    if (config.recordAuthentication === false) {
      console.log("Starting Kable with recordAuthentication disabled, authentication requests will not be recorded");
      this.recordAuthentication = false;
    }

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


    // this.kableEnvironment = this.environment.toLowerCase() === 'live' ? 'live' : 'test';

    axios({
      url: `${this.baseUrl}/api/v1/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || '',
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
      }
    })
      .then((response: any) => {
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
      .catch((error: any) => {
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


  record = (data: any) => {
    if (this.debug) {
      console.debug("Received data to record");
    }

    let clientId = data['clientId'];
    if (clientId) {
      delete data['clientId']
    }
    let customerId = data['customerId'];
    if (clientId) {
      delete data['customerId'];
    }

    this.enqueueEvent(clientId, data, customerId);
  }


  authenticate = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (this.debug) {
      console.debug("Received request to authenticate");
    }

    // const method = req.method;
    const clientId = req.get(X_CLIENT_ID_HEADER_KEY);
    const secretKey = req.get(X_API_KEY_HEADER_KEY);

    if (!this.environment || !this.kableClientId) {
      return res.status(500).json({ message: 'Unauthorized. Failed to initialize Kable: Configuration invalid' });
    }

    if (!clientId || !secretKey) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId && validCacheClientId === clientId) {
      if (this.debug) {
        console.debug("Valid Cache Hit");
      }
      if (this.recordAuthentication) {
        this.enqueueEvent(clientId, {}, undefined);
      }
      return next();
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId && invalidCacheClientId === clientId) {
      if (this.debug) {
        console.debug("Invalid Cache Hit");
      }
      return res.status(401).json({ message: 'Unauthorized' });
    }

    if (this.debug) {
      console.debug("Authenticating at server");
    }

    axios({
      url: `${this.baseUrl}/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_CLIENT_ID_HEADER_KEY]: clientId || '',
        [X_API_KEY_HEADER_KEY]: secretKey || '',
      },
      data: req.body
    })
      .then((response: any) => {
        const status = response.status;

        if (status >= 200 && status < 300) {
          this.validCache.set(secretKey, clientId);
          if (this.recordAuthentication) {
            this.enqueueEvent(clientId, {}, undefined);
          }
          return next();
        }

        console.warn(`Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
        return res.status(401).json({ message: 'Unauthorized' });
      })
      .catch((error: any) => {
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

  private enqueueEvent = (clientId: string, data: any, customerId?: string) => {
    const event: any = {};

    event['environment'] = this.environment;
    event['kableClientId'] = this.kableClientId;
    event['clientId'] = clientId;
    event['customerId'] = customerId;
    event['timestamp'] = new Date();

    event['data'] = data;

    const library: any = {};
    library['name'] = packageJson.name;
    library['version'] = packageJson.version;

    this.queue.push(event);
    if (this.disableCache) {
      this.flushQueue();
    }

    if (this.queue.length >= this.queueMaxCount) {
      this.flushQueue();
      return;
    }

    if (this.queueFlushInterval && !this.timer) {
      this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
    }
  }

  private flushQueue = () => {
    if (this.debug) {
      console.debug('Flushing Kable event queue...');
    }

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.queue.length) {
      const events = this.queue.splice(0, this.queueMaxCount);

      axios({
        url: `${this.baseUrl}/api/v1/events`,
        method: 'POST',
        headers: {
          [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
          [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || '',
          [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
        },
        data: events
      })
        .then(() => {
          console.debug(`Successfully sent ${events.length} events to Kable server`);
        })
        .catch((error: any) => {
          console.error(`Failed to send ${events.length} events to Kable server`);
        })
    } else {
      if (this.debug) {
        console.debug('...no Kable events to flush...');
      }
    }

    this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
  }

}


export { Kable };
