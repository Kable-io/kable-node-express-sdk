import axios from "axios";
import express from "express";
import NodeCache from "node-cache";
import packageJson from '../package.json';

const KABLE_ENVIRONMENT_HEADER_KEY = 'KABLE-ENVIRONMENT';
const KABLE_CLIENT_ID_HEADER_KEY = 'KABLE-CLIENT-ID';
const KABLE_CLIENT_SECRET_HEADER_KEY = 'KABLE-CLIENT-SECRET';
const X_CLIENT_ID_HEADER_KEY = 'X-CLIENT-ID';
const X_API_KEY_HEADER_KEY = 'X-API-KEY';

declare global {
  namespace Express {
    interface Request {
      clientId?: string;
    }
  }
}

class Kable {

  private environment: string;
  private kableClientId: string;
  private kableClientSecret: string;
  private baseUrl: string;
  private debug: boolean;
  private maxQueueSize: number;
  private recordAuthentication: boolean;

  private queue: any[];
  private queueFlushInterval: number;
  private validCache: any;
  private invalidCache: any;
  private timer: any;

  constructor(config: any) {

    console.log("[KABLE] Initializing Kable");

    if (!config) {
      throw new Error('[KABLE] Failed to initialize Kable: config not provided');
      // console.error('[KABLE] Failed to initialize Kable: config not provided');
    }

    this.environment = config.environment;
    this.kableClientId = config.clientId;
    this.kableClientSecret = config.clientSecret;
    this.baseUrl = config.baseUrl;
    this.debug = config.debug || false;
    this.maxQueueSize = config.maxQueueSize || 10; // maximum number of messages to queue before sending
    if (this.debug) {
      console.log("[KABLE] Starting Kable with debug enabled");
    }

    const disableCache: boolean = config.disableCache || false;
    if (disableCache) {
      this.maxQueueSize = 1;
    }
    if (this.maxQueueSize > 100) {
      this.maxQueueSize = 100;
    }
    console.log(`[KABLE] Starting Kable with maxQueueSize ${this.maxQueueSize}`);

    this.recordAuthentication = true;
    if (config.recordAuthentication === false) {
      console.log("[KABLE] Starting Kable with recordAuthentication disabled, authentication requests will not be recorded");
      this.recordAuthentication = false;
    }

    if (!this.environment) {
      throw new Error('[KABLE] Failed to initialize Kable: environment not provided');
      // console.error('Failed to initialize Kable: environment not provided');
    }
    if (!this.kableClientId) {
      throw new Error('[KABLE] Failed to initialize Kable: clientId not provided');
      // console.error('Failed to initialize Kable: clientId not provided');
    }
    if (!this.kableClientSecret) {
      throw new Error('[KABLE] Failed to initialize Kable: clientSecret not provided');
      // console.error('Failed to initialize Kable: clientSecret not provided');
    }
    if (!this.baseUrl) {
      throw new Error('[KABLE] Failed to initialize Kable: baseUrl not provided');
      // console.error('Failed to initialize Kable: baseUrl not provided');
    }

    this.queue = [];
    this.queueFlushInterval = 10000; // 10 seconds

    this.validCache = new NodeCache({ stdTTL: 30, maxKeys: 1000, checkperiod: 300 });
    this.invalidCache = new NodeCache({ stdTTL: 30, maxKeys: 1000, checkperiod: 300 });


    // this.kableEnvironment = this.environment.toLowerCase() === 'live' ? 'live' : 'test';

    axios({
      url: `${this.baseUrl}/api/v1/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || '',

        [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
      }
    })
      .then((response: any) => {
        if (response.status === 200) {
          // proceed with initialization
        } else if (response.status === 401) {
          throw new Error('[KABLE] Failed to initialize Kable: Unauthorized');
          // console.error('[KABLE] Failed to initialize Kable: Unauthorized');
        } else {
          throw new Error('[KABLE] Failed to initialize Kable: Something went wrong');
          // console.error('[KABLE] Failed to initialize Kable: Something went wrong');
        }

        console.log("[KABLE] Kable initialized successfully");
      })
      .catch((error: any) => {
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            // console.error('[KABLE] Failed to initialize Kable: Unauthorized');
            throw new Error('[KABLE] Failed to initialize Kable: Unauthorized');
          } else {
            // console.warn(`[KABLE] Failed to initialize Kable: Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`);
            throw new Error(`[KABLE] Failed to initialize Kable: Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`);
          }
        } else {
          console.error(error);
          // console.error('[KABLE] Failed to initialize Kable: Something went wrong');
          throw new Error('[KABLE] Failed to initialize Kable: Something went wrong');
        }
      });
  }


  record = (data: any) => {
    if (this.debug) {
      console.debug("[KABLE] Received data to record");
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

  express = {
    authenticate: (req: express.Request, res: express.Response, next: express.NextFunction) => {
      try {
        const clientId = req.get(X_CLIENT_ID_HEADER_KEY);
        const secretKey = req.get(X_API_KEY_HEADER_KEY);
        
        req.clientId = await express.authenticate(clientId, secretKey)
        next()
      } catch (error: any) {
        switch (error.constructor) {
          case UnauthorizedError:
            res.status(401).json({ message: error.message })
          case InternalServerError:
            res.status(500).json({ message: error.message })
          default:
            console.error(`[KABLE] Received unexpected error`, error)
            res.status(500).json({ message: 'Unexpected error' })
        }
      }
    }
  }

  authenticate = async (clientId: string, secretKey: string): Promise<string> => {
    if (this.debug) {
      console.debug("[KABLE] Received request to authenticate");
    }

    if (!this.environment || !this.kableClientId) {
      throw new InternalServerError('Unauthorized. Failed to initialize Kable: Configuration invalid')
    }

    if (!clientId || !secretKey) {
      throw new UnauthorizedError('Unauthorized. clientId or secretKey not provided')
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId && validCacheClientId === clientId) {
      if (this.debug) {
        console.debug("[KABLE] Valid Cache Hit");
      }
      if (this.recordAuthentication) {
        this.enqueueEvent(clientId, {}, undefined);
      }

      return clientId; // not sure this is needed, just following suit
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId && invalidCacheClientId === clientId) {
      if (this.debug) {
        console.debug("[KABLE] Invalid Cache Hit");
      }
      throw new UnauthorizedError('Unauthorized')
    }

    if (this.debug) {
      console.debug("[KABLE] Authenticating at server");
    }

    return axios({
      url: `${this.baseUrl}/api/authenticate`,
      method: 'POST',
      headers: {
        [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',

        [X_CLIENT_ID_HEADER_KEY]: clientId || '',
        [X_API_KEY_HEADER_KEY]: secretKey || '',
      },
      data: req.body // I don't actually know what should go here. Is body needed?
    })
      .then((response: any) => {
        const status = response.status;

        if (status >= 200 && status < 300) {
          this.validCache.set(secretKey, clientId);
          if (this.recordAuthentication) {
            this.enqueueEvent(clientId, {}, undefined);
          }

          return clientId;
        }

        console.warn(`[KABLE] Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
        throw new UnauthorizedError('Unauthorized')
      })
      .catch((error: any) => {
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            this.invalidCache.set(secretKey, clientId);
            throw new UnauthorizedError('Unauthorized')
          }

          console.warn(`[KABLE] Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`)
          throw new InternalServerError(`Unexpected ${status} response from Kable authenticate`)
        }
        else {
          console.error(error);
          throw new InternalServerError(error)
        }
      });
    }
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

    if (this.queue.length >= this.maxQueueSize) {
      this.flushQueue();
      return;
    }

    if (this.queueFlushInterval && !this.timer) {
      this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
    }
  }

  private flushQueue = () => {
    if (this.debug) {
      console.debug('[KABLE] Flushing Kable event queue...');
    }

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.queue.length) {
      const events = this.queue.splice(0, this.maxQueueSize);

      axios({
        url: `${this.baseUrl}/api/v1/events/create`,
        method: 'POST',
        headers: {
          [KABLE_ENVIRONMENT_HEADER_KEY]: this.environment || '',
          [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || '',
          [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || '',
          [X_API_KEY_HEADER_KEY]: this.kableClientSecret || '',
        },
        data: events
      })
        .then(() => {
          console.debug(`Successfully sent ${events.length} events to Kable server`);
        })
        .catch((error: any) => {
          console.error(JSON.stringify(error));
          console.error(`[KABLE] Failed to send ${events.length} events to Kable server`);
          events.map(event => console.log(`[KABLE] Kable Event (Error): ${JSON.stringify(event)}`));
        })
    } else {
      if (this.debug) {
        console.debug('[KABLE] ...no Kable events to flush...');
      }
    }

    this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
  }

}

export { Kable };

class InternalServerError extends Error {}
class UnauthorizedError extends Error {}