import packageJson from "../package.json";
import express from "express";
import axios, { AxiosError } from "axios";
import axiosRetry from "axios-retry";
import { v4 as uuid4 } from "uuid";
import NodeCache from "node-cache";

const KABLE_CLIENT_ID_HEADER_KEY = "KABLE-CLIENT-ID";
const KABLE_CLIENT_SECRET_HEADER_KEY = "KABLE-CLIENT-SECRET";
const X_CLIENT_ID_HEADER_KEY = "X-CLIENT-ID";
const X_API_KEY_HEADER_KEY = "X-API-KEY";

declare global {
  namespace Express {
    interface Request {
      clientId?: string;
    }
  }
}

class Kable {
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

  /**
   * Initialize Kable with credentials found in your Kable dashboard and settings for the client library.
   *
   * @param {Object} config
   *   @param {string} kableClientId (required)
   *   @param {string} kableClientSecret (required)
   *   @param {string} baseUrl (required)
   *   @param {boolean} debug (optional, print log lines, default false)
   *   @param {number} maxQueueSize (optional, maximum number of events to batch before flushing, default 20)
   *   @param {boolean} recordAuthentication (optional, disables recording of authentication events for cases where `authenticate` and `record` are used together, default true)
   */
  constructor(config: any) {
    console.log("[KABLE] Initializing Kable");

    if (!config) {
      throw new Error(
        "[KABLE] Failed to initialize Kable: config not provided"
      );
    }

    this.kableClientId = config.kableClientId;
    this.kableClientSecret = config.kableClientSecret;
    this.baseUrl = config.baseUrl;
    this.debug = config.debug || false;
    if (this.debug) {
      console.log("[KABLE] Starting Kable with debug enabled");
    }

    this.maxQueueSize = Math.max(config.maxQueueSize, 1) || 20;
    const disableCache: boolean = Boolean(config.disableCache) || false; // for backward compatibility
    if (disableCache) {
      this.maxQueueSize = 1;
    }
    this.maxQueueSize = Math.min(this.maxQueueSize, 500); // maximum allowable maxQueueSize is 500
    console.log(
      `[KABLE] Starting Kable with maxQueueSize ${this.maxQueueSize}`
    );

    this.recordAuthentication = true;
    if (config.recordAuthentication === false) {
      console.log(
        "[KABLE] Starting Kable with recordAuthentication disabled, authentication requests will not be recorded"
      );
      this.recordAuthentication = false;
    }

    if (!this.kableClientId) {
      throw new Error(
        "[KABLE] Failed to initialize Kable: kableClientId not provided"
      );
    }
    if (!this.kableClientSecret) {
      throw new Error(
        "[KABLE] Failed to initialize Kable: kableClientSecret not provided"
      );
    }
    if (!this.baseUrl) {
      throw new Error(
        "[KABLE] Failed to initialize Kable: baseUrl not provided"
      );
    }

    this.queue = [];
    this.queueFlushInterval = 10000; // 10 seconds

    this.validCache = new NodeCache({
      stdTTL: 30,
      maxKeys: 1000,
      checkperiod: 300,
    });
    this.invalidCache = new NodeCache({
      stdTTL: 30,
      maxKeys: 1000,
      checkperiod: 300,
    });

    axiosRetry(axios, {
      retries: 3,
      retryDelay: axiosRetry.exponentialDelay,
      retryCondition: this.isErrorRetryable,
      onRetry: (retryCount, error, requestConfig) => {
        if (this.debug) {
          console.log(
            `[KABLE] Retrying failed event flush (${error.response?.status}, retry ${retryCount})`
          );
        }
      },
    });

    axios({
      url: `${this.baseUrl}/api/v1/authenticate`,
      method: "POST",
      headers: {
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || "",
        [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || "",

        [X_CLIENT_ID_HEADER_KEY]: this.kableClientId || "",
        [X_API_KEY_HEADER_KEY]: this.kableClientSecret || "",
      },
    })
      .then((response: any) => {
        if (response.status === 200) {
          console.log("[KABLE] Kable initialized successfully");
        } else if (response.status === 401) {
          throw new Error("[KABLE] Failed to initialize Kable: Unauthorized");
        } else {
          throw new Error(
            "[KABLE] Failed to initialize Kable: Something went wrong"
          );
        }
      })
      .catch((error: any) => {
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            throw new Error("[KABLE] Failed to initialize Kable: Unauthorized");
          } else {
            throw new Error(
              `[KABLE] Failed to initialize Kable: Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`
            );
          }
        } else {
          console.error(error);
          throw new Error(
            "[KABLE] Failed to initialize Kable: Something went wrong"
          );
        }
      });
  }

  /**
   * Record a usage event.
   *
   * @param clientId The clientId of the customer to whom this event should be attributed.
   * @param data Event data to record.
   * @param transactionId A unique identifier for this event used as an idempotency key. (If not provided, a UUID will be auto-generated.)
   * @param callback
   * @returns
   */
  record = (
    clientId: string,
    data: any,
    transactionId?: string,
    callback?: any
  ) => {
    if (this.debug) {
      console.debug("[KABLE] Received data to record");
    }

    this.enqueueEvent(clientId, data, transactionId, callback);
    return this;
  };

  authenticate = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    if (this.debug) {
      console.debug("[KABLE] Received request to authenticate");
    }

    // const method = req.method;
    const clientId = req.get(X_CLIENT_ID_HEADER_KEY);
    const secretKey = req.get(X_API_KEY_HEADER_KEY);

    if (!this.baseUrl || !this.kableClientId) {
      return res.status(500).json({
        message:
          "Unauthorized. Failed to initialize Kable: Configuration invalid",
      });
    }

    if (!clientId || !secretKey) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const validCacheClientId = this.validCache.get(secretKey);
    if (validCacheClientId && validCacheClientId === clientId) {
      if (this.debug) {
        console.debug("[KABLE] Valid Cache Hit");
      }
      if (this.recordAuthentication) {
        this.enqueueEvent(clientId, {});
      }
      req.clientId = clientId;
      return next();
    }

    const invalidCacheClientId = this.invalidCache.get(secretKey);
    if (invalidCacheClientId && invalidCacheClientId === clientId) {
      if (this.debug) {
        console.debug("[KABLE] Invalid Cache Hit");
      }
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (this.debug) {
      console.debug("[KABLE] Authenticating at server");
    }

    axios({
      url: `${this.baseUrl}/api/authenticate`,
      method: "POST",
      headers: {
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || "",

        [X_CLIENT_ID_HEADER_KEY]: clientId || "",
        [X_API_KEY_HEADER_KEY]: secretKey || "",
      },
    })
      .then((response: any) => {
        const status = response.status;

        if (status >= 200 && status < 300) {
          this.validCache.set(secretKey, clientId);
          if (this.recordAuthentication) {
            this.enqueueEvent(clientId, {});
          }
          req.clientId = clientId;
          return next();
        }

        console.warn(
          `[KABLE] Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`
        );
        return res.status(401).json({ message: "Unauthorized" });
      })
      .catch((error: any) => {
        if (error.response && error.response.status) {
          const status = error.response.status;
          if (status == 401) {
            this.invalidCache.set(secretKey, clientId);
            return res.status(401).json({ message: "Unauthorized" });
          }

          console.warn(
            `[KABLE] Unexpected ${status} response from Kable authenticate. Please update your SDK to the latest version immediately.`
          );
          return res.status(500).json({ message: "Something went wrong" });
        } else {
          console.error(error);
          return res.status(500).json({ message: "Something went wrong" });
        }
      });
  };

  shutdown = () => {
    this.flushQueue();
  };

  private enqueueEvent = (
    clientId: string,
    data: any,
    transactionId?: string,
    callback?: any
  ) => {
    callback = callback || (() => {});

    const event: any = {};

    event["kableClientId"] = this.kableClientId;
    event["clientId"] = clientId;
    event["timestamp"] = new Date();
    event["transactionId"] = transactionId || uuid4();

    event["data"] = data;

    const library: any = {};
    library["name"] = packageJson.name;
    library["version"] = packageJson.version;
    event["library"] = library;

    this.queue.push({ event: event, callback: callback });

    if (this.queue.length >= this.maxQueueSize) {
      this.flushQueue();
    }

    if (this.queueFlushInterval && !this.timer) {
      this.timer = setTimeout(() => this.flushQueue(), this.queueFlushInterval);
    }
  };

  private flushQueue = (callback?: any) => {
    callback = callback || (() => {});

    if (this.debug) {
      console.debug("[KABLE] Flushing Kable event queue...");
    }

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (!this.queue.length) {
      console.debug("[KABLE] ...no Kable events to flush...");
      return;
    }

    const items: any[] = this.queue.splice(0, this.maxQueueSize);
    const events: any[] = items.map((i: any) => i.event);
    const callbacks: any[] = items.map((i: any) => i.callback);

    const finish = (error?: any) => {
      callbacks.forEach((callback: any) => callback(error));
      callback(error);
    };

    axios({
      url: `${this.baseUrl}/api/v1/events/create`,
      method: "POST",
      headers: {
        [KABLE_CLIENT_ID_HEADER_KEY]: this.kableClientId || "",
        [KABLE_CLIENT_SECRET_HEADER_KEY]: this.kableClientSecret || "",
      },
      data: events,
    })
      .then(() => {
        console.debug(
          `[KABLE] Successfully sent ${events.length} events to Kable server`
        );
        finish();
      })
      .catch((error: any) => {
        console.error(JSON.stringify(error));
        console.error(
          `[KABLE] Failed to send ${events.length} events to Kable server`
        );
        events.map((event) =>
          console.log(`[KABLE] Kable Event (Error): ${JSON.stringify(event)}`)
        );
        finish(error);
      });
  };

  private isErrorRetryable = (error: AxiosError) => {
    if (axiosRetry.isNetworkError(error)) {
      return true;
    }
    if (!error.response) {
      return false; // unclear if request reached the server
    }
    const statusCode: number = error.response.status;
    if (statusCode >= 500 && statusCode < 600) {
      return true; // retryable status codes
    }
    if (statusCode === 429) {
      return true; // retry rate limited requests
    }
    return false;
  };
}

export { Kable };
