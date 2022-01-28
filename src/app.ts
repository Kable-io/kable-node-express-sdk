import express from "express";

const NodeCache = require("node-cache");
const axios = require("axios");
const app = express();
app.use(express.json());
const PORT = 3001;

const ENVIRONMENT: string = "DEVELOPMENT";
const CLIENT_ID: string = "<SOME_VALUE>";
const CLIENT_SECRET: string = "<SOME_OTHER_VALUE>";

const validCache = new NodeCache({ stdTTL: 15 });
const invalidCache = new NodeCache({ stdTTL: 15 });


const checkValidCache = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  try {
    const { key } = req.params;
    if (validCache.has(key)) {
      // console.log("VALID CACHE HIT");
      return res.status(200).json({ clientId: validCache.get(key) });
    }
    // console.log("VALID CACHE MISS");
    return next();
  } catch (e) {
    throw new Error("Something went wrong");
  }
};

const checkInvalidCache = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  try {
    const { key } = req.params;
    if (invalidCache.has(key)) {
      // console.log("INVALID CACHE HIT");
      return res.status(401).json({ message: "Unauthorized" });
    }
    // console.log("INVALID CACHE MISS");
    return next();
  } catch (e) {
    throw new Error("Something went wrong");
  }
};


app.get("/verify/:clientId/:key", checkValidCache, checkInvalidCache, async (req: express.Request, res: express.Response) => {
  try {
    const { clientId, key } = req.params;

    const response = await axios.post(`http://localhost:3000/api/authentications/verify`,
      {
        environment: ENVIRONMENT,
        client_id: clientId,
        key: key
      }
    );

    if (response.status != 200) {
      return res.status(500).json({ message: 'Failed to authenticate' });
    }

    const data = response.data;

    if (data.valid) {
      validCache.set(key, data.client_id);
      return res.status(200).send(true);

    } else {
      invalidCache.set(key, data.client_id);
      return res.status(200).send(false);
    }

  } catch (e) {
    return res.status(500).json({ message: 'Failed to authenticate' });
  }
});


const server = app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// module.exports = server;
