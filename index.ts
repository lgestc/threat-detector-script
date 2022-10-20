import { Client } from "@elastic/elasticsearch";
import { eachLimit } from "async";

import { getAllDocuments } from "./get_all_documents";
import { mark as mark } from "./mark";

const EVENTS_INDEX = "filebeat-url";
const THREATS_INDEX = "logs-ti_*";

const client = new Client({
  auth: {
    username: "elastic",
    password: "changeme",
  },
  node: "http://localhost:9200",
});

interface Threat {
  "threat.indicator.url.full": string;
}

const CONCURRENCY = 12;

const entry = async () => {
  const start = Date.now();

  // TODO dont store everyting in memory lol
  const allThreats = await getAllDocuments<Threat>(client, THREATS_INDEX);

  const total = allThreats.length;
  let progress = 0;

  await eachLimit(allThreats, CONCURRENCY, async (threat, cb) => {
    console.log(`processing ${threat._source?.["threat.indicator.url.full"]}`);

    try {
      const query = {
        bool: {
          must_not: {
            exists: {
              field: "threat",
            },
          },
          must: {
            match: {
              "url.full": threat._source?.["threat.indicator.url.full"],
            },
          },
        },
      };

      await mark(client, EVENTS_INDEX, query, threat._id, Date.now());

      cb();
    } catch (error: any) {
      cb(error);
    }

    progress++;

    console.log(`${progress}/${total}`);
  });

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  console.log(`done in ${duration}, tps: ${tps}`);
};

entry();
