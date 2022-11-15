import { Client } from "@elastic/elasticsearch";
import { QueryDslQueryContainer } from "@elastic/elasticsearch/lib/api/types";
import { eachLimit } from "async";

import { getAllDocuments } from "./get_all_documents";
import { mark as mark, THREAT_DETECTION_INDICATOR_FIELD } from "./mark";

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
  "threat.indicator.type": string;
}

// How many threat processing tasks should be running at any given time
const CONCURRENCY = 12;

const entry = async () => {
  const start = Date.now();

  // TODO dont store everything in memory lol.
  // This may work with 100k threats, but needs to take memory limitations into account.
  // Ideally, this should be an async iterator.
  // Also, threats should be partitioned so that each Kibana node receives a portion of these to process.
  const allThreats = await getAllDocuments<Threat>(client, THREATS_INDEX);

  const total = allThreats.length;
  let progress = 0;

  await eachLimit(allThreats, CONCURRENCY, async (threat, cb) => {
    const threatValue = threat._source?.["threat.indicator.url.full"];

    if (!threatValue) {
      return cb();
    }

    console.log(`processing ${threatValue}`);

    try {
      const query: QueryDslQueryContainer = {
        bool: {
          // This prevents processing events that were already checked. That means, after initial "scan",
          // subsequent runs will be a lot faster - as we are not updating the events we already noticed as
          // matching the threat.
          must_not: {
            exists: {
              field: THREAT_DETECTION_INDICATOR_FIELD,
            },
          },
          // TODO only include should clauses that occur within given threat type
          should: [
            {
              match: {
                "url.full": threatValue,
              },
            },
            {
              match: {
                "file.hash.md5": threatValue,
              },
            },
            {
              match: {
                "file.hash.sha1": threatValue,
              },
            },
            {
              match: {
                "file.pe.imphash": threatValue,
              },
            },
            {
              match: {
                "source.ip": threatValue,
              },
            },
          ],
        },
      };

      // This marks all the events matching the threat with a timestamp and threat id, so that we can do aggregations on this information later.
      // We should probably use some fields from the ECS to mark the indicators instead of custom ones.
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
