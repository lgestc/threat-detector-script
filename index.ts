import { Client } from "@elastic/elasticsearch";
import { QueryDslQueryContainer } from "@elastic/elasticsearch/lib/api/types";
import { eachLimit } from "async";

import { getAllDocuments } from "./get_all_documents";
import { mark as mark, THREAT_DETECTION_INDICATOR_FIELD } from "./mark";
import { shouldClauseForThreat } from "./should_clause_for_threat";
import { Threat } from "./threat";

const EVENTS_INDEX = "filebeat-url";
const THREATS_INDEX = "logs-ti_*";

const client = new Client({
  auth: {
    username: "elastic",
    password: "changeme",
  },
  node: "http://localhost:9200",
});

// How many threat processing tasks should be running at any given time
const CONCURRENCY = 4;

const entry = async () => {
  const start = Date.now();

  // TODO don't store everything in memory
  // This may work with 100k threats, but needs to take memory limitations into account.
  // Ideally, this should be an async iterator, an event emitter or something similar to this.
  // Even better, it should be possible to run multiple instances of this iteration process across the stack.
  // Maybe we could run separate worker per threat type, initially? Something to consider.
  const allThreats = await getAllDocuments<Threat>(client, THREATS_INDEX);

  const total = allThreats.length;
  let progress = 0;

  await eachLimit(
    allThreats,
    CONCURRENCY,
    async ({ _source: threat, _id: threatId }, cb) => {
      if (!threat) {
        progress++;

        return cb();
      }

      try {
        const shouldClause = shouldClauseForThreat(threat);

        if (!shouldClause) {
          console.warn(
            `skipping threat as no clauses are defined for its type: ${threat["threat.indicator.type"]}`
          );
          progress++;
          return cb();
        }

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
            should: shouldClause,
          },
        };

        // This marks all the events matching the threat with a timestamp and threat id, so that we can do
        // aggregations on this information later.
        // We should probably use some fields from the ECS to mark the indicators instead of custom ones.
        await mark(client, EVENTS_INDEX, query, threatId, Date.now());

        cb();
      } catch (error: any) {
        cb(error);
      }

      progress++;

      console.log(`${progress}/${total}`);
    }
  );

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  console.log(`done in ${duration}, tps: ${tps}`);
};

entry();
