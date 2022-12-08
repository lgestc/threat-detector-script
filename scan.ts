/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Client } from "@elastic/elasticsearch";
import async from "async";
import get from "lodash/get";

export type ThreatSource = Record<RawIndicatorFieldId, unknown>;

import type {
  OpenPointInTimeResponse,
  SortResults,
  QueryDslQueryContainer,
  SearchHit,
} from "@elastic/elasticsearch/lib/api/types";
import { RawIndicatorFieldId } from "./indicator";

/**
 * Most of these are present in the 'threat.indicator' generating 'should' clauses can
 * be automated
 */
const FIELDS = [
  "url.full",
  "file.hash.sha1",
  "file.hash.md5",
  "file.pe.imphash",
  "source.ip",
  "destination.ip",
];

const BATCH_SIZE = 1000;

// Scan will be paused if it takes too long
const MAX_DURATION_IN_SECONDS = 60 * 5;

const THREAT_QUERY: QueryDslQueryContainer = {
  bool: {
    minimum_should_match: 1,
    should: [
      {
        range: {
          // Skip indicators checked within the time window
          [RawIndicatorFieldId.DetectionTimestamp]: {
            lte: "now-1m", // make it dynamic, using the schedule setting
          },
        },
      },
      {
        bool: {
          must_not: {
            exists: {
              field: RawIndicatorFieldId.DetectionTimestamp,
            },
          },
        },
      },
    ],
  },
};

/**
 * Returns filter clause with 'match' conditions
 */
export const shouldClauseForThreat = (
  threat: ThreatSource
): Array<{ match: { [key: string]: string | undefined } }> =>
  FIELDS.map((field) => [
    field,
    get(threat, `threat.indicator.${field.includes(".ip") ? "ip" : field}`),
  ])
    .filter(([_field, value]) => value)
    .map(([field, value]) => ({
      match: {
        [field]: value,
      },
    }));

const updateMapping = async (client: Client, threatIndex: string[]) => {
  await client.indices.putMapping({
    index: threatIndex,
    properties: {
      threat: {
        properties: {
          detection: {
            properties: {
              matches: {
                type: "long",
              },
              timestamp: {
                type: "date",
              },
            },
          },
        },
      },
    },
  });
};

export const getDocuments = async <T = unknown>(
  es: Client,
  pit: string,
  query?: QueryDslQueryContainer,
  after?: SortResults
): Promise<Array<SearchHit<T>>> => {
  const {
    hits: { hits },
  } = await es.search<T>({
    pit: {
      id: `${pit}`,
      keep_alive: "1m",
    },
    size: BATCH_SIZE,
    sort: ["@timestamp"],
    ...(query ? { query } : {}),
    ...(after ? { search_after: after } : {}),
  });

  return hits;
};

export const countDocuments = async (
  client: Client,
  index: string[],
  query?: QueryDslQueryContainer
) =>
  (
    await client.count({
      index,
      query,
    })
  ).count;

export const fastCount = async (
  client: Client,
  index: string[],
  query?: QueryDslQueryContainer
) => {
  const {
    hits: { total },
  } = await client.search({
    index,
    query,
    track_total_hits: 100,
    size: 0,
  });

  if (typeof total === "number") {
    return total;
  } else {
    return total?.value || 0;
  }
};

export const matchEvents = async (
  client: Client,
  eventsIndex: string[],
  threat: ThreatSource
) => {
  const shouldClause = shouldClauseForThreat(threat);

  const lastProcessedTimestamp = get(
    threat,
    RawIndicatorFieldId.DetectionTimestamp
  );

  const eventsQuery: QueryDslQueryContainer = {
    bool: {
      minimum_should_match: 1,
      should: shouldClause,
      ...(lastProcessedTimestamp
        ? {
            must: {
              range: {
                "@timestamp": {
                  // Process only the events that were registered after the latest scan
                  gte: Number(lastProcessedTimestamp),
                },
              },
            },
          }
        : {}),
    },
  };

  return fastCount(client, eventsIndex, eventsQuery);
};

async function* documentGenerator<T>(
  client: Client,
  index: string[],
  query?: QueryDslQueryContainer
) {
  let after: SortResults | undefined;

  const pit: OpenPointInTimeResponse["id"] = (
    await client.openPointInTime({
      index,
      keep_alive: "1m",
    })
  ).id;

  while (true) {
    const docs = await getDocuments<T>(client, pit, query, after);

    if (!docs.length) {
      break;
    }

    after = docs[docs.length - 1].sort;

    yield docs;
  }
}

const threatGenerator = (client: Client, threatIndex: string[]) =>
  documentGenerator<ThreatSource>(client, threatIndex, THREAT_QUERY);

interface ScanParams {
  threatIndex: string[];
  eventsIndex: string[];
  concurrency: number;
  verbose: boolean;
}

interface ScanDependencies {
  client: Client;
  log: (message: string) => void;
}

export const scan = async (
  { client, log }: ScanDependencies,
  { threatIndex, eventsIndex, concurrency, verbose }: ScanParams
) => {
  const verboseLog = (message: string) => {
    if (!verbose) {
      return;
    }

    log(message);
  };

  log("update threat indices mapping");

  await updateMapping(client, threatIndex);

  log(`starting scan verbose=${verbose}`);

  const total = await countDocuments(client, threatIndex, THREAT_QUERY);

  let newThreats = 0;

  log(`total threats to process=${total}`);

  let progress = 0;

  const start = Date.now();

  // Will be used for auto-regulation. If we know how much 1000 threats took,
  // we can make an assumption about the entire run.
  const firstBatchStart = Date.now();

  let firstBatchDuration = 0;

  let paused = false;

  for await (const threats of threatGenerator(client, threatIndex)) {
    // pause if it is taking too long, scan will resume in subsequent run
    if (Date.now() - start > MAX_DURATION_IN_SECONDS * 1000 - 100) {
      paused = true;
      break;
    }

    const matches: Array<{ count: number; id: string; index: string }> = [];

    await async.eachLimit(
      threats,
      concurrency,
      async ({ _source: threat, _id: threatId, _index: index }) => {
        progress++;

        verboseLog(`processing threat ${threatId} (${progress}/${total})`);

        if (!threat) {
          log(`source is missing`);
          return;
        }

        const minMatchingEventsCount = await matchEvents(
          client,
          eventsIndex,
          threat
        );

        newThreats += minMatchingEventsCount;

        const knownThreats = Number(
          get(threat, RawIndicatorFieldId.Matches) || 0
        );

        if (minMatchingEventsCount) {
          verboseLog(
            `threat ${threatId} matched in at last ${minMatchingEventsCount} new documents (~${knownThreats} matches known before)`
          );
        }

        matches.push({
          count: Number(knownThreats + minMatchingEventsCount),
          id: threatId,
          index,
        });
      }
    );

    const operations = matches.flatMap((match) => [
      {
        update: {
          _id: match.id,
          _index: match.index,
        },
      },
      {
        doc: {
          threat: {
            detection: {
              timestamp: Date.now(),
              matches: match.count,
            },
          },
        },
      },
    ]);

    await client.bulk({ operations });

    const firstBatchEnd = Date.now();

    // Some estimations on how long it will take
    if (!firstBatchDuration) {
      firstBatchDuration = (firstBatchEnd - firstBatchStart) / 1000;

      const totalBatches = Math.round(total / BATCH_SIZE);

      const estimate = totalBatches * firstBatchDuration;

      log(
        `first batch took: ${firstBatchDuration}s out of max ${MAX_DURATION_IN_SECONDS}s, estimated total time: ${estimate}s`
      );
    }
  }

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  log(
    `scan ${
      paused ? "paused (will be picked up in another run)" : "done"
    } after ${duration}s, threats per second: ${tps}, new threats: ${newThreats}`
  );
};
