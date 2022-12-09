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

const threatQuery = (interval: string): QueryDslQueryContainer => ({
  bool: {
    minimum_should_match: 1,
    should: [
      {
        range: {
          // Skip indicators checked within the time window
          [RawIndicatorFieldId.DetectionTimestamp]: {
            lte: `now-${interval}`, // make it dynamic, using the schedule setting
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
});

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
  query: QueryDslQueryContainer,
  sortSalt: string,
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
    sort: {
      _script: {
        type: "number",
        script: {
          lang: "painless",
          params: {
            salt: sortSalt,
          },
          source: "(doc['@timestamp'].value + params.salt).hashCode()",
        },
        order: "asc",
      },
    },
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
  query: QueryDslQueryContainer,
  sortSalt: string
) {
  let after: SortResults | undefined;

  const pit: OpenPointInTimeResponse["id"] = (
    await client.openPointInTime({
      index,
      keep_alive: "1m",
    })
  ).id;

  while (true) {
    const docs = await getDocuments<T>(client, pit, query, sortSalt, after);

    if (!docs.length) {
      break;
    }

    after = docs[docs.length - 1].sort;

    yield docs;
  }
}

const threatGenerator = (
  client: Client,
  threatIndex: string[],
  interval: string,
  sortSalt: string
) =>
  documentGenerator<ThreatSource>(
    client,
    threatIndex,
    threatQuery(interval),
    sortSalt
  );

interface ScanParams {
  threatIndex: string[];
  eventsIndex: string[];
  concurrency: number;
  verbose: boolean;
  interval: string;
}

interface ScanDependencies {
  client: Client;
  log: (message: string) => void;
}

export const scan = async (
  { client, log }: ScanDependencies,
  {
    threatIndex,
    eventsIndex,
    concurrency,
    verbose,
    interval = "1m",
  }: ScanParams
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

  const total = await countDocuments(
    client,
    threatIndex,
    threatQuery(interval)
  );

  let newThreats = 0;

  log(`total threats to process=${total}`);

  let progress = 0;

  const start = Date.now();

  const sortSalt = `${start}`;

  let paused = false;

  // Scan will be paused if it takes too long
  const intervalMultiplier = interval.includes("m")
    ? 60
    : interval.includes("h")
    ? 3600
    : 1;
  const intervalInSeconds = parseInt(interval, 10) * intervalMultiplier;

  log(`intervalInSeconds=${intervalInSeconds}`);

  for await (const threats of threatGenerator(
    client,
    threatIndex,
    interval,
    sortSalt
  )) {
    // pause if it is taking too long, scan will resume in subsequent run
    if (Date.now() - start > intervalInSeconds * 1000 - 100) {
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
