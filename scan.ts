/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import type { Client } from "@elastic/elasticsearch";
import async from "async";

export interface Threat {
  "threat.indicator.type": string;
  "threat.indicator.url.full": string;
  "threat.indicator.file.hash.md5": string;
  "threat.indicator.file.hash.sha1": string;
}

import type {
  OpenPointInTimeResponse,
  SortResults,
  QueryDslQueryContainer,
  SearchHit,
} from "@elastic/elasticsearch/lib/api/types";

/**
 * Returns filter clause with 'match' conditions for relevant fields only
 * @param threat
 * @returns
 */
export const shouldClauseForThreat = (threat: Threat) => {
  switch (threat["threat.indicator.type"]) {
    case "url": {
      return [
        {
          match: {
            "url.full": threat["threat.indicator.url.full"],
          },
        },
      ];
    }

    case "file": {
      return [
        {
          match: {
            "file.hash.md5": threat["threat.indicator.file.hash.md5"],
            "file.hash.sha1": threat["threat.indicator.file.hash.sha1"],
          },
        },
      ];
    }
  }
};

export const THREAT_DETECTION_MATCH_COUNT_FIELD =
  "threat.detection.match.count" as const;

export const THREAT_DETECTION_TIMESTAMP_FIELD =
  "threat.detection.timestamp" as const;

const updateMapping = async (client: Client, eventsIndex: string[]) => {
  await client.indices.putMapping({
    index: eventsIndex,
    properties: {
      [THREAT_DETECTION_MATCH_COUNT_FIELD]: {
        type: "byte",
      },
      [THREAT_DETECTION_TIMESTAMP_FIELD]: {
        type: "date",
      },
    },
  });
};

export const markIndicator = async (
  es: Client,
  index: string[],
  query: QueryDslQueryContainer,
  count: number,
  timestamp: number
) =>
  es.updateByQuery({
    index,
    query,
    script: {
      lang: "painless",
      source: `ctx._source["${THREAT_DETECTION_TIMESTAMP_FIELD}"] = params.timestamp; ctx._source["${THREAT_DETECTION_MATCH_COUNT_FIELD}"] = params.indicator`,
      params: {
        timestamp,
        count,
      },
    },
    conflicts: "proceed",
    refresh: false,
    max_docs: 1,
  });

export const getDocuments = async <T = unknown>(
  es: Client,
  pit: string,
  query?: QueryDslQueryContainer,
  after?: any
): Promise<Array<SearchHit<T>>> => {
  const {
    hits: { hits },
  } = await es.search<T>({
    pit: {
      id: `${pit}`,
      keep_alive: "1m",
    },
    size: 1000,
    sort: ["@timestamp"],
    ...(query ? { query } : {}),
    ...(after ? { search_after: after } : {}),
  });

  return hits;
};

export const countDocuments = async (
  client: Client,
  index: string[],
  query?: QueryDslQueryContainer,
  terminateAfter?: number
) =>
  (
    await client.count({
      index,
      query,
      terminate_after: terminateAfter,
    })
  ).count;

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

export const scan = async (
  { client, log }: { client: Client; log: (message: string) => void },
  {
    threatIndex,
    eventsIndex,
    concurrency,
    verbose,
  }: {
    threatIndex: string[];
    eventsIndex: string[];
    concurrency: number;
    verbose: boolean;
  }
) => {
  const verboseLog = (message: string) => {
    if (!verbose) {
      return;
    }

    log(message);
  };

  log("update input indices mapping");

  await updateMapping(client, eventsIndex);

  log("starting scan");

  const total = await countDocuments(client, threatIndex);
  let progress = 0;

  const start = Date.now();

  let updatesCount = 0;

  for await (const threats of documentGenerator<Threat>(client, threatIndex)) {
    await async.eachLimit(
      threats,
      concurrency,
      async ({ _source: threat, _id: threatId, _index }) => {
        progress++;

        verboseLog(`processing threat ${threatId} (${progress}/${total})`);

        if (!threat) {
          verboseLog(`source is missing`);
          return;
        }

        const shouldClause = shouldClauseForThreat(threat);

        if (!shouldClause) {
          verboseLog(
            `skipping threat as no clauses are defined for its type: ${threat["threat.indicator.type"]}`
          );
          return;
        }

        const query: QueryDslQueryContainer = {
          bool: {
            // This prevents processing events that were already checked. That means, after initial "scan",
            // subsequent runs will be a lot faster - as we are not updating the events we already noticed as
            // matching the threat.
            must_not: {
              exists: {
                field: THREAT_DETECTION_MATCH_COUNT_FIELD,
              },
            },
            should: shouldClause,
          },
        };

        const matches = await countDocuments(client, eventsIndex, query, 100);

        await client.update({
          index: _index,
          id: threatId,
          script: {
            lang: "painless",
            source: `ctx._source["${THREAT_DETECTION_TIMESTAMP_FIELD}"] = params.timestamp; ctx._source["${THREAT_DETECTION_MATCH_COUNT_FIELD}"] = params.indicator`,
            params: {
              timestamp: Date.now(),
              count: matches,
            },
          },
          refresh: false,
        });

        verboseLog(`${matches} matches found for threat ${threatId}`);
      }
    );
  }

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  log(
    `scan done in ${duration}s, threats per second: ${tps}, updated docs: ${updatesCount}`
  );
};
