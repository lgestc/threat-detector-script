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

const updateMapping = async (client: Client, threatIndex: string[]) => {
  await client.indices.putMapping({
    index: threatIndex,
    properties: {
      [THREAT_DETECTION_MATCH_COUNT_FIELD]: {
        type: "short",
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

  log("update threat indices mapping");

  await updateMapping(client, threatIndex);

  log("starting scan");

  const total = await countDocuments(client, threatIndex);
  let progress = 0;

  const start = Date.now();

  for await (const threats of documentGenerator<Threat>(client, threatIndex, {
    // This prevents processing threats that were already checked. That means, after initial "scan",
    // subsequent runs will be a lot faster - though we need to clear this after some time probably
    bool: {
      must_not: {
        exists: {
          field: THREAT_DETECTION_TIMESTAMP_FIELD,
        },
      },
    },
  })) {
    const matches: Array<{ count: number; id: string; index: string }> = [];

    await async.eachLimit(
      threats,
      concurrency,
      async ({ _source: threat, _id: threatId, _index: threatIndex }) => {
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
            should: shouldClause,
          },
        };

        // Threat match query is terminated once we count 100 max, for performance.
        // This can be configurable
        const count = await countDocuments(client, eventsIndex, query, 100);

        matches.push({ count, id: threatId, index: threatIndex });
      }
    );

    const operations: any[] = matches.flatMap((match) => [
      {
        update: {
          _id: match.id,
          _index: match.index,
        },
      },
      { doc: { [THREAT_DETECTION_MATCH_COUNT_FIELD]: match.count } },
    ]);

    await client.bulk({ operations });
  }

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  log(`scan done in ${duration}s, threats per second: ${tps}`);
};
