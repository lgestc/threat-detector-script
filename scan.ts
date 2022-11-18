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

export const THREAT_DETECTION_INDICATOR_FIELD =
  "threat.detection.indicator" as const;

export const mark = async (
  es: Client,
  index: string,
  query: QueryDslQueryContainer,
  indicator: string,
  timestamp: number
) =>
  es.updateByQuery({
    index,
    query,
    script: {
      lang: "painless",
      source: `ctx._source["threat.detection.timestamp"] = params.timestamp; ctx._source["${THREAT_DETECTION_INDICATOR_FIELD}"] = params.indicator`,
      params: {
        timestamp,
        indicator,
      },
    },
    conflicts: "proceed",
    refresh: false,
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

export const getAllDocuments = async <T = unknown>(
  client: Client,
  index: string,
  query?: QueryDslQueryContainer
): Promise<Array<SearchHit<T>>> => {
  let after: SortResults | undefined;

  const pit: OpenPointInTimeResponse["id"] = (
    await client.openPointInTime({
      index,
      keep_alive: "1m",
    })
  ).id;

  const allDocs: Array<SearchHit<T>> = [];

  while (true) {
    const docs = await getDocuments<T>(client, pit, query, after);

    if (!docs.length) {
      break;
    }

    after = docs[docs.length - 1].sort;

    allDocs.push(...docs);
  }

  return allDocs;
};

async function* threatsGenerator<T>(
  client: Client,
  index: string,
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
    threatIndex: string;
    eventsIndex: string;
    concurrency: number;
    verbose: boolean;
  }
) => {
  log("starting scan");

  const start = Date.now();

  const verboseLog = (message: string) => {
    if (!verbose) {
      return;
    }

    log(message);
  };

  let progress = 0;

  // TODO don't store everything in memory
  // This may work with 100k threats, but needs to take memory limitations into account.
  // Ideally, this should be an async iterator, an event emitter or something similar to this.
  // Even better, it should be possible to run multiple instances of this iteration process across the stack.
  // Maybe we could run separate worker per threat type, initially? Something to consider.
  const allThreats = await getAllDocuments<Threat>(client, threatIndex);

  const total = allThreats.length;

  // for await (const threats of threatsGenerator(client, threatIndex)) {
  // }

  await async.eachLimit(
    allThreats,
    concurrency,
    async ({ _source: threat, _id: threatId }) => {
      progress++;

      verboseLog(`processing threats: ${progress}/${total}`);

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
              field: THREAT_DETECTION_INDICATOR_FIELD,
            },
          },
          should: shouldClause,
        },
      };

      // This marks all the events matching the threat with a timestamp and threat id, so that we can do
      // aggregations on this information later.
      // We should probably use some fields from the ECS to mark the indicators instead of custom ones.
      await mark(client, eventsIndex, query, threatId, Date.now());
    }
  );

  const end = Date.now();

  const duration = (end - start) / 1000;

  const tps = Math.floor(total / duration);

  log(`scan done in ${duration}s, threats per second: ${tps}`);
};
