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
) =>
  (
    await client.search({
      index,
      query,
      terminate_after: 1,
      rest_total_hits_as_int: true,
      size: 0,
    })
  ).hits.total as number;

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

  log(`starting scan verbose=${verbose}`);

  const threatQuery: QueryDslQueryContainer = {
    bool: {
      minimum_should_match: 1,
      should: [
        {
          range: {
            // Skip indicators checked within the time window
            [RawIndicatorFieldId.DetectionTimestamp]: {
              lte: "now-1m",
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

  const total = await countDocuments(client, threatIndex, threatQuery);

  let newThreats = 0;

  log(`total threats to process=${total}`);

  let progress = 0;

  const start = Date.now();

  for await (const threats of documentGenerator<ThreatSource>(
    client,
    threatIndex,
    threatQuery
  )) {
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

        const count = await fastCount(client, eventsIndex, eventsQuery);

        newThreats += count;

        const knownThreats = Number(
          get(threat, RawIndicatorFieldId.Matches) || 0
        );

        if (count) {
          verboseLog(
            `threat ${threatId} matched in at last ${count} new documents (~${knownThreats} matches known before)`
          );
        }

        matches.push({
          count: Number(knownThreats + count),
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
    `scan done in ${duration}s, threats per second: ${tps}, new threats: ${newThreats}`
  );
};
