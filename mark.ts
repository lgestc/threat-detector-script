import { Client } from "@elastic/elasticsearch";
import { QueryDslQueryContainer } from "@elastic/elasticsearch/lib/api/types";

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
