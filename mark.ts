import { Client } from "@elastic/elasticsearch";
import { QueryDslQueryContainer } from "@elastic/elasticsearch/lib/api/types";

export const mark = async (
  es: Client,
  index: string,
  query: QueryDslQueryContainer,
  threat: string,
  timestamp: number
) =>
  es.updateByQuery({
    index,
    query,
    script: {
      lang: "painless",
      source:
        'ctx._source["touchedAt"] = params.timestamp; ctx._source["threat"] = params.threat',
      params: {
        timestamp,
        threat,
      },
    },
    conflicts: "proceed",
  });
