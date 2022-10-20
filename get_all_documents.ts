import { Client } from "@elastic/elasticsearch";
import {
  OpenPointInTimeResponse,
  QueryDslQueryContainer,
  SearchHit,
  SortResults,
} from "@elastic/elasticsearch/lib/api/types";
import { getDocuments } from "./get_documents";

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
