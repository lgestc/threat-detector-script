import { Client } from "@elastic/elasticsearch";

export const deleteIndex = (es: Client, index: string) =>
  es.indices.delete({ index });
