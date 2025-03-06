# Indices

In Kibana and Elasticsearch, the term **"indices"** is used to *refer to logical namespaces that hold collections of documents*. Each document is a collection of fields, similar to rows in a relational database table. Indices are the largest unit of data in Elasticsearch and serve as a way to organize and store data efficiently.

## Key Points About Indices in Kibana

1. **Definition**: An index in Elasticsearch is a logical namespace that holds a collection of documents. Each document is a collection of fields, similar to rows in a relational database table.
 
2. **Index Patterns**: In Kibana, an **index pattern** is used to define which Elasticsearch indices or data streams you want to explore. It can include wildcards to match multiple indices, making it easier to analyze large datasets across multiple sources.
 
3. **Management**: Kibana provides features for managing indices through **Index Management**, allowing users to view and edit index settings, mappings, and statistics. This helps ensure data is stored correctly and efficiently.
 
4. **Data Views**: In newer versions of Kibana, **data views** have replaced index patterns for accessing Elasticsearch data. A data view can point to one or more indices, data streams, or index aliases.
 
5. **Terminology**: The terms **"indices"** and **"indexes"** are often used interchangeably, but in the context of Elasticsearch and Kibana, **"indices"** is the preferred term.
