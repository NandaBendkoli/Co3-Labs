import { gql } from 'graphql-tag';

export const typeDefs = gql`
type Asset {
  id: ID!
  filename: String!
  mime: String!
  size: Int!
  sha256: String
  status: String!
  version: Int!
  createdAt: String!
  updatedAt: String!
}

type UploadTicket {
  assetId: ID!
  storagePath: String!
  uploadUrl: String!
  expiresAt: String!
  nonce: String!
}

type DownloadLink {
  url: String!
  expiresAt: String!
}

type AssetEdge { cursor: String!, node: Asset! }
type PageInfo { endCursor: String, hasNextPage: Boolean! }
type AssetConnection { edges: [AssetEdge!]!, pageInfo: PageInfo! }

type Query {
  myAssets(after: String, first: Int, q: String): AssetConnection!
  getDownloadUrl(assetId: ID!): DownloadLink!
}

type Mutation {
  createUploadUrl(filename: String!, mime: String!, size: Int!): UploadTicket!
  finalizeUpload(assetId: ID!, clientSha256: String!, version: Int!): Asset!
  renameAsset(assetId: ID!, filename: String!, version: Int!): Asset!
  shareAsset(assetId: ID!, toEmail: String!, canDownload: Boolean!, version: Int!): Asset!
  revokeShare(assetId: ID!, toEmail: String!, version: Int!): Asset!
  deleteAsset(assetId: ID!, version: Int!): Boolean!
}
`;
