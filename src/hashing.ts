export type Hashing = {
  hash: (password: string) => Promise<string>;
  verify: (password: string, hash: string) => Promise<boolean>;
  needsReHash: (hash: string) => boolean;
};

export type HashingDep = {
  hashing: Hashing;
};
