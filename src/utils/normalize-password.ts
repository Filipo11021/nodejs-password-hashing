export function normalizePassword(password: string) {
  return password.normalize("NFKC");
}
