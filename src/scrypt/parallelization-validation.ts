const getMaxParallelization = (blockSize: number) =>
  Math.floor(((Math.pow(2, 32) - 1) * 32) / (128 * blockSize));

export function isValidParallelization({
  blocksize,
  parallelization,
}: {
  blocksize: number;
  parallelization: number;
}) {
  const maxP = getMaxParallelization(blocksize);
  return parallelization <= maxP;
}
