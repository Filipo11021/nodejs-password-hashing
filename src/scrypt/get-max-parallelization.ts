export const getMaxParallelization = (blockSize: number) =>
  Math.floor(((Math.pow(2, 32) - 1) * 32) / (128 * blockSize));
