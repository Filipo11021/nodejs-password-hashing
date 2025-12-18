import z from "zod";

export const bufferSchema = ({ min, max }: { min: number; max: number }) =>
  z.instanceof(Buffer).refine((buf) => buf.length >= min && buf.length <= max, {
    message: `Buffer length must be between ${min} and ${max} bytes`,
  });
