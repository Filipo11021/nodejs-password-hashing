export function toHex(buffer: Buffer<ArrayBuffer>) {
  return buffer.toString("hex");
}

export function fromHex(hex: string) {
  return Buffer.from(hex, "hex");
}
