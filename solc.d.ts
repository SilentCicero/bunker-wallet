declare module "solc" {
  const solc: { compile(input: string): string; version(): string };
  export default solc;
}
