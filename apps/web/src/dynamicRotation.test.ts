import { expect, test } from "bun:test";
import { createBurnerSession } from "./burner";
const phrase = `${"abandon ".repeat(23)}art`;
test("recovers arbitrary local derivation index without rotation count or saved state", () => {
  const original = createBurnerSession();
  const owner = original.loadMnemonicSigner(phrase, 47);
  const restored = createBurnerSession();
  expect(restored.recoverSigner(phrase, owner, 40, 10)).toBe(47);
  expect(() => restored.recoverSigner(phrase, owner, 0, 20)).toThrow("range");
});
test("selects only one local next key and supports intentional index switch", () => {
  const session = createBurnerSession();
  session.loadMnemonicSigner(phrase);
  const selected = session.selectNextSigner(47, phrase);
  expect(selected).toBe(createBurnerSession().loadMnemonicSigner(phrase, 47));
  expect(() => session.selectNextSigner(-1)).toThrow();
});
