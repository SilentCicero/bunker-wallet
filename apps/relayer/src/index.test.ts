import {expect,test} from "bun:test";test("production deployment configuration is absent",async()=>{expect(await Bun.file(new URL("../../../wrangler.jsonc",import.meta.url)).exists()).toBe(false)});
