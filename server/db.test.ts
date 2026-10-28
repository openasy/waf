import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "waf-")), "nested", "waf.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("starts a site in detection-only mode, and keeps its mode and paranoia level to what the rule set knows", () => {
    const db = openDb(":memory:");
    const insert = (id: string, extra = "", values = "") =>
      db
        .prepare(
          `INSERT INTO sites (id, name, hosts, upstream, created_by, created_at, updated_at${extra}) VALUES (?, ?, '[]', 'http://a', 'x', 'now', 'now'${values})`,
        )
        .run(id, id);
    insert("a");
    expect(db.prepare("SELECT mode, paranoia, inbound_threshold FROM sites WHERE id = 'a'").get()).toEqual({
      mode: "detection",
      paranoia: 1,
      inbound_threshold: 5,
    });
    expect(() => insert("b", ", mode", ", 'off'")).toThrow(/CHECK/);
    expect(() => insert("c", ", paranoia", ", 5")).toThrow(/CHECK/);
  });
});
