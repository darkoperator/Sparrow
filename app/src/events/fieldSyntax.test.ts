import { describe, expect, it } from "vitest";
import { buildField, parseField, quoteValue, splitField, type Term } from "./fieldSyntax";

const lit = (text: string, exclude = false): Term => ({ text, exclude, wild: false });

describe("fieldSyntax", () => {
  // The same texts as core's `values_with_syntax_characters_filter_exactly_when_quoted` (tests/events_query.rs), which
  // checks that each one filters exactly these values in the database.
  it.each([
    ['"a,b"', [lit("a,b")]],
    ['"*"', [lit("*")]],
    ['"x*y"', [lit("x*y")]],
    ['"!bang"', [lit("!bang")]],
    ['say "hi"', [lit('say "hi"')]],
    ['"""quoted"""', [lit('"quoted"')]],
    ['" pad "', [lit(" pad ")]],
    ['"a,b", a', [lit("a,b"), lit("a")]],
    ['!"a,b", !a, !b', [lit("a,b", true), lit("a", true), lit("b", true)]],
    ['!"*"', [lit("*", true)]],
    ["a,b", [lit("a"), lit("b")]],
    ["x*y", [{ text: "x*y", exclude: false, wild: true }]],
    ["  a , !b,, c ", [lit("a"), lit("b", true), lit("c")]],
  ])("reads %j as core does", (text, terms) => {
    expect(parseField(text)).toEqual({ ok: true, terms });
  });

  it.each([
    ["!", "a '!' needs a value after it (like !value)"],
    [",,", "only commas, no value"],
    ["a, !", "a '!' needs a value after it (like !value)"],
    ['"open', 'a quote is not closed (a quoted value ends with ")'],
    ['"a"b', "a quoted value must end at its closing quote (put a comma after it)"],
  ])("refuses %j as core does", (text, message) => {
    expect(parseField(text)).toEqual({ ok: false, message });
  });

  it("quotes exactly the values the syntax would otherwise read differently", () => {
    for (const plain of ["alice@contoso.example", "203.0.113.7", "2001:db8::1", "a!b", "NT AUTHORITY\\SYSTEM"]) {
      expect(quoteValue(plain)).toBe(plain);
    }
    expect(quoteValue("a,b")).toBe('"a,b"');
    expect(quoteValue("*")).toBe('"*"');
    expect(quoteValue("!x")).toBe('"!x"');
    expect(quoteValue('"q"')).toBe('"""q"""');
    // A quote mid-value would read as itself unquoted; quoting it anyway is the same value.
    expect(quoteValue('O"Brien')).toBe('"O""Brien"');
    expect(quoteValue(" pad")).toBe('" pad"');
  });

  it("every hostile value round-trips as exactly one value, included or excluded", () => {
    const values = ["a,b", "*", "x*y", "!bang", '"', 'say "hi", "bye"', " lead", "trail ", "!", ",", '""', "u".repeat(60) + "@contoso.example"];
    for (const v of values) {
      expect(parseField(quoteValue(v))).toEqual({ ok: true, terms: [lit(v)] });
      expect(parseField(buildField([v], true, ""))).toEqual({ ok: true, terms: [lit(v, true)] });
    }
    expect(parseField(buildField(values, false, ""))).toEqual({ ok: true, terms: values.map((v) => lit(v)) });
  });

  it("builds ticks, exclude and pattern into one text and splits it back", () => {
    expect(buildField(["a", "b"], false, "")).toBe("a,b");
    expect(buildField(["a", "b"], true, "")).toBe("!a,!b");
    expect(buildField(["a"], false, " admin* ")).toBe("a,admin*");
    expect(buildField([], false, "  ")).toBe("");
    expect(splitField("a,b")).toEqual({ values: ["a", "b"], exclude: false, pattern: "" });
    expect(splitField('!a, !"x,y", admin*')).toEqual({ values: ["a", "x,y"], exclude: true, pattern: "admin*" });
    // The other polarity goes to the pattern, quoted as needed.
    expect(splitField('a, !"b,c"')).toEqual({ values: ["a"], exclude: false, pattern: '!"b,c"' });
    // A text the syntax refuses stays as typed, in the pattern box.
    expect(splitField("!")).toEqual({ values: [], exclude: false, pattern: "!" });
  });
});
