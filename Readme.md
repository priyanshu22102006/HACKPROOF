# HackProof Context Test — External vs. Copied Algorithm Fixture

## Overview

This repository is a small, hand-built test fixture used alongside HackProof,
the hackathon build-provenance and integrity platform. It contains two
independent implementations of the same simple calculation — one presented
as an **external** algorithm and one presented as a **copied** algorithm —
plus a minimal application entry point. The repository exists to provide a
concrete, runnable example of the "two implementations, two code-provenance
stories" scenario that HackProof's context and integrity tooling is designed
to reason about.

**Repository:** `hackproof-context-test`

## Problem Statement

HackProof's broader goal is to help judges and reviewers tell the difference
between code that was genuinely authored during a build window and code that
was imported, copied, or otherwise brought in from elsewhere, without
jumping to accusations. Testing that kind of tooling requires realistic
fixtures: small, clearly-labeled examples of "external" versus "copied" code
that a provenance or context-analysis system could later be pointed at. This
repository is one such fixture — a deliberately minimal case with two
algorithm files that are easy to reason about by hand.

## What This Feature Demonstrates

- Two separate algorithm implementations — `external_algorithm.js` and
  `copied_algorithm.cjs` — each execute correctly and independently.
- The two files use two different Node.js module systems (native ES modules
  and CommonJS) side by side in the same project, and both run correctly
  from the command line.
- Both implementations were manually executed and their outputs were
  confirmed to match the expected arithmetic for their respective inputs.

**What this does *not* demonstrate** (see [Current Limitations](#current-limitations)):
this repository does not itself perform any comparison, similarity check, or
integrity/provenance analysis between the two files. It is the raw material
for that kind of test, not an implementation of it.

## How It Works

- **`src/external_algorithm.js`** exports a single function, `calculateScore`,
  via a native ES module `export` statement. Given a number, it returns that
  number multiplied by `42`.
- **`src/copied_algorithm.cjs`** exports a single function (assigned to
  `module.exports`) that takes an array and returns a new array with each
  element multiplied by `42`, using CommonJS's `.cjs` extension.
- **`src/app.js`** is a minimal entry point that logs
  `"HackProof context test"` to the console. It does not currently import or
  invoke either algorithm file.

Both algorithms implement the same underlying operation — multiplication by
`42` — just at different call shapes (a single number vs. an array) and
through different module systems, which is what makes them a useful pair for
exercising module-system-aware tooling.

## Repository / File Structure

```
hackproof-context-test/
├── package.json                  # minimal manifest (see Implementation Details)
└── src/
    ├── app.js                    # entry point; logs a startup message
    ├── external_algorithm.js     # ES module implementation (calculateScore)
    └── copied_algorithm.cjs      # CommonJS implementation (advancedAlgorithm)
```

## Implementation Details

- **`external_algorithm.js`**
  ```js
  function calculateScore(input) {
    return input * 42;
  }

  export { calculateScore };
  ```
  Uses ES module `export` syntax. The file has a `.js` extension, and
  `package.json` does not declare `"type": "module"` (see below), so Node
  relies on its own module-syntax detection to run it as ESM.

- **`copied_algorithm.cjs`**
  ```js
  function advancedAlgorithm(data) {
      return data.map(x => x * 42);
  }

  module.exports = advancedAlgorithm;
  ```
  Uses CommonJS `module.exports`, made explicit by the `.cjs` extension so it
  is always treated as CommonJS regardless of any `package.json` setting.

- **`app.js`**
  ```js
  console.log("HackProof context test");
  ```
  A placeholder entry point; it does not currently wire up either algorithm.

- **`package.json`** currently contains only an empty object (`{}`) — no
  `name`, `version`, `scripts`, `dependencies`, or `type` field. There is no
  test runner, build step, or dependency configured in this repository.

### A module-system note worth recording

Because `package.json` has no `"type"` field and `external_algorithm.js`
uses `.js` (not `.mjs`), running it does not unambiguously declare itself as
ESM up front. When it was executed via `node -e "import(...)"` (see
[Test Commands](#test-commands)), Node's runtime module-syntax detection
recognized the `export` statement and reparsed the file as an ES module,
emitting an informational warning (`MODULE_TYPELESS_PACKAGE_JSON`)
recommending that `"type": "module"` be added to `package.json` to avoid the
reparse overhead. The script still ran and returned the correct result —
this is a performance/clarity note, not a functional failure.

`copied_algorithm.cjs` is unaffected by this, since its `.cjs` extension
always marks it as CommonJS.

## Testing

Testing performed so far was **manual, ad hoc execution from the command
line** — there is no automated test framework, test script, or assertion
library configured in this repository (`package.json` defines no `scripts`
or `dependencies`). Each algorithm file was run directly with `node -e` and
its output was visually compared against the expected arithmetic result.

### Test Commands

```bash
# external_algorithm.js — ES module export
node -e "import('./src/external_algorithm.js').then(m => console.log(m.calculateScore(2)))"

# copied_algorithm.cjs — CommonJS export
node -e "const f=require('./src/copied_algorithm.cjs'); console.log(f([1,2,3]))"
```

### Expected Outputs

| Command | Output |
|---|---|
| `calculateScore(2)` from `external_algorithm.js` | `84` |
| `[1,2,3]` through `copied_algorithm.cjs` | `[ 42, 84, 126 ]` |

Both outputs are arithmetically consistent with the source: `calculateScore`
returns `input * 42` (`2 * 42 = 84`), and `advancedAlgorithm` maps
`x => x * 42` over its input array (`[1*42, 2*42, 3*42] = [42, 84, 126]`).

## Current Limitations

- **No automated tests.** All verification so far has been manual,
  one-off `node -e` invocations, not a repeatable test suite.
- **No comparison or similarity logic.** Nothing in this repository compares
  `external_algorithm.js` and `copied_algorithm.cjs` to each other, computes
  a similarity score, or flags one as derived from the other. Any resemblance
  between them (both multiply their input by `42`) is only visible to a
  human reading the code.
- **No integrity/provenance analysis is performed here.** This repository
  does not contain, call, or depend on any HackProof context-awareness,
  GPG-verification, or evidence-graph code. It is a fixture that such tooling
  could be pointed at, not an implementation of that tooling.
- **`app.js` does not use either algorithm.** The entry point is a standalone
  placeholder and is not wired to `external_algorithm.js` or
  `copied_algorithm.cjs`.
- **`package.json` carries no project metadata.** There is no `name`,
  `version`, declared `type`, license, or dependency list.
- **What the test results prove:** only that each function executes and
  returns arithmetically correct output for the one input tried. They do not
  prove correctness across other inputs (e.g. negative numbers, non-numeric
  input, empty arrays), and they do not prove anything about the *origin* or
  *authenticity* of either file's code.

## Future Improvements

- Add an automated test suite (e.g. Node's built-in `node:test`, or Jest) so
  results are repeatable and covered by more than one input.
- Add a comparison step that actually inspects both algorithm files (e.g.
  structural/AST comparison) if this fixture is meant to exercise a
  similarity-detection feature.
- Wire this fixture into HackProof's context-awareness tooling so the
  "external" vs. "copied" framing is backed by an actual analysis pass,
  rather than being conveyed only through file naming.
- Fill in `package.json` (`name`, `version`, `type`, `scripts`) so the module
  system is explicit and a `npm test` script exists.
- Connect `app.js` to the algorithm modules so the entry point exercises them
  as part of running the app, not just via ad hoc commands.

## How to Run

This repository has no dependencies, so no install step is required.

```bash
# Clone and enter the repository
git clone https://github.com/anantapathak8/hackproof-context-test.git
cd hackproof-context-test

# Run the external algorithm (ES module)
node -e "import('./src/external_algorithm.js').then(m => console.log(m.calculateScore(2)))"

# Run the copied algorithm (CommonJS, .cjs extension)
node -e "const f=require('./src/copied_algorithm.cjs'); console.log(f([1,2,3]))"

# Run the app entry point
node src/app.js
```

## Conclusion

This repository is a small, verified fixture: two arithmetic algorithms —
one written as an ES module, one as CommonJS — that both run correctly from
the command line and produce the expected output. It is intended as raw
material for testing HackProof's context and integrity tooling against an
"external vs. copied" code scenario, not as an implementation of that
tooling itself. The next meaningful step is connecting this fixture to an
actual analysis pass rather than relying on file naming alone to convey the
scenario.
