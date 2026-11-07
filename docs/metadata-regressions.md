# HTTP and stored metadata contracts

HTTP collection uses `http_headers.h` for the selected response's headers,
status and body. After informational responses, all three refer to the final
response. A protocol upgrade remains a 101 response with opaque payload.
Partial headers have no body; LF-only header separators are accepted. Text in
a response body cannot supply `Server`, `Location` or other header metadata.
Synchronous enrichment, the opt-in async pre-pass and web recon share these
boundaries. The async path lowercases each response once for header lookups.

Stored CVE and web-path arrays use `stored_json.h`. JSON whitespace, escaped
strings, scientific notation and boolean triage flags do not change their
meaning. CVE identifiers come from direct string `id` members of array objects;
nested keys and quoted examples are not CVEs. Decoded control characters stay
escaped when printed from JSON fields in findings reports.

The parser rejects nesting beyond 64 containers before constructing a JSON
tree. Invalid UTF-8 is repaired using the existing shared JSON helper. Empty
legacy CVE cells retain their existing meaning of an empty list. A malformed
list, or a CVE array containing invalid records, cannot establish a patch
comparison: the report states that the comparison is unavailable instead of
claiming that the host was fully patched.

The regression drivers exercise the actual executable with owned loopback
HTTP fixtures or inert SQLite rows:

```sh
python3 tests/enrichment_http_contracts.py ./kmap --artifacts test-results/enrichment-http
python3 tests/report_json_contracts.py ./kmap --artifacts test-results/report-json
make check-kmap
python3 tests/run_sanitizer_harnesses.py --output test-results/sanitizers
```

The new drivers run in both the Linux unit workflow and the Windows build
workflow. The sanitizer manifest includes the production HTTP helper, stored
JSON helper and CVE diff tests. `fuzz/ossfuzz/fuzz_stored_json.cc` exercises the
production stored parser and serialization round trips; ClusterFuzzLite builds
it and packages the committed seeds. The seed-archive tests cover compiler
failure, missing inputs and removal of stale seeds during a rebuild.

Protocol references: [HTTP message framing, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-2),
[informational responses, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2),
and [JSON grammar, RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html#section-2).
The JSON library's [parser callback documentation](https://json.nlohmann.me/features/parsing/parser_callbacks/)
explains why discarding a value in a callback does not stop parsing deep input.
