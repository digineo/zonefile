# 2.2.2

- Fixed SOA output for `#resource_records(powerdns_sql: true)`. Previously,
  this returned primary and email fields unmodified (i.e. possibly with
  trailing dot).

# 2.2.1

- Fixed a bug where the Zonefile parser would trip over an RR like
  `a in txt "whatever"` and drop the previous record (due to missing
  regexp anchors).

# 2.2.0

- Zone file data exported with `#resource_records` now always include
  the RR class (which defaults to "IN", if not set).
- `#resource_records` now accepts a `powerdns_sql: true` argument to
  make working with PowerDNS SQL storage a bit easier:

  - it replaces "@" with the origin
  - names not ending in "." are suffixed with the origin (creating FQDNs)
  - the final dot is removed

  Note that this export mode is propably not RFC conform, but required
  for manipulating data in one of PowerDNS's SQL storages.
- finally added a `Rakefile` and `Gemfile` to ease local development


# 2.1.1

- TTL values are now also expanded when dumping records.

# 2.1.0

- TTL values are now always expanded to seconds (i.e. 1H => 3600),
  and the `:ttl` keys now contain the integer value

# 2.0.3

- follow recommendations of RFC1982 and perform proper
  integer overflow for SOA serial

# 2.0.2

- add `Zonefile#next_serial`

# 2.0.1

- improve `Zonefile#resource_records`

# 2.0.0

- improve `Zonefile#resource_records`

# 1.99

- add CAA record support
- cleanup repository
- deprecate `Zonefile.preserve_name`

# Historic releases

- 1.06 - ?
- 1.05 - Adds support for TLSA records
- 1.03 - Fixes TXT records, quotes are not treated anymore
- 1.02 - Fixes
- 1.01 - Fixes
- 1.00 - Initial Release
