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
