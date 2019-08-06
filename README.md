# Ruby Zonefile - Parse and manipulate DNS Zone Files.

[![CircleCI](https://circleci.com/gh/digineo/zonefile.svg?style=svg)](https://circleci.com/gh/digineo/zonefile)

## Description

This class can read, manipulate and create DNS zone files. It
supports A, AAAA, MX, NS, SOA, TXT, CNAME, PTR and SRV records. The
data can be accessed by the instance method of the same name.

All except SOA return an array of hashes containing the named data;
SOA directly returns the hash since there can only be one SOA
information.

The following hash keys are returned per record type:

| Type | Keys |
|:-----|:-----|
| SOA        | `:ttl`, `:primary`, `:email`, `:serial`, `:refresh`, `:retry`, `:expire`, `:minimumTTL` |
| A          | `:name`, `:ttl`, `:class`, `:host` |
| MX         | `:name`, `:ttl`, `:class`, `:pri`, `:host` |
| NS         | `:name`, `:ttl`, `:class`, `:host` |
| CAA        | `:name`, `:ttl`, `:class`, `:flag`, `:tag`, `:value` |
| CNAME      | `:name`, `:ttl`, `:class`, `:host` |
| TXT        | `:name`, `:ttl`, `:class`, `:text` |
| A4 (AAAA)  | `:name`, `:ttl`, `:class`, `:host` |
| PTR        | `:name`, `:ttl`, `:class`, `:host` |
| SRV        | `:name`, `:ttl`, `:class`, `:pri`, `:weight`, `:port`, `:host` |
| DS         | `:name`, `:ttl`, `:class`, `:key_tag`, `:algorithm`, `:digest_type`, `:digest` |
| DNSKEY     | `:name`, `:ttl`, `:class`, `:flag`, `:protocol`, `:algorithm`, `:public_key` |
| RRSIG      | `:name`, `:ttl`, `:class`, `:type_covered`, `:algorithm`, `:labels`, `:original_ttl`, `:expiration`, `:inception`, `:key_tag`, `:signer` `:signature` |
| NSEC       | `:name`, `:ttl`, `:class`, `:next`, `:types` |
| NSEC3      | `:name`, `:ttl`, `:class`, `:algorithm`, `:flags`, `:iterations`, `:salt`, `:next`, `:types` |
| NSEC3PARAM | `:name`, `:ttl`, `:class`, `:algorithm`, `:flags`, `:iterations`, `:salt` |
| TLSA       | `:name`, `:ttl`, `:class`, `:certificate_usage`, `:selector`, `:matching_type`, `:data` |
| NAPTR      | `:name`, `:ttl`, `:class`, `:order`, `:preference`, `:flags`, `:service`, `:regexp`, `:replacement` |
| SPF        | `:name`, `:ttl`, `:class`, `:text` |

This list might be incomplete. Inspect `Zonefile::RECORDS` for the actual
list of supported record types. Please note that the SOA record type is
omitted from that list.


# Installation

Add this to your `Gemfile` and run `bundle install`:

```ruby
gem "zonefile", "~> 2.0", git: "https://github.com/digineo/zonefile.git"
```


# Examples

## Read a Zonefile

```ruby
zf = Zonefile.from_file('/path/to/zonefile.db')

# Display MX-Records
zf.mx.each do |mx_record|
  puts "Mail Exchagne with priority: #{mx_record[:pri]} --> #{mx_record[:host]}"
end

# Show SOA TTL
puts "Record Time To Live: #{zf.soa[:ttl]}"

# Show A-Records
zf.a.each do |a_record|
  puts "#{a_record[:name]} --> #{a_record[:host]}"
end
```

## Manipulate a Zonefile

```ruby
zf = Zonefile.from_file('/path/to/zonefile.db')

# Change TTL and add an A-Record
zf.soa[:ttl] = '123123' # Change the SOA ttl
zf.a << { class: 'IN', name: 'www', host: '192.168.100.1', ttl: 3600 }  # add A-Record

# Setting PTR records (deleting existing ones)

zf.ptr = [{ class: 'IN', name: '1.100.168.192.in-addr.arpa', host: 'my.host.com' },
          { class: 'IN', name: '2.100.168.192.in-addr.arpa', host: 'me.host.com' }]

# Increase Serial Number
zf.new_serial

# Print new zonefile
puts "New Zonefile: \n#{zf.output}"
```

# Hacking

To get started, run these commands:

```console
$ git clone git@github.com:digineo/zonefile.git
$ cd zonefile
$ bundle install
$ rake # invokes test + rubocop
```

# License

MIT License

# Authors

- Martin Boese, based on Simon Flack Perl library DNS::ZoneParse
- Andy Newton, patch to support various additional records
- Digineo GmbH:
  - Julian Kornberger, patch to support TLSA records
  - Dominik Menke, various improvements
- Nic P, SPF support
- Leon M, Fixes
