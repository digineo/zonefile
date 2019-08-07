require "minitest/autorun"
require "pathname"

$LOAD_PATH.push File.expand_path("../lib", __dir__)
require "zonefile"

$zf_output_shown = false

class TestZonefile < Minitest::Test #:nodoc:
  # make_my_diffs_pretty!

  def setup
    zonefile = Pathname.new(__dir__).join("test-zone.db")
    @zf = Zonefile.from_file(zonefile.to_s, "test-origin")
  end

  def run_again_with_zf_output!
    caller_name = caller[0][/`.*'/][1..-2]
    guard_var   = :"@__again_for__#{caller_name}__"
    return if instance_variable_get(guard_var)

    instance_variable_set guard_var, true

    # generate output and re-read @zf from it
    @zf = Zonefile.new(@zf.output, "test-origin")

    # call caller again
    send caller_name
  end

  def teardown
    return if $zf_output_shown || failures.empty?

    $zf_output_shown = true
    puts "\n\e[35m" << @zf.output << "\e[0m"
  end

  def test_next_serial
    Time.stub :now, Time.new(2019, 7, 18, 12, 34, 56, 0) do
      {
        0            => 2019071800, # non-date serials jump to current date
        1            => 2019071800,
        100          => 2019071800,
        -1           => 2019071800,
        2019071700   => 2019071800, # date-like serials will be incremented
        2019071800   => 2019071801,
        2019071899   => 2019071900,
        2020202019   => 2020202020,
        "0"          => 2019071800, # serial can be given as string
        "2020202019" => 2020202020,
        nil          => 2019071800, # impl detail: nil.to_i == 0
        ""           => 2019071800, # impl detail:  "".to_i == 0
        2**32 - 2    => 2**32 - 1,  # serial arithmetic
        2**32 - 1    => 0,
        2**32        => 1,
        2**32 + 1    => 2,
      }.each do |input, expected|
        actual = Zonefile.next_serial(input)
        assert actual.is_a?(String)
        assert_equal expected.to_s, actual, "expected next_serial(#{input}) to equal #{expected}, got #{actual}"
      end
    end
  end

  def test_expand_ttl
    [nil, ""].each do |input|
      assert_nil Zonefile.expand_ttl(input)
    end

    {
      0       => 0,
      60      => 60,
      84600   => 84600,
      "1w"    => 7 * 24 * 3600,
      "1d"    => 24 * 3600,
      "1H"    => 3600,
      "1s"    => 1,
      "2h42m" => 2 * 3600 + 42 * 60,
      "99d"   => 99 * 24 * 3600, # despite RFC1035, section 7.3
    }.each do |input, expected|
      actual = Zonefile.expand_ttl(input)
      assert_equal expected, actual, "expected expand_ttl(#{input}) to equal #{expected}, got #{actual}"
    end
  end

  def test_empty
    zf = Zonefile.new
    zf.soa[:refresh] = 1234
    assert zf.empty?
  end

  def test_setter
    data = [
      { class: "IN", name: "123", host: "test" },
      { name: "321", hosts: "test2" },
    ]
    @zf.ptr = data
    assert_equal data, @zf.ptr

    assert_raises(NoMethodError) do
      @zf.dont_exist(123, 123, 123)
    end
  end

  def test_soa
    assert_equal({
      origin:     "@",
      ttl:        3600,
      primary:    "ns0.dns-zoneparse-test.net.",
      email:      "support.dns-zoneparse-test.net.",
      serial:     "2000100501",
      refresh:    10800,
      retry:      3600,
      expire:     691200,
      minimumTTL: 86400,
    }, @zf.soa)

    run_again_with_zf_output!
  end

  def test_a
    assert_equal([
      { name: "@",         ttl: nil,   class: "IN", host: "127.0.0.1" },
      { name: "localhost", ttl: nil,   class: "IN", host: "127.0.0.1" },
      { name: "mail",      ttl: nil,   class: "IN", host: "127.0.0.1" },
      { name: "www",       ttl: nil,   class: "IN", host: "127.0.0.1" },
      { name: "www",       ttl: nil,   class: "in", host: "10.0.0.2" },
      { name: "www",       ttl: 43200, class: "IN", host: "10.0.0.3" }, # name preserved
      { name: "www",       ttl: nil,   class: nil,  host: "10.0.0.5" },
      { name: "foo",       ttl: nil,   class: "IN", host: "10.0.0.6" },
      { name: "mini",      ttl: nil,   class: nil,  host: "10.0.0.7" },
    ], @zf.a)

    run_again_with_zf_output!
  end

  def test_mx
    assert_equal([
      { name: "@",   ttl: nil, class: "IN", host: "mail",     pri: 10 },
      { name: "www", ttl: nil, class: "IN", host: "10.0.0.4", pri: 10 },
    ], @zf.mx)

    run_again_with_zf_output!
  end

  def test_cname
    assert_equal([
      { name: "ftp",    ttl: nil,   class: "IN", host: "www" },
      { name: "expand", ttl: 21600, class: "IN", host: "@" },
      { name: "cname",  ttl: nil,   class: "in", host: "b" },
    ], @zf.cname)

    run_again_with_zf_output!
  end

  def test_ns
    assert_equal([
      { name: nil,  ttl: 43200, class: "IN", host: "ns0.dns-zoneparse-test.net." },
      { name: "@",  ttl: nil,   class: "IN", host: "ns1.dns-zoneparse-test.net." },
      { name: "ns", ttl: nil,   class: "in", host: "@" },
    ], @zf.ns)

    run_again_with_zf_output!
  end

  def test_txt
    assert_equal([
      { name: "www",       ttl: nil, class: nil,  text: '"web;server"' },
      { name: "soup",      ttl: nil, class: "IN", text: '"This is a text message"' },
      { name: "txta",      ttl: nil, class: nil,  text: '"t=y; o=-"' },
      { name: "_kerberos", ttl: nil, class: "IN", text: "maxnet.ao" },
      { name: "a",         ttl: nil, class: "in", text: "cname" },
      { name: "a",         ttl: nil, class: "in", text: "@" },
    ], @zf.txt)

    run_again_with_zf_output!
  end

  def test_spf
    assert_equal([
      { name: "@",         ttl: nil, class: "IN", text: '"v=spf1 mx ~all"' },
      { name: "www",       ttl: nil, class: nil,  text: '"v=spf1 -all"' },
      { name: "elsewhere", ttl: nil, class: "IN", text: '"v=spf1 mx ?all"' },
    ], @zf.spf)

    run_again_with_zf_output!
  end

  def test_a4
    assert_equal([
      { name: "icarus", ttl: nil, class: "IN", host: "fe80::0260:83ff:fe7c:3a2a" },
    ], @zf.a4)

    run_again_with_zf_output!
  end

  def test_srv
    assert_equal([{
      name:   "_sip._tcp.example.com.",
      ttl:    86400,
      class:  "IN",
      pri:    "0",
      weight: "5",
      port:   "5060",
      host:   "sipserver.example.com."
    }], @zf.srv)

    run_again_with_zf_output!
  end

  def test_serial_generator
    old_serial = @zf.soa[:serial]
    new_serial = @zf.new_serial
    assert new_serial.to_i > old_serial.to_i
    newer_serial = @zf.new_serial
    assert_equal newer_serial.to_i - 1, new_serial.to_i
  end

  def test_serial_arithmetic
    @zf.soa[:serial] = (2**32).to_s
    @zf.new_serial
    assert_equal "1", @zf.soa[:serial]
  end

  def test_ptr
    assert_equal([{
      name:   "12.23.21.23.in-addr.arpa",
      ttl:    nil,
      class:  "IN",
      host:   "www.myhost.example.com."
    }], @zf.ptr)

    run_again_with_zf_output!
  end

  def test_ds
    assert_equal([
      { name: "ds1", ttl: nil, class: "IN", key_tag: 31528, algorithm: "5", digest_type: 1, digest: "2274EACD70C5CD6862E1C0262E99D48D9FDEC271" },
      { name: "ds2", ttl: nil, class: "IN", key_tag: 31528, algorithm: "5", digest_type: 1, digest: "2BB183AF5F22588179A53B0A98631FAD1A292118" },
    ], @zf.ds)

    run_again_with_zf_output!
  end

  def test_nsec
    assert_equal([
      { name: "alfa.example.com.", ttl: 86400, class: "IN", next: "host.example.com.", types: "A MX RRSIG NSEC TYPE1234"},
    ], @zf.nsec)

    run_again_with_zf_output!
  end

  def test_nsec3
    assert_equal([{
      name:       "alfa.example.com.",
      ttl:        nil,
      class:      "IN",
      algorithm:  "1",
      flags:      "1",
      iterations: "12",
      salt:       "aabbccdd",
      next:       "2vptu5timamqttgl4luu7kg2leoaor3s",
      types:      "A RRSIG",
    }], @zf.nsec3)

    run_again_with_zf_output!
  end

  def test_nsec3param
    assert_equal([{
      name:       "alfa.example.com.",
      ttl:        nil,
      class:      "IN",
      algorithm:  "1",
      flags:      "0",
      iterations: "12",
      salt:       "aabbccdd",
    }], @zf.nsec3param)

    run_again_with_zf_output!
  end

  def test_naptr
    assert_equal([{
      name:        "urn.example.com.",
      ttl:         nil,
      class:       "IN",
      order:       100,
      preference:  50,
      flags:       '"s"',
      service:     '"http+N2L+N2C+N2R"',
      regexp:      '""',
      replacement: "www.example.com.",
    }], @zf.naptr)

    run_again_with_zf_output!
  end

  def test_dnskey
    pkey = <<~PUBLIC_KEY.gsub(/\s+/, "").strip
      AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajI
      QKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJB
      OztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==
    PUBLIC_KEY

    assert_equal([
      { name: "example.com.", ttl: 86400, class: "IN", flag: 256, protocol: 3, algorithm: "5", public_key: pkey },
      { name: "example.net.", ttl: 86400, class: "IN", flag: 256, protocol: 3, algorithm: "5", public_key: pkey },
    ], @zf.dnskey)

    run_again_with_zf_output!
  end

  def test_rrsig
    sig = <<~SIGNATURE.gsub(/\s+/, "").strip
      oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKd
      fb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoX
      mJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=
    SIGNATURE

    assert_equal([{
      name:         "host.example.com.",
      ttl:          86400,
      class:        "IN",
      type_covered: "A",
      algorithm:    "5",
      labels:       3,
      original_ttl: 86400,
      expiration:   20030322173103,
      inception:    20030220173103,
      key_tag:      2642,
      signer:       "example.com.",
      signature:    sig,
    }], @zf.rrsig)

    run_again_with_zf_output!
  end

  def test_tlsa
    sig = <<~SIGNATURE.gsub("\n", " ").strip
      92003ba34942dc74152e2f2c408d29ec
      a5a520e7f2e06bb944f4dca346baf63c
      1b177615d466f6c4b71c216a50292bd5
      8c9ebdd2f74e38fe51ffd48c43326cbc
    SIGNATURE

    assert_equal([{
      name:              "_443._tcp.www.example.com.",
      ttl:               86400,
      class:             "IN",
      certificate_usage: 1,
      selector:          1,
      matching_type:     2,
      data:              sig,
    }], @zf.tlsa)

    run_again_with_zf_output!
  end

  def test_origin
    assert_equal "test-zone.db", @zf.origin

    run_again_with_zf_output!
  end

  def test_caa
    assert_equal([
      { name: "example.com.",      ttl: nil, class: "IN", flag: 0, tag: "issue", value: '"ca.example.com"' },
      { name: "example.com.",      ttl: nil, class: "IN", flag: 0, tag: "iodef", value: '"mailto:security@example.com"' },
      { name: "host.example.com.", ttl: nil, class: "IN", flag: 0, tag: "issue", value: '";"' },
    ], @zf.caa)

    run_again_with_zf_output!
  end

  def test_resource_records
    subject = @zf.resource_records

    actual = subject.each_with_object("") do |(k, rrs), str|
      rrs = [rrs] if k == :soa
      rrs.each do |rr|
        str << [rr.name, rr.ttl, rr.class, rr.type, rr.data].join("\t") << "\n"
      end
    end

    expected = Pathname.new(__dir__).join("test-zone.rr").read
    assert_equal expected, actual
    run_again_with_zf_output!
  end

  def test_resource_records_powerdns
    subject = @zf.resource_records(powerdns_sql: true)

    actual = subject.each_with_object("") do |(k, rrs), str|
      rrs = [rrs] if k == :soa
      rrs.each do |rr|
        str << [rr.name, rr.ttl, rr.class, rr.type, rr.data].join("\t") << "\n"
      end
    end

    expected = Pathname.new(__dir__).join("test-zone.pdns").read
    assert_equal expected, actual
    # this won't work: run_again_with_zf_output!
  end
end
