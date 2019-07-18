require "minitest/autorun"
require "pathname"

$LOAD_PATH.push File.expand_path("../lib", __dir__)
require "zonefile"

$zf_output_shown = false

class ZonefileTestCase < Minitest::Unit::TestCase #:nodoc:
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
    return # if $zf_output_shown || failures.empty?

    $zf_output_shown = true
    puts "\n\e[35m" << @zf.output << "\e[0m"
  end

  def test_next_serial
    Time.stub :now, Time.new(2019, 7, 18, 12, 34, 56, 0) do
      {
        0          => 2019071800,
        1          => 2019071800,
        100        => 2019071800,
        2019071700 => 2019071800,
        2019071800 => 2019071801,
        2019071899 => 2019071900,
        2020202019 => 2020202020,
      }.each do |input, expected|
        actual = Zonefile.next_serial(input.to_s)
        assert_equal expected.to_s, actual
      end
    end
  end

  def test_empty
    zf = Zonefile.new
    zf.soa[:refresh] = 1234
    assert zf.empty?
  end

  def test_setter
    data = [{ class: "IN", name: "123", host: "test" },
            { name: "321", hosts: "test2" }]
    @zf.ptr = data
    assert_equal 2, @zf.ptr.size
    assert @zf.ptr[0][:host] == data[0][:host]
    assert @zf.ptr[1][:name] == data[1][:name]
    assert_raises(NoMethodError) do
      @zf.dont_exist(123, 123, 123)
    end
  end

  def test_soa
    assert_equal "86400", @zf.soa[:minimumTTL]
    assert_equal "691200", @zf.soa[:expire]
    assert_equal "3600", @zf.soa[:retry]
    assert_equal "10800", @zf.soa[:refresh]
    assert_equal "2000100501", @zf.soa[:serial]
    assert_equal "support.dns-zoneparse-test.net.", @zf.soa[:email]
    assert_equal "ns0.dns-zoneparse-test.net.", @zf.soa[:primary]

    run_again_with_zf_output!
  end

  def test_a
    assert_equal 9,           @zf.a.size
    assert_equal "mini",      @zf.a.last[:name]
    assert_equal "10.0.0.7",  @zf.a.last[:host]
    assert_equal "127.0.0.1", @zf.a.first[:host]

    a = @zf.a.find {|rr| rr[:host] == "10.0.0.3" }
    assert_equal "43200", a[:ttl]
    assert_equal "www", a[:name].to_s # name preserved

    run_again_with_zf_output!
  end

  def test_mx
    assert_equal 2, @zf.mx.size
    assert_equal 10, @zf.mx.first[:pri]

    run_again_with_zf_output!
  end

  def test_cname
    www = @zf.cname.find {|rr| rr[:host] == "www" }
    refute_nil www

    run_again_with_zf_output!
  end

  def test_ns
    assert_equal "ns0.dns-zoneparse-test.net.", @zf.ns[0][:host]
    assert_equal "ns1.dns-zoneparse-test.net.", @zf.ns[1][:host]

    run_again_with_zf_output!
  end

  def test_txt
    # puts @zf.txt.inspect
    assert_equal '"web;server"', @zf.txt[0][:text]
    assert_equal "IN", @zf.txt[1][:class]
    assert_equal "soup", @zf.txt[1][:name]
    assert_equal "txta", @zf.txt[2][:name]
    assert_equal "IN", @zf.txt[3][:class]
    assert_equal "\"t=y; o=-\"", @zf.txt[2][:text]
    assert_equal "maxnet.ao", @zf.txt[3][:text]
    assert_equal "_kerberos", @zf.txt[3][:name]

    assert_equal 4, @zf.txt.size

    run_again_with_zf_output!
  end

  def test_spf
    assert_equal '"v=spf1 mx ~all"', @zf.spf[0][:text]
    assert_equal "IN", @zf.spf[0][:class]
    assert_equal "@", @zf.spf[0][:name]
    assert_equal '"v=spf1 -all"', @zf.spf[1][:text]
    assert_equal "www", @zf.spf[1][:name]
    assert_nil @zf.spf[1][:class]
    assert_equal "elsewhere", @zf.spf[2][:name]
    assert_equal '"v=spf1 mx ?all"', @zf.spf[2][:text]

    assert_equal 3, @zf.spf.size

    run_again_with_zf_output!
  end

  def test_a4
    assert_equal "icarus", @zf.a4[0][:name]
    assert_equal "IN", @zf.a4[0][:class]
    assert_equal 1, @zf.a4.size
    assert_equal "fe80::0260:83ff:fe7c:3a2a", @zf.a4[0][:host]

    run_again_with_zf_output!
  end

  def test_srv
    assert_equal "_sip._tcp.example.com.", @zf.srv[0][:name]
    assert_equal "86400", @zf.srv[0][:ttl]
    assert_equal "0", @zf.srv[0][:pri]
    assert_equal "5", @zf.srv[0][:weight]
    assert_equal "5060", @zf.srv[0][:port]
    assert_equal "sipserver.example.com.", @zf.srv[0][:host]

    run_again_with_zf_output!
  end

  def test_serial_generator
    old = @zf.soa[:serial]
    new = @zf.new_serial
    assert new.to_i > old.to_i
    newer = @zf.new_serial
    assert newer.to_i - 1, new

    @zf.soa[:serial] = "9999889901"
    @zf.new_serial
    assert_equal "9999889902", @zf.soa[:serial]
  end

  def test_ptr
    assert_equal "12.23.21.23.in-addr.arpa", @zf.ptr[0][:name]
    assert_equal "www.myhost.example.com.",  @zf.ptr[0][:host]

    run_again_with_zf_output!
  end

  def test_ds
    assert_equal "ds1", @zf.ds[0][:name]
    assert_equal 31528, @zf.ds[0][:key_tag]
    assert_equal "5", @zf.ds[0][:algorithm]
    assert_equal 1, @zf.ds[0][:digest_type]
    assert_equal "2274EACD70C5CD6862E1C0262E99D48D9FDEC271", @zf.ds[0][:digest]
    assert_equal "ds2", @zf.ds[1][:name]
    assert_equal 31528, @zf.ds[1][:key_tag]
    assert_equal "5", @zf.ds[1][:algorithm]
    assert_equal 1, @zf.ds[1][:digest_type]
    assert_equal "2BB183AF5F22588179A53B0A98631FAD1A292118", @zf.ds[1][:digest]

    run_again_with_zf_output!
  end

  def test_nsec
    assert_equal "alfa.example.com.", @zf.nsec[0][:name]
    assert_equal "host.example.com.", @zf.nsec[0][:next]
    assert_equal "A MX RRSIG NSEC TYPE1234", @zf.nsec[0][:types]

    run_again_with_zf_output!
  end

  def test_nsec3
    assert_equal "1", @zf.nsec3[0][:algorithm]
    assert_equal "1", @zf.nsec3[0][:flags]
    assert_equal "12", @zf.nsec3[0][:iterations]
    assert_equal "aabbccdd", @zf.nsec3[0][:salt]
    assert_equal "2vptu5timamqttgl4luu7kg2leoaor3s", @zf.nsec3[0][:next]
    assert_equal "A RRSIG", @zf.nsec3[0][:types]

    run_again_with_zf_output!
  end

  def test_nsec3param
    assert_equal "1", @zf.nsec3param[0][:algorithm]
    assert_equal "0", @zf.nsec3param[0][:flags]
    assert_equal "12", @zf.nsec3param[0][:iterations]
    assert_equal "aabbccdd", @zf.nsec3param[0][:salt]

    run_again_with_zf_output!
  end

  def test_naptr
    assert_equal "urn.example.com.", @zf.naptr[0][:name]
    assert_equal 100, @zf.naptr[0][:order]
    assert_equal 50, @zf.naptr[0][:preference]
    assert_equal "\"s\"", @zf.naptr[0][:flags]
    assert_equal "\"http+N2L+N2C+N2R\"", @zf.naptr[0][:service]
    assert_equal "\"\"", @zf.naptr[0][:regexp]
    assert_equal "www.example.com.", @zf.naptr[0][:replacement]

    run_again_with_zf_output!
  end

  def test_dnskey
    assert_equal "example.com.", @zf.dnskey[0][:name]
    assert_equal 256, @zf.dnskey[0][:flag]
    assert_equal 3, @zf.dnskey[0][:protocol]
    assert_equal "5", @zf.dnskey[0][:algorithm]
    pkey = <<PUBLIC_KEY.gsub(/\s+/, "").strip
           AQPSKmynfzW4kyBv015MUG2DeIQ3
           Cbl+BBZH4b/0PY1kxkmvHjcZc8no
           kfzj31GajIQKY+5CptLr3buXA10h
           WqTkF7H6RfoRqXQeogmMHfpftf6z
           Mv1LyBUgia7za6ZEzOJBOztyvhjL
           742iU/TpPSEDhm2SNKLijfUppn1U
           aNvv4w==
PUBLIC_KEY
    assert_equal pkey, @zf.dnskey[0][:public_key]
    assert_equal "example.net.", @zf.dnskey[1][:name]
    assert_equal 256, @zf.dnskey[1][:flag]
    assert_equal 3, @zf.dnskey[1][:protocol]
    assert_equal "5", @zf.dnskey[1][:algorithm]
    assert_equal pkey, @zf.dnskey[1][:public_key]

    run_again_with_zf_output!
  end

  def test_rrsig
    assert_equal "host.example.com.", @zf.rrsig[0][:name]
    assert_equal "A", @zf.rrsig[0][:type_covered]
    assert_equal "5", @zf.rrsig[0][:algorithm]
    assert_equal 3, @zf.rrsig[0][:labels]
    assert_equal 86400, @zf.rrsig[0][:original_ttl]
    assert_equal 2003_03_22_17_31_03, @zf.rrsig[0][:expiration]
    assert_equal 2003_02_20_17_31_03, @zf.rrsig[0][:inception]
    assert_equal 2642, @zf.rrsig[0][:key_tag]
    assert_equal "example.com.", @zf.rrsig[0][:signer]
    sig = <<SIGNATURE.gsub(/\s+/, "").strip
        oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr
        PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o
        B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t
        GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG
        J5D6fwFm8nN+6pBzeDQfsS3Ap3o=
SIGNATURE
    assert_equal sig, @zf.rrsig[0][:signature]

    run_again_with_zf_output!
  end

  def test_tlsa
    assert_equal "_443._tcp.www.example.com.", @zf.tlsa[0][:name]
    assert_equal "86400", @zf.srv[0][:ttl]
    assert_equal 1, @zf.tlsa[0][:certificate_usage]
    assert_equal 1, @zf.tlsa[0][:selector]
    assert_equal 2, @zf.tlsa[0][:matching_type]

    sig = <<SIGNATURE.gsub(/\s+/, "").strip
        92003ba34942dc74152e2f2c408d29ec
        a5a520e7f2e06bb944f4dca346baf63c
        1b177615d466f6c4b71c216a50292bd5
        8c9ebdd2f74e38fe51ffd48c43326cbc
SIGNATURE
    assert_equal sig, @zf.tlsa[0][:data].gsub(/\s+/, "")

    run_again_with_zf_output!
  end

  def test_origin
    assert_equal "test-zone.db", @zf.origin

    run_again_with_zf_output!
  end

  def test_caa
    assert_equal "example.com.", @zf.caa[0][:name]
    assert_equal 0, @zf.caa[0][:flag]
    assert_equal "issue", @zf.caa[0][:tag]
    assert_equal '"ca.example.com"', @zf.caa[0][:value]

    assert_equal "example.com.", @zf.caa[1][:name]
    assert_equal 0, @zf.caa[1][:flag]
    assert_equal "iodef", @zf.caa[1][:tag]
    assert_equal '"mailto:security@example.com"', @zf.caa[1][:value]

    assert_equal "host.example.com.", @zf.caa[2][:name]
    assert_equal 0, @zf.caa[2][:flag]
    assert_equal "issue", @zf.caa[2][:tag]
    assert_equal '";"', @zf.caa[2][:value]

    run_again_with_zf_output!
  end

  def test_resource_records
    subject = @zf.resource_records

    expected = Pathname.new(__dir__).join("test-zone.rr").read
    actual = subject.each_with_object("") do |(k, rrs), str|
      rrs = [rrs] if k == :soa
      rrs.each do |rr|
        str << [rr.name, rr.ttl, rr.class, rr.type, rr.data].join("\t") << "\n"
      end
    end

    assert_equal expected, actual

    run_again_with_zf_output!
  end
end
