#
# = Ruby Zonefile - Parse and manipulate DNS Zone Files.
#
# == Description
# This class can read, manipulate and create DNS zone files. It supports A, AAAA, MX, NS, SOA,
# TXT, CNAME, PTR and SRV records. The data can be accessed by the instance method of the same
# name. All except SOA return an array of hashes containing the named data. SOA directly returns the
# hash since there can only be one SOA information.
#
# The following hash keys are returned per record type:
#
# * SOA
#   - :ttl, :primary, :email, :serial, :refresh, :retry, :expire, :minimumTTL
# * A
#   - :name, :ttl, :class, :host
# * MX
#   - :name, :ttl, :class, :pri, :host
# * NS
#   - :name, :ttl, :class, :host
# * CNAME
#   - :name, :ttl, :class, :host
# * TXT
#   - :name, :ttl, :class, :text
# * A4 (AAAA)
#   - :name, :ttl, :class, :host
# * PTR
#   - :name, :ttl, :class, :host
# * SRV
#   - :name, :ttl, :class, :pri, :weight, :port, :host
# * DS
#   - :name, :ttl, :class, :key_tag, :algorithm, :digest_type, :digest
# * DNSKEY
#   - :name, :ttl, :class, :flag, :protocol, :algorithm, :public_key
# * RRSIG
#   - :name, :ttl, :class, :type_covered, :algorithm, :labels, :original_ttl,
#     :expiration, :inception, :key_tag, :signer, :signature
# * NSEC
#   - :name, :ttl, :class, :next, :types
# * NSEC3
#   - :name, :ttl, :class, :algorithm, :flags, :iterations, :salt, :next, :types
# * NSEC3PARAM
#   - :name, :ttl, :class, :algorithm, :flags, :iterations, :salt
# * TLSA
#   - :name, :ttl, :class, :certificate_usage, :selector, :matching_type, :data
# * NAPTR
#   - :name, :ttl, :class, :order, :preference, :flags, :service, :regexp, :replacement
# * SPF
#   - :name, :ttl, :class, :text
#
# == Examples
#
# === Read a Zonefile
#
#  zf = Zonefile.from_file('/path/to/zonefile.db')
#
#  # Display MX-Records
#  zf.mx.each do |mx_record|
#     puts "Mail Exchagne with priority: #{mx_record[:pri]} --> #{mx_record[:host]}"
#  end
#
#  # Show SOA TTL
#  puts "Record Time To Live: #{zf.soa[:ttl]}"
#
#  # Show A-Records
#  zf.a.each do |a_record|
#     puts "#{a_record[:name]} --> #{a_record[:host]}"
#  end
#
#
# ==== Manipulate a Zonefile
#
#  zf = Zonefile.from_file('/path/to/zonefile.db')
#
#  # Change TTL and add an A-Record
#
#  zf.soa[:ttl] = '123123'  # Change the SOA ttl
#  zf.a << { :class => 'IN', :name => 'www', :host => '192.168.100.1', :ttl => 3600 }  # add A-Record
#
#  # Setting PTR records (deleting existing ones)
#
#  zf.ptr = [ { :class => 'IN', :name=>'1.100.168.192.in-addr.arpa', :host => 'my.host.com' },
#             { :class => 'IN', :name=>'2.100.168.192.in-addr.arpa', :host => 'me.host.com' } ]
#
#  # Increase Serial Number
#  zf.new_serial
#
#  # Print new zonefile
#  puts "New Zonefile: \n#{zf.output}"
#
# == Name attribute magic
#
# Since 1.04 the :name attribute is preserved and returned as defined in a previous record if a zonefile entry
# omits it. This should be the expected behavior for most users.
# You can switch this off globally by calling Zonefile.preserve_name(false)
#
# This options is deprecated in version 1.99 and will be removed in 2.0.
#
# == Authors
#
# Martin Boese, based on Simon Flack Perl library DNS::ZoneParse
#
# Andy Newton, patch to support various additional records
#
# Dominik Menke (Digineo GmbH), various improvements
#
class Zonefile
  RECORDS = %i[
    a a4 cname dnskey ds mx naptr ns nsec nsec3 nsec3param ptr rrsig soa spf srv tlsa txt
  ].freeze

  attr_reader :records
  attr_reader :soa
  attr_reader :data
  attr_reader :origin # global $ORIGIN option
  attr_reader :ttl    # global $TTL option

  @@preserve_name = true

  # For compatibility: This can switches off copying of the :name from the
  # previous record in a zonefile if found omitted.
  # This was zonefile's behavior in <= 1.03 .
  def self.preserve_name(do_preserve_name)
    @@preserve_name = do_preserve_name
  end

  RECORDS.each do |name|
    next if name == :soa

    define_method name do
      @records[name]
    end

    define_method "#{name}=" do |val|
      @records[name] = val
    end
  end

  # Compact a zonefile content - removes empty lines, comments,
  # converts tabs into spaces etc...
  def self.simplify(content)
    # concatenate everything split over multiple lines in parentheses - remove ;-comments in block
    flattened = content.gsub(/(\([^\)]*?\))/) {|m|
      m.split(/\n/)
        .map {|l| l.gsub(/\;.*$/, "") }
        .join("\n")
        .gsub(/[\r\n]/, "")
        .gsub(/[\(\)]/, "")
    }

    normalized = flattened.split(/\n/).map {|line|
      r = line
        .gsub(/\t/, " ")
        .gsub(/\s+/, " ")

      # FIXME: this is ugly and not accurate, couldn't find proper regex:
      #   Don't strip ';' if it's quoted. Happens a lot in TXT records.
      (0..(r.length - 1)).find_all {|i| r[i].chr == ";" }.each do |comment_idx|
        unless r[(comment_idx + 1)..-1].index(/['"]/)
          r = r[0..(comment_idx - 1)]
          break
        end
      end

      r
    }
    normalized.delete_if {|line| line.empty? || line[0].chr == ";" }.join("\n")
  end

  # create a new zonefile object by passing the content of the zonefile
  def initialize(zonefile = "", file_name = nil, origin = nil)
    @data = zonefile
    @filename = file_name
    @origin = origin || (file_name ? file_name.split("/").last : "")

    @records = {}
    @soa = {}
    RECORDS.each {|r| @records[r] = [] }
    parse
  end

  # True if no records (except sao) is defined in this file
  def empty?
    RECORDS.each do |r|
      return false unless @records[r].empty?
    end
    true
  end

  # Create a new object by reading the content of a file
  def self.from_file(file_name, origin = nil)
    Zonefile.new(File.read(file_name), file_name.split("/").last, origin)
  end

  def add_record(type, data = {})
    if @@preserve_name
      @lastname = data[:name] if data[:name].to_s != ""
      data[:name] = @lastname if data[:name].to_s == ""
    end
    @records[type.downcase.intern] << data
  end

  # Generates a new serial number in the format of YYYYMMDDII if possible
  def new_serial
    base = Time.now.strftime("%Y%m%d")

    if (@soa[:serial].to_i / 100) > base.to_i
      ns = @soa[:serial].to_i + 1
      @soa[:serial] = ns.to_s
      return ns.to_s
    end

    serial = format("%<base>s00", base: base).to_i
    serial += 1 while serial <= @soa[:serial].to_i
    @soa[:serial] = serial.to_s
  end

  module RE
    VALID_NAME = /[-@._*a-zA-Z0-9]+/.freeze
    VALID_IP6  = /[-@._*a-zA-Z0-9:]+/.freeze # ??
    RR_CLASS   = /\b(?:IN|HS|CH)\b/i.freeze
    RR_TTL     = /(?:\d+[wdhms]?)+/i.freeze
    TTL_CLS    = %r{
      (?:(#{RR_TTL})\s)?
      (?:(#{RR_CLASS})\s)?
    }ox.freeze
    BASE64     = %r{ [a-zA-Z0-9+/\s]*={0,2} }x.freeze
    HEXADEIMAL = /([\sa-fA-F0-9]*)/.freeze
    QUOTED     = /(\"[^\"]*\")/.freeze

    DIRECTIVE_ORIGIN = /^\$ORIGIN\s*(#{VALID_NAME})/oi.freeze
    DIRECTIVE_TTL    = /^\$TTL\s+(#{RR_TTL})/oi.freeze

    SOA = %r{
      ^(#{VALID_NAME}) \s+ #{TTL_CLS} \b SOA \s+ (#{VALID_NAME}) \s+
      (#{VALID_NAME}) \s*
      (#{RR_TTL}) \s+
      (#{RR_TTL}) \s+
      (#{RR_TTL}) \s+
      (#{RR_TTL}) \s+
      (#{RR_TTL}) \s*
    }oix.freeze

    NS = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b NS \s (#{VALID_NAME})
    }oix.freeze

    A = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b A \s (#{VALID_NAME})
    }oix.freeze

    CNAME = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b CNAME \s (#{VALID_NAME})
    }oix.freeze

    AAAA = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b AAAA \s (#{VALID_IP6})$
    }oix.freeze

    MX = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b MX \s (\d+) \s (#{VALID_NAME})$
    }oix.freeze

    SRV = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b SRV \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (#{VALID_NAME})
    }oix.freeze

    DS = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b DS \s
      (\d+) \s
      (\w+) \s
      (\d+) \s
      #{HEXADEIMAL}
    }oix.freeze

    NSEC = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b NSEC \s
      (#{VALID_NAME}) \s
      ([\s\w]*)
    }oix.freeze

    NSEC3 = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b NSEC3 \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (-|[A-F0-9]*) \s
      ([A-Z2-7=]*) \s
      ([\s\w]*)
    }oix.freeze

    NSEC3PARAM = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b NSEC3PARAM \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (-|[A-F0-9]*)
    }oix.freeze

    DNSKEY = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b DNSKEY \s
      (\d+) \s
      (\d+) \s
      (\w+) \s
      (#{BASE64})
    }oix.freeze

    RRSIG = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b RRSIG \s
      (\w+) \s
      (\w+) \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (#{VALID_NAME}) \s
      (#{BASE64})
    }oix.freeze

    TLSA = %r{
      ^(#{VALID_NAME}) \s* #{TTL_CLS} \b TLSA \s
      (\d+) \s
      (\d+) \s
      (\d+) \s
      (#{BASE64})
    }oix.freeze

    NAPTR = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b NAPTR \s
      (\d+) \s
      (\d+) \s
      #{QUOTED} \s
      #{QUOTED} \s
      #{QUOTED} \s
      (#{VALID_NAME})
    }oix.freeze

    PTR = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b PTR \s+ (#{VALID_NAME})$
    }oix.freeze

    TXT = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b TXT \s+ (.*)$
    }oix.freeze

    SPF = %r{
      ^(#{VALID_NAME})? \s* #{TTL_CLS} \b SPF \s+ (.*)$
    }oix.freeze
  end
  private_constant :RE

  def parse_line(line)
    # rubocop:disable Style/BracesAroundHashParameters
    case line
    when RE::DIRECTIVE_ORIGIN
      @origin = $1
    when RE::DIRECTIVE_TTL
      @ttl = $1
    when RE::SOA
      @soa.merge!({
        origin:     $1,
        ttl:        @soa[:ttl] || $2 || "",
        primary:    $4,
        email:      $5,
        serial:     $6,
        refresh:    $7,
        retry:      $8,
        expire:     $9,
        minimumTTL: $10,
      })
    when RE::NS
      add_record("ns", {
        name:  $1,
        ttl:   $2,
        class: $3,
        host:  $4,
      })
    when RE::A
      add_record("a", {
        name:  $1,
        ttl:   $2,
        class: $3,
        host:  $4,
      })
    when RE::AAAA
      add_record("a4", {
        name:  $1,
        ttl:   $2,
        class: $3,
        host:  $4,
      })
    when RE::CNAME
      add_record("cname", {
        name:  $1,
        ttl:   $2,
        class: $3,
        host:  $4,
      })
    when RE::PTR
      add_record("ptr", {
        name:  $1,
        ttl:   $2,
        class: $3,
        host:  $4,
      })
    when RE::DNSKEY
      add_record("dnskey", {
        name:       $1,
        ttl:        $2,
        class:      $3,
        flag:       $4.to_i,
        protocol:   $5.to_i,
        algorithm:  $6,
        public_key: $7.gsub(/\s/, ""),
      })
    when RE::DS
      add_record("ds", {
        name:        $1,
        ttl:         $2,
        class:       $3,
        key_tag:     $4.to_i,
        algorithm:   $5,
        digest_type: $6.to_i,
        digest:      $7.gsub(/\s/, ""),
      })
    when RE::MX
      add_record("mx", {
        name:  $1,
        ttl:   $2,
        class: $3,
        pri:   $4.to_i,
        host:  $5,
      })
    when RE::NAPTR
      add_record("naptr", {
        name:        $1,
        ttl:         $2,
        class:       $3,
        order:       $4.to_i,
        preference:  $5.to_i,
        flags:       $6,
        service:     $7,
        regexp:      $8,
        replacement: $9,
      })
    when RE::NSEC
      add_record("nsec", {
        name:  $1,
        ttl:   $2,
        class: $3,
        next:  $4,
        types: $5.strip,
      })
    when RE::NSEC3
      add_record("nsec3", {
        name:       $1,
        ttl:        $2,
        class:      $3,
        algorithm:  $4,
        flags:      $5,
        iterations: $6,
        salt:       $7,
        next:       $8.strip,
        types:      $9.strip,
      })
    when RE::NSEC3PARAM
      add_record("nsec3param", {
        name:       $1,
        ttl:        $2,
        class:      $3,
        algorithm:  $4,
        flags:      $5,
        iterations: $6,
        salt:       $7,
      })
    when RE::RRSIG
      add_record("rrsig", {
        name:         $1,
        ttl:          $2,
        class:        $3,
        type_covered: $4,
        algorithm:    $5,
        labels:       $6.to_i,
        original_ttl: $7.to_i,
        expiration:   $8.to_i,
        inception:    $9.to_i,
        key_tag:      $10.to_i,
        signer:       $11,
        signature:    $12.gsub(/\s/, ""),
      })
    when RE::SPF
      add_record("spf", {
        name:  $1,
        ttl:   $2,
        class: $3,
        text:  $4.strip,
      })
    when RE::SRV
      add_record("srv", {
        name:   $1,
        ttl:    $2,
        class:  $3,
        pri:    $4,
        weight: $5,
        port:   $6,
        host:   $7,
      })
    when RE::TLSA
      add_record("tlsa", {
        name:              $1,
        ttl:               $2,
        class:             $3,
        certificate_usage: $4.to_i,
        selector:          $5.to_i,
        matching_type:     $6.to_i,
        data:              $7,
      })
    when RE::TXT
      add_record("txt", {
        name:  $1,
        ttl:   $2,
        class: $3,
        text:  $4.strip,
      })
    end
    # rubocop:enable Style/BracesAroundHashParameters
  end

  def parse
    Zonefile.simplify(@data).each_line do |line|
      parse_line(line)
    end
  end

  # Build a new nicely formatted Zonefile
  def output
    out = <<~ENDH
      ;
      ;  Database file #{@filename || 'unknown'} for #{@origin || 'unknown'} zone.
      ;	Zone version: #{soa[:serial]}
      ;
      #{soa[:origin]}		#{soa[:ttl]} IN  SOA  #{soa[:primary]} #{soa[:email]} (
      				#{soa[:serial]}	; serial number
      				#{soa[:refresh]}	; refresh
      				#{soa[:retry]}	; retry
      				#{soa[:expire]}	; expire
      				#{soa[:minimumTTL]}	; minimum TTL
      				)

      #{@origin ? "$ORIGIN #{@origin}" : ''}
      #{@ttl ? "$TTL #{@ttl}" : ''}
    ENDH

    {
      ns:         ["NS",         :host],
      mx:         ["MX",         :pri, :host],
      a:          ["A",          :host],
      cname:      ["CNAME",      :host],
      a4:         ["AAAA",       :host],
      txt:        ["TXT",        :text],
      spf:        ["SPF",        :text],
      srv:        ["SRV",        :pri, :weight, :port, :host],
      ptr:        ["PTR",        :host],
      ds:         ["DS",         :key_tag, :algorithm, :digest_type, :digest],
      nsec:       ["NSEC",       :next, :types],
      nsec3:      ["NSEC3",      :algorithm, :flags, :iterations, :salt, :next, :types],
      nsec3param: ["NSEC3PARAM", :algorithm, :flags, :iterations, :salt],
      dnskey:     ["DNSKEY",     :flag, :protocol, :algorithm, :public_key],
      rrsig:      ["RRSIG",      :type_covered, :algorithm, :labels, :original_ttl, :expiration, :inception, :key_tag, :signer, :signature],
      tlsa:       ["TLSA",       :certificate_usage, :selector, :matching_type, :data],
      naptr:      ["NAPTR",      :order, :preference, :flags, :service, :regexp, :replacement],
    }.each do |name, (type, *fields)|
      out << format_rr(name, type, *fields)
    end

    out
  end

  private

  def format_rr(name, type, *fields)
    return if (rrs = @records[name]).empty?

    rrs.inject("\n; Zone #{type} Records\n") do |out, rr|
      line = [:name, :ttl, :class, type, *fields].map {|f|
        f.is_a?(Symbol) ? rr[f] : f
      }
      out << line.join("\t") << "\n"
    end
  end
end
