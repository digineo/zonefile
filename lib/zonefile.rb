#
# = Ruby Zonefile - Parse and manipulate DNS Zone Files.
#
# == Description
#
# This class can read, manipulate and create DNS zone files. Among others,
# it supports A, AAAA, MX, NS, SOA, TXT, CNAME, PTR and SRV records. The
# data can be accessed by the instance method of the same name. All except
# SOA return an array of hashes containing the named data. SOA directly
# returns the hash since there can only be one SOA information.
#
# See `Zonefile::RECORDS` for a list of currently supported records.
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
# == Authors
#
# Martin Boese, based on Simon Flack Perl library DNS::ZoneParse
#
# Andy Newton, patch to support various additional records
#
# Dominik Menke (Digineo GmbH), various improvements
#
class Zonefile
  # This defines the supported RR methods (keys), their RR type
  # (`values[0]`) and additional RR data fields (`values[1..-1]`).
  #
  # For example, this class defines a method #a4, which returns a
  # list of AAAA records represented by an hash. Each hash has the
  # keys :name, :ttl, :class and additionally :host.
  #
  # For SRV records, #srv returns a list of hashes with keys :name,
  # :ttl, :class and additionally :pri, :weight, :port and :host.
  #
  # Please note, the SOA record is absent from this definition list.
  # #soa will return a single hash with keys :origin, :ttl, :primary,
  # :email, :serial, :refresh, :retry, :expire, and :minimumTTL.
  RECORDS = { # method_name => [RR type, RR data fields]
    ns:         ["NS",         :host],
    a:          ["A",          :host],
    a4:         ["AAAA",       :host],
    cname:      ["CNAME",      :host],
    caa:        ["CAA",        :flag, :tag, :value],
    dnskey:     ["DNSKEY",     :flag, :protocol, :algorithm, :public_key],
    ds:         ["DS",         :key_tag, :algorithm, :digest_type, :digest],
    mx:         ["MX",         :pri, :host],
    naptr:      ["NAPTR",      :order, :preference, :flags, :service, :regexp, :replacement],
    nsec:       ["NSEC",       :next, :types],
    nsec3:      ["NSEC3",      :algorithm, :flags, :iterations, :salt, :next, :types],
    nsec3param: ["NSEC3PARAM", :algorithm, :flags, :iterations, :salt],
    ptr:        ["PTR",        :host],
    rrsig:      ["RRSIG",      :type_covered, :algorithm, :labels, :original_ttl, :expiration, :inception, :key_tag, :signer, :signature],
    spf:        ["SPF",        :text],
    srv:        ["SRV",        :pri, :weight, :port, :host],
    tlsa:       ["TLSA",       :certificate_usage, :selector, :matching_type, :data],
    txt:        ["TXT",        :text],
  }.freeze

  attr_reader :records  # all records, except SOA
  attr_reader :soa      # single SOA record
  attr_reader :data     # original zonefile
  attr_reader :origin   # global $ORIGIN directive
  attr_reader :ttl      # global $TTL directive

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
      (0..(r.length - 1)).find_all {|i| r[i] == ";" }.each do |comment_idx|
        unless r[(comment_idx + 1)..-1].index(/['"]/)
          r = r[0..(comment_idx - 1)]
          break
        end
      end

      r
    }
    normalized.delete_if {|line| line.empty? || line[0] == ";" }.join("\n")
  end

  # Create a new object by reading the content of a file
  def self.from_file(file_name, origin = nil)
    Zonefile.new(File.read(file_name), file_name.split("/").last, origin)
  end

  MAX_SERIAL = 2**32 # uint32

  def self.next_serial(curr_serial)
    curr = curr_serial.to_i
    base = Time.now.strftime("%Y%m%d00").to_i

    serial = curr >= base ? curr + 1 : base
    (serial % MAX_SERIAL).to_s
  end

  TTL_FACTORS = {
    "w" => 7 * 24 * 60 * 60,
    "d" => 24 * 60 * 60,
    "h" => 60 * 60,
    "m" => 60,
  }.freeze

  def self.expand_ttl(value)
    return value if value.nil? || value.is_a?(Numeric)
    return nil   if value == ""

    value.to_s.scan(/(\d+)([wdhms])?/i).inject(0) do |sum, (n, u)|
      factor = u ? TTL_FACTORS.fetch(u.downcase, 1) : 1
      sum + (n.to_i * factor)
    end
  end

  def expand_ttl(value)
    self.class.expand_ttl(value)
  end

  # create a new zonefile object by passing the content of the zonefile
  def initialize(zonefile = "", file_name = nil, origin = nil)
    @data = zonefile
    @filename = file_name
    self.origin = origin || (file_name ? file_name.split("/").last : "")

    @records = {}
    @soa = {}
    @lastname = nil
    @ttl = nil
    RECORDS.each do |name, _|
      @records[name] = []
    end
    parse
  end

  RECORDS.each do |name, _|
    define_method name do
      @records[name]
    end

    define_method "#{name}=" do |val|
      @records[name] = val
    end
  end

  def origin=(val)
    @origin = val.chomp(".")
  end

  # True if no records (except sao) is defined in this file
  def empty?
    RECORDS.each do |name, _|
      return false unless @records[name].empty?
    end
    true
  end

  def add_record(type, data = {})
    @lastname = data[:name] if data[:name].to_s != ""
    data[:name] = @lastname if data[:name].to_s == ""
    @records[type] << data
  end

  # Generates a new serial number in the format of YYYYMMDDII if possible
  def new_serial
    @soa[:serial] = self.class.next_serial(@soa[:serial])
  end

  def parse
    self.class.simplify(@data).each_line do |line|
      parse_line(line.rstrip)
    end
  end

  def parse_line(line)
    if (origin = Parser::DIRECTIVE_ORIGIN.match(line))
      self.origin = origin
    elsif (ttl = Parser::DIRECTIVE_TTL.match(line))
      @ttl = ttl
    elsif (data = Parser::SOA.match(line))
      @soa.merge! data
    elsif (name, data = Parser::Matcher.find_for(line))
      add_record name, data
    end
  end

  module Parser
    # valid name literal
    VALID_NAME = /[-@._*a-zA-Z0-9]+/.freeze
    # valid ipv6 address literal
    VALID_IP6  = /[-@._*a-zA-Z0-9:]+/.freeze # ??
    # resource class literal
    RR_CLASS   = /\b(?:IN|HS|CH)\b/i.freeze
    # resource TTL literal
    RR_TTL     = /(?:\d+[wdhms]?)+/i.freeze
    # base64 string literal (maybe space separated)
    BASE64     = %r{ [a-zA-Z0-9+/\s]*={0,2} }x.freeze
    # hex string literal (maybe space separated)
    HEX        = /[\sa-fA-F0-9]*/.freeze
    # quoted string literal
    QUOTED     = /\"[^\"]*\"/.freeze

    # compound common prefix for many RRs (name is required)
    PREFIX_REQ_NAME = %r{
      ^
      (?<name>      #{VALID_NAME}) \s+
      (?:(?<ttl>    #{RR_TTL})\s+)?
      (?:(?<class>  #{RR_CLASS})\s+)?
      \b
    }oix.freeze

    # compound common prefix for many RRs (name is optional)
    PREFIX_OPT_NAME = %r{
      ^
      (?<name>      #{VALID_NAME})? \s*
      (?:(?<ttl>    #{RR_TTL})\s+)?
      (?:(?<class>  #{RR_CLASS})\s+)?
      \b
    }oix.freeze

    # Matcher is an internal helper class. Its constructor receives a
    # regualar expression which defines the matching behaviour, and
    # a block to extract matches into a Hash (most of the time; the
    # type of the extracted data is not constrained).
    class Matcher
      def self.children
        @children ||= []
      end

      # Throws input against known Matchers and returns the name and
      # extrated data (if one matched). Otherwise returns nil.
      def self.find_for(input)
        s = input.to_s
        children.each do |m|
          if (data = m.match(s))
            return [m.name, data]
          end
        end
        nil
      end

      attr_reader :name, :regexp, :block

      def initialize(name, regexp, &block)
        self.class.children << self if name
        @name   = name
        @regexp = regexp
        @block  = block
      end

      def match(input)
        return unless (m = regexp.match(input))

        block.call(m)
      end
    end

    # origin directive
    DIRECTIVE_ORIGIN = Matcher.new nil, %r{
      ^
      \$ORIGIN \s+
      (?<origin>  #{VALID_NAME})
      $
    }oix.freeze do |m|
      m[:origin]
    end

    # ttl directive
    DIRECTIVE_TTL = Matcher.new nil, %r{
      ^
      \$TTL \s+
      (?<ttl> #{RR_TTL})
      $
    }oix.freeze do |m|
      Zonefile.expand_ttl(m[:ttl])
    end

    SOA = Matcher.new nil, %r{
      #{PREFIX_REQ_NAME} SOA \s+
      (?<primary>     #{VALID_NAME}) \s+
      (?<email>       #{VALID_NAME}) \s*
      (?<serial>      \d+) \s+
      (?<refresh>     #{RR_TTL}) \s+
      (?<retry>       #{RR_TTL}) \s+
      (?<expire>      #{RR_TTL}) \s+
      (?<minimumTTL>  #{RR_TTL}) \s*
    }oix.freeze do |m|
      {
        origin:     m[:name],
        ttl:        Zonefile.expand_ttl(m[:ttl]) || "",
        primary:    m[:primary],
        email:      m[:email],
        serial:     m[:serial],
        refresh:    Zonefile.expand_ttl(m[:refresh]),
        retry:      Zonefile.expand_ttl(m[:retry]),
        expire:     Zonefile.expand_ttl(m[:expire]),
        minimumTTL: Zonefile.expand_ttl(m[:minimumTTL]),
      }
    end

    NS = Matcher.new :ns, %r{
      #{PREFIX_OPT_NAME} NS \s
      (?<host>  #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
      }
    end

    A = Matcher.new :a, %r{
      #{PREFIX_OPT_NAME} A \s
      (?<host>  #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
      }
    end

    AAAA = Matcher.new :a4, %r{
      #{PREFIX_OPT_NAME} AAAA \s
      (?<host>  #{VALID_IP6})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
      }
    end

    CAA = Matcher.new :caa, %r{
      #{PREFIX_OPT_NAME} CAA \s+
      (?<flag>  \d+) \s+
      (?<tag>   issue|issuewild|iodef) \s+
      (?<value> .*)
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        flag:  m[:flag].to_i,
        tag:   m[:tag],
        value: m[:value].strip,
      }
    end

    CNAME = Matcher.new :cname, %r{
      #{PREFIX_OPT_NAME} CNAME \s
      (?<host>  #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
      }
    end

    MX = Matcher.new :mx, %r{
      #{PREFIX_OPT_NAME} MX \s
      (?<pri> \d+) \s
      (?<host>  #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
        pri:   m[:pri].to_i,
      }
    end

    SRV = Matcher.new :srv, %r{
      #{PREFIX_OPT_NAME} SRV \s
      (?<pri>     \d+) \s
      (?<weight>  \d+) \s
      (?<port>    \d+) \s
      (?<host>    #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:   m[:name],
        ttl:    Zonefile.expand_ttl(m[:ttl]),
        class:  m[:class],
        pri:    m[:pri],
        weight: m[:weight],
        port:   m[:port],
        host:   m[:host],
      }
    end

    DS = Matcher.new :ds, %r{
      #{PREFIX_OPT_NAME} DS \s
      (?<key_tag>     \d+) \s
      (?<algorithm>   \w+) \s
      (?<digest_type> \d+) \s
      (?<digest>      #{HEX})
      $
    }oix.freeze do |m|
      {
        name:        m[:name],
        ttl:         Zonefile.expand_ttl(m[:ttl]),
        class:       m[:class],
        key_tag:     m[:key_tag].to_i,
        algorithm:   m[:algorithm],
        digest_type: m[:digest_type].to_i,
        digest:      m[:digest].gsub(/\s/, ""),
      }
    end

    NSEC = Matcher.new :nsec, %r{
      #{PREFIX_OPT_NAME} NSEC \s
      (?<next>  #{VALID_NAME}) \s
      (?<types> [\s\w]*)
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        next:  m[:next],
        types: m[:types].strip,
      }
    end

    NSEC3 = Matcher.new :nsec3, %r{
      #{PREFIX_OPT_NAME} NSEC3 \s
      (?<algorithm>  \d+) \s
      (?<flags>      \d+) \s
      (?<iterations> \d+) \s
      (?<salt>       -|[A-F0-9]*) \s
      (?<next>       [A-Z2-7=]*) \s
      (?<types>      [\s\w]*)
      $
    }oix.freeze do |m|
      {
        name:       m[:name],
        ttl:        Zonefile.expand_ttl(m[:ttl]),
        class:      m[:class],
        algorithm:  m[:algorithm],
        flags:      m[:flags],
        iterations: m[:iterations],
        salt:       m[:salt],
        next:       m[:next].strip,
        types:      m[:types].strip,
      }
    end

    NSEC3PARAM = Matcher.new :nsec3param, %r{
      #{PREFIX_OPT_NAME} NSEC3PARAM \s
      (?<algorithm>   \d+) \s
      (?<flags>       \d+) \s
      (?<iterations>  \d+) \s
      (?<salt>        -|[A-F0-9]*)
      $
    }oix.freeze do |m|
      {
        name:       m[:name],
        ttl:        Zonefile.expand_ttl(m[:ttl]),
        class:      m[:class],
        algorithm:  m[:algorithm],
        flags:      m[:flags],
        iterations: m[:iterations],
        salt:       m[:salt],
      }
    end

    DNSKEY = Matcher.new :dnskey, %r{
      #{PREFIX_OPT_NAME} DNSKEY \s
      (?<flag>      \d+) \s
      (?<protocol>  \d+) \s
      (?<algorithm> \w+) \s
      (?<pubkey>    #{BASE64})
      $
    }oix.freeze do |m|
      {
        name:       m[:name],
        ttl:        Zonefile.expand_ttl(m[:ttl]),
        class:      m[:class],
        flag:       m[:flag].to_i,
        protocol:   m[:protocol].to_i,
        algorithm:  m[:algorithm],
        public_key: m[:pubkey].gsub(/\s+/, ""),
      }
    end

    RRSIG = Matcher.new :rrsig, %r{
      #{PREFIX_OPT_NAME} RRSIG \s
      (?<type_covered>  \w+) \s
      (?<algorithm>     \w+) \s
      (?<labels>        \d+) \s
      (?<original_ttl>  \d+) \s
      (?<expiration>    \d+) \s
      (?<inception>     \d+) \s
      (?<key_tag>       \d+) \s
      (?<signer>        #{VALID_NAME}) \s
      (?<signature>     #{BASE64})
      $
    }oix.freeze do |m|
      {
        name:         m[:name],
        ttl:          Zonefile.expand_ttl(m[:ttl]),
        class:        m[:class],
        type_covered: m[:type_covered],
        algorithm:    m[:algorithm],
        labels:       m[:labels].to_i,
        original_ttl: m[:original_ttl].to_i,
        expiration:   m[:expiration].to_i,
        inception:    m[:inception].to_i,
        key_tag:      m[:key_tag].to_i,
        signer:       m[:signer],
        signature:    m[:signature].gsub(/\s/, ""),
      }
    end

    TLSA = Matcher.new :tlsa, %r{
      #{PREFIX_REQ_NAME} TLSA \s
      (?<usage>     \d+) \s
      (?<selector>  \d+) \s
      (?<type>      \d+) \s
      (?<data>      #{BASE64})
      $
    }oix.freeze do |m|
      {
        name:              m[:name],
        ttl:               Zonefile.expand_ttl(m[:ttl]),
        class:             m[:class],
        certificate_usage: m[:usage].to_i,
        selector:          m[:selector].to_i,
        matching_type:     m[:type].to_i,
        data:              m[:data],
      }
    end

    NAPTR = Matcher.new :naptr, %r{
      #{PREFIX_OPT_NAME} NAPTR \s
      (?<order>       \d+) \s
      (?<preference>  \d+) \s
      (?<flags>       #{QUOTED}) \s
      (?<service>     #{QUOTED}) \s
      (?<regexp>      #{QUOTED}) \s
      (?<replacement> #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:        m[:name],
        ttl:         Zonefile.expand_ttl(m[:ttl]),
        class:       m[:class],
        order:       m[:order].to_i,
        preference:  m[:preference].to_i,
        flags:       m[:flags],
        service:     m[:service],
        regexp:      m[:regexp],
        replacement: m[:replacement],
      }
    end

    PTR = Matcher.new :ptr, %r{
      #{PREFIX_OPT_NAME} PTR \s+
      (?<host> #{VALID_NAME})
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        host:  m[:host],
      }
    end

    TXT = Matcher.new :txt, %r{
      #{PREFIX_OPT_NAME} TXT \s+
      (?<text> .*)
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        text:  m[:text].strip,
      }
    end

    SPF = Matcher.new :spf, %r{
      #{PREFIX_OPT_NAME} SPF \s+
      (?<text> .*)
      $
    }oix.freeze do |m|
      {
        name:  m[:name],
        ttl:   Zonefile.expand_ttl(m[:ttl]),
        class: m[:class],
        text:  m[:text].strip,
      }
    end
  end
  private_constant :Parser

  # Build a new nicely formatted Zonefile
  def output
    out = <<~ZONE
      ;
      ; Database file #{@filename || 'unknown'} for #{@origin || 'unknown'} zone.
      ; Zone version: #{soa[:serial]}
      ;
    ZONE

    out << "$ORIGIN #{@origin}.\n" if @origin
    out << "$TTL #{@ttl}\n"        if @ttl

    out << "\n" << <<~ZONE
      #{soa[:origin]}\t#{soa[:ttl]}\tIN\tSOA\t(
      \t\t\t\t\t#{soa[:primary]}\t; primary
      \t\t\t\t\t#{soa[:email]}\t; email
      \t\t\t\t\t#{soa[:serial]}\t; serial number
      \t\t\t\t\t#{soa[:refresh]}\t; refresh
      \t\t\t\t\t#{soa[:retry]}\t; retry
      \t\t\t\t\t#{soa[:expire]}\t; expire
      \t\t\t\t\t#{soa[:minimumTTL]}\t; minimum TTL
      \t\t\t\t)
    ZONE

    RECORDS.each do |name, (type, *fields)|
      out << format_rr(name, type, *fields)
    end

    out
  end

  RR = Struct.new(:name, :ttl, :class, :type, :data)

  # Returns a list of RR instances for further processing.
  #
  # If `powerdns_sql` is truthy, RR names and data is transformed into a
  # format suitable for PowerDNS SQL backends (i.e. host names without trailing
  # dot are suffixed with `$ORIGIN`, `@` is expanded to `$ORIGIN`, and hostnames
  # with trailing dot loose the trailing dot.
  #
  # The `powerdns_sql` knob implements/emulates an "official wart", as per
  # https://github.com/PowerDNS/pdns/blob/rel/auth-4.2.x/pdns/zone2sql.cc#L59-L63
  def resource_records(powerdns_sql: false)
    soa_origin = powerdns_sql ? expand_dot(soa[:origin]) : soa[:origin]
    rr_soa = RR.new(soa_origin, expand_ttl(soa[:ttl]), "IN", "SOA")
    rr_soa.data = {
      primary:    (:dot if powerdns_sql),
      email:      (:dot if powerdns_sql),
      serial:     nil,
      refresh:    :ttl,
      retry:      :ttl,
      expire:     :ttl,
      minimumTTL: :ttl,
    }.map {|f, expand|
      val = soa[f]
      val = expand_dot(val) if expand == :dot
      val = expand_ttl(val) if expand == :ttl
      val
    }.join("\t")

    RECORDS.each_with_object(soa: rr_soa) do |(name, (type, *fields)), rrs|
      @records[name].each do |item|
        item = expand_dot_content(type, item) if powerdns_sql

        rr = RR.new(item[:name], expand_ttl(item[:ttl]), (item[:class] || "IN").upcase, type)
        rr.data = fields.map {|f| item[f] }.join("\t")
        rrs[type] ||= []
        rrs[type] << rr
      end
    end
  end

  private

  # Fields in RECORDS, which are subject to name expansion with
  # `resource_records(powerdns_sql: true)`.
  DOT_CONTENT = {
    "NS"    => [:host],
    "CNAME" => [:host],
    "MX"    => [:host],
    "NAPTR" => [:replacement],
    "PTR"   => [:host],
    "SRV"   => [:host],
  }.freeze
  private_constant :DOT_CONTENT

  def expand_dot_content(type, item)
    item = item.clone
    item[:name] = expand_dot item[:name]
    DOT_CONTENT.fetch(type, []).each do |f|
      item[f] = expand_dot item[f]
    end
    item
  end

  def expand_dot(str)
    return @origin        if str == "@" || str.nil?
    return str.chomp(".") if str.end_with?(".")

    if str.end_with?(@origin)
      str
    else
      "#{str}.#{@origin}"
    end
  end

  def format_rr(name, type, *fields)
    return "" if (rrs = @records[name]).empty?

    rrs.inject("\n; Zone #{type} Records\n") do |out, rr|
      line = [:name, :ttl, :class, type, *fields].map {|f|
        case f
        when :ttl   then expand_ttl(rr[f])
        when Symbol then rr[f]
        else             f
        end
      }
      out << line.join("\t") << "\n"
    end
  end
end
