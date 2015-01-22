
SPF = 'spf'
SPF2 = 'spf2'
IP = 'ip'

#SPF Policies
SPF1 = 'spf1'
SPF2_PRA = 'spf2.0/pra'
SPF2_MFROM = 'spf2.0/mfrom'
SPF2_MFROM_PRA = 'spf2.0/mfrom,pra'

#SPF Mechanisms
INCLUDE = 'include'
IP4 = 'ip4'
IP6 = 'ip6'
REDIRECT = 'redirect'
ALL = 'all'
A = 'a'
PTR = 'ptr'
EXISTS = 'exists'
EXP = 'exp'
MX = 'mx'

# Qualifiers
PASS = '+'
FAIL = '-'
SOFTFAIL = '~'
NEUTRAL = '?'

class DomainInfo

  attr_accessor :mx, :aaaa, :a, :ns

  def initialize(domain, continuous_print = nil)
    @domain = domain
    @spf = {}
    set_info(dig_domain(domain))
    self.to_s if continuous_print
  end

  def dig_domain(domain)
    # Have to query for txt in order to ensure ANY reutrns txt
    dig_info = `dig #{domain} txt | grep TXT`
    info =  `dig #{domain} ANY`
    comb = "#{dig_info}\n#{info}"
    return comb
  end

  def set_info(info)
    info_lines = info.split("\n")
    info_lines.each do |line|
      split_line = line.split("\t")
      update_info(split_line[4], split_line[5]) if split_line.length == 6
      update_info(split_line[3], split_line[4]) if split_line.length == 5
    end
  end

  def update_info(record_type, record_info)
    case record_type
      when 'A'
        @a = [] unless @a
        @a.push(record_info)
      when 'NS'
        @ns = [] unless @ns
        @ns.push(record_info)
      when 'AAAA'
        @aaaa = [] unless @aaaa
        @aaaa.push(record_info)
      when 'MX'
        @mx = [] unless @mx
        @mx.push(record_info)
      when 'SOA'
        @soa = [] unless @soa
        @soa.push(record_info)
      when 'TXT'
        @txt = [] unless @txt
        @txt.push(record_info)
        handle_txt(record_info)
    end
  end

  def handle_txt(txt_info)
    puts ''
    txt_info.slice!('"')
    txt_info.slice!('"')
    handle_spf(txt_info)
  end

  def determine_spf_policy(txt_info)
    if txt_info.include?(SPF1)
      txt_info.slice!("v=#{SPF1}")
      return SPF1
    elsif txt_info.include?(SPF2_MFROM)
      txt_info.slice!(SPF2_MFROM)
      return SPF2_MFROM
    elsif txt_info.include?(SPF2_PRA)
      txt_info.slice!(SPF2_PRA)
      return SPF2_PRA
    elsif txt_info.include?(SPF2_MFROM_PRA)
      txt_info.slice!(SPF2_MFROM_PRA)
      return SPF2_MFROM_PRA
    end
  end

  def handle_spf(txt_info)
    spf = determine_spf_policy(txt_info)
    @spf[spf] = {} unless @spf.keys.include?(spf)
    txt_info.split(' ').each do |info_str|
      add_info(info_str, spf, ALL) if info_str.include?(ALL)
      add_info(info_str, spf, IP4) if info_str.include?(IP4)
      add_info(info_str, spf, IP6) if info_str.include?(IP6)
      add_info(info_str, spf, MX) if info_str.include?(MX)
      add_info(info_str, spf, A) if info_str.include?(A) and !info_str.include?(ALL)
      add_info(info_str, spf, PTR) if info_str.include?(PTR)
      add_info(info_str, spf, EXISTS) if info_str.include?(EXISTS)
      handle_include(info_str, spf) if info_str.include?(INCLUDE)
    end
  end

  def add_info(info, spf, key)
    @spf[spf][key] = [] unless @spf[spf].keys.include?(key)
    value = get_value_from_info(info, key)
    handle_include(info, spf) if info.include?(INCLUDE)
    @spf[spf][key].push(value)
  end

  def get_value_from_info(info, key)
    value = info
    info_array = info.split(':') if info.include?(':')
    value = info_array[1] if info_array
    value = info_array[1..-1].join(':') if key == IP6
    return value
  end

  def handle_include(info, spf)
    @spf[spf][INCLUDE] = {} unless @spf[spf].keys.include?(INCLUDE)
    domain = info.split(':')[1]
    sleep 1
    @spf[spf][INCLUDE][value] = DomainInfo.new(domain)
  end

  def to_s
    puts "Domain: #{@domain}"
    @a.each { |item| puts "A: #{item}"} if @a
    @aaaa.each { |item| puts "AAAA: #{item}"} if @aaaa
    @soa.each { |item| puts "SOA: #{item}"} if @soa
    @mx.each { |item| puts "MX: #{item}"} if @mx
    @ns.each { |item| puts "NS: #{item}"} if @ns
    @txt.each { |item| puts "TXT: #{item}"} if @txt
    # ugly and to be fixed
    @spf.keys.each do |key|
      puts "###### KEY #######"
      puts key
      if @spf[key].instance_of?(Hash)
        @spf[key].keys.each do |key2|
          puts "###### KEY 2 #######"
          puts key2
          puts @spf[key][key2].to_s unless @spf[key][key2].instance_of?(Hash)
          @spf[key][key2].keys.each do |key3|
            puts "###### KEY 3 #######"
            puts key3
            puts @spf[key][key2][key3].to_s
          end if @spf[key][key2].instance_of?(Hash)
        end
      elsif @spf[key].instance_of?(Array)
        @spf[key].each { |item| puts item }
      end
    end if @spf
    puts
  end

  # To be implmented
  def get_ips
    ips = []
    return ips
  end


end

