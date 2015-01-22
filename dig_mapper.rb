
require './domain_info.rb'

class DigMapper

  attr_accessor :domains, :domain_list

  def initialize(file_location)
    @domain_list = get_domain_list(file_location)
    @domain_list.collect!(&:strip)
    @domains = {}
  end

  def get_domain_list(file_location)
    return File.readlines(file_location)
  end

  def create_map
    @domain_list.each do |domain|
      @domains[domain] = DomainInfo.new(domain)
      sleep 1
    end
  end

end

if __FILE__ == $0
  dig = DigMapper.new('single_domain')
  dig.create_map
  dig.domains.keys.each do |domain_info_key|
    dig.domains[domain_info_key].to_s
  end
end