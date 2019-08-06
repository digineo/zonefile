# frozen_string_literal: true

require "rubygems"

SPEC = Gem::Specification.new do |s|
  s.name         = "zonefile"
  s.version      = "2.2.1"
  s.author       = ["Martin Boese", "Dominik Menke"]
  s.email        = ["martin@internet.ao", "dom+gems@digineo.de"]
  s.homepage     = "https://github.com/digineo/zonefile"
  s.license      = "MIT"
  s.platform     = Gem::Platform::RUBY
  s.required_ruby_version = ">= 2.4.0"
  s.summary      = "BIND 8/9 Zonefile Reader and Writer"
  s.description  = <<~TEXT
    A library that can create, read, write, modify BIND compatible
    Zonefiles (RFC1035).

    Warning: It probably works for most cases, but it might not be
    able to read all files even if they are valid for bind.
  TEXT

  candidates     = Dir.glob("{lib,tests}/**/*") << "CHANGELOG"
  s.files        = candidates.delete_if {|item| %w[~ doc].include?(item) }
  s.require_path = "lib"

  s.add_development_dependency "minitest"
  s.add_development_dependency "rake"
  s.add_development_dependency "rubocop", "~> 0.72.0"
end
