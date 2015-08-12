#!/usr/bin/env rake

require 'rake'
require 'fileutils'
require 'bundler/setup'

Bundler.require(:default)

DaFunk::RakeTask.new do |t|
  t.mrbc  = "mrbc"
  # t.mrbc  = "cloudwalk compile"
  t.mruby = "mruby -b"
  # t.mruby = "cloudwalk run"
end
