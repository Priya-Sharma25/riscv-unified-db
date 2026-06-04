#!/usr/bin/env ruby
# frozen_string_literal: true
#
# split_instructions.rb
#
# Splits an AsciiDoc instruction appendix produced by the riscv-unified-db
# `gen:instruction_appendix_adoc` task into four files:
#
#   unpriv_rv32.adoc  — Unprivileged instructions valid in RV32
#   unpriv_rv64.adoc  — Unprivileged instructions valid in RV64
#   priv_rv32.adoc    — Privileged instructions valid in RV32
#   priv_rv64.adoc    — Privileged instructions valid in RV64
#
# Instructions valid in both RV32 and RV64 appear in both width files.
#
# Privilege classification: an instruction is privileged if any of its
# "Included in" extensions begins with 'S' (supervisor/machine-mode in the
# RISC-V naming convention: Sm*, Ss*, Sh*, Sv*, or bare S) or 'H' (hypervisor).
#
# Usage:
#   ruby split_instructions.rb [INPUT] [OUTPUT_DIR]
#
#   INPUT       Path to all_instructions.adoc
#               Default: ./gen/instructions_appendix/all_instructions.adoc
#   OUTPUT_DIR  Directory to write the four output files
#               Default: same directory as INPUT

require "fileutils"

HELP = <<~HELP
  Usage: ruby split_instructions.rb [OPTIONS] [INPUT] [OUTPUT_DIR]

  Splits all_instructions.adoc into four files by ISA base and privilege level.

  Arguments:
    INPUT       Path to all_instructions.adoc
                (default: ./gen/instructions_appendix/all_instructions.adoc)
    OUTPUT_DIR  Directory to write the four output files
                (default: same directory as INPUT)

  Options:
    -h, --help  Show this message

  Output files:
    unpriv_rv32.adoc  Unprivileged instructions for RV32
    unpriv_rv64.adoc  Unprivileged instructions for RV64
    priv_rv32.adoc    Privileged instructions for RV32
    priv_rv64.adoc    Privileged instructions for RV64

  Instructions supported in both RV32 and RV64 appear in both width output files.

  Privilege detection:
    An instruction is privileged if any required extension starts with 'S'
    (supervisor/machine-mode: Sm*, Ss*, Sh*, Sv*, or bare S) or 'H' (hypervisor).
HELP

if ARGV.include?("--help") || ARGV.include?("-h")
  puts HELP
  exit
end

# Extensions whose names match this pattern are privileged.
# RISC-V spec naming: all S-prefixed extensions are supervisor- or machine-mode;
# H is the hypervisor extension.
PRIV_EXT_RE = /\A[SH]/

input  = ARGV[0] || File.join("gen", "instructions_appendix", "all_instructions.adoc")
outdir = ARGV[1] || File.dirname(File.expand_path(input))

abort "Error: input file not found: #{input}" unless File.exist?(input)
FileUtils.mkdir_p(outdir)

# ── Parse ─────────────────────────────────────────────────────────────────────

lines    = File.readlines(input, encoding: "UTF-8")
header   = []
current  = nil
sections = []

lines.each do |line|
  if line.start_with?("[#udb:doc:inst:")
    current = [line]
    sections << current
  elsif current
    current << line
  else
    header << line
  end
end

warn "Parsed #{sections.size} instruction sections from #{input}"

# ── Classification helpers ────────────────────────────────────────────────────

# Returns [rv32_supported, rv64_supported] by inspecting the Base table:
#
#   | RV32 | RV64          <- header row
#                          <- blank separator
#   | &#x2713;             <- RV32 cell  (checkmark = supported, blank = not)
#   | &#x2713;             <- RV64 cell
#
def base_support(section)
  idx = section.find_index { |l| l.strip == "| RV32 | RV64" }
  return [false, false] unless idx

  # Skip the blank separator between the header row and the data rows.
  data = idx + 1
  data += 1 while data < section.size && section[data].strip.empty?
  return [false, false] if data >= section.size

  rv32 = section[data].include?("&#x2713;")
  rv64 = (data + 1) < section.size && section[data + 1].include?("&#x2713;")
  [rv32, rv64]
end

# Returns true if any "Included in" extension matches PRIV_EXT_RE.
# Extension lines in the table look like:  | *ExtName*
def privileged?(section)
  in_included = false
  section.each do |line|
    in_included = true if line.strip == "Included in::"
    next unless in_included
    return true if line =~ /^\| \*([^*]+)\*/ && $1.match?(PRIV_EXT_RE)
  end
  false
end

# Replace the document-level title (= Some Title) while preserving all attrs.
# Also strips the :wavedrom: attribute line because it contains a machine-local
# absolute path that must not be committed to riscv-isa-manual.
def titled_header(header, title)
  header
    .reject { |l| l.start_with?(":wavedrom:") }
    .map    { |l| l.start_with?("= ") ? "[appendix]\n== #{title}\n" : l }
    .join
end

# Qualify a bare instruction anchor with a base prefix so that the same
# instruction appearing in both RV32 and RV64 appendixes has a unique ID.
#
#   [#udb:doc:inst:add]      → [#udb:doc:inst:rv32:add]
#   [#udb:doc:inst:rv32:add] → unchanged (already qualified)
ANCHOR_RE = /\[#udb:doc:inst:(?!rv(?:32|64):)([^\]]+)\]/

def qualify_anchors(text, base)
  text.gsub(ANCHOR_RE, "[#udb:doc:inst:#{base}:\\1]")
end

# Increment every heading level in a section body by one = sign so that
# instruction headings (== name) are subordinate to the appendix title (== Title).
#
#   == add   →  === add
#   === foo  →  ==== foo
def increment_heading_levels(text)
  text.gsub(/^(=+) /) { "#{$1}= " }
end

# Add an insn: alias anchor before each udb:doc:inst anchor so that the
# riscv-isa-manual's insnlink: macro can cross-reference the appendix entry.
#
# insnlink:add[] targets #insn:add.  The display name is taken from the
# === heading that immediately follows the anchor (preserving dots, e.g. lr.w),
# which is what insnlink: uses (name.downcase, no sanitize).
#
#   [#udb:doc:inst:rv32:add]      [#insn:add]
#   === add                   →   [#udb:doc:inst:rv32:add]
#                                 === add
def add_insn_alias(text)
  text.gsub(/(\[#udb:doc:inst:rv(?:32|64):[^\]]+\]\n)(={3,} )(.+\n)/) do
    "[#insn:#{$3.chomp.downcase}]\n#{$1}#{$2}#{$3}"
  end
end

# Convert Antora-style extension xrefs to the riscv-isa-manual ext: macro.
#
# The generated adoc uses Antora cross-references for extensions:
#   xref:exts:D.adoc#udb:doc:ext:D[D]
#
# riscv-isa-manual registers ext: as a custom inline macro (macros.rb).
# AsciiDoc's scanner finds ext:D[D] embedded inside those xref targets and
# errors with "macro ext:D[] does not accept arguments". Converting to the
# native macro fixes the error and renders the extension name correctly.
#
#   xref:exts:D.adoc#udb:doc:ext:D[D]  →  ext:D[]
EXT_XREF_RE = /xref:exts:[^.]+\.adoc#udb:doc:ext:[^\[]+\[([^\]]+)\]/

def convert_ext_xrefs(text)
  text.gsub(EXT_XREF_RE, 'ext:\1[]')
end

# ── Partition ─────────────────────────────────────────────────────────────────

buckets = { unpriv_rv32: [], unpriv_rv64: [], priv_rv32: [], priv_rv64: [] }

sections.each do |sect|
  rv32, rv64 = base_support(sect)
  priv       = privileged?(sect)
  text       = sect.join

  if priv
    buckets[:priv_rv32] << add_insn_alias(increment_heading_levels(convert_ext_xrefs(qualify_anchors(text, "rv32")))) if rv32
    buckets[:priv_rv64] << add_insn_alias(increment_heading_levels(convert_ext_xrefs(qualify_anchors(text, "rv64")))) if rv64
  else
    buckets[:unpriv_rv32] << add_insn_alias(increment_heading_levels(convert_ext_xrefs(qualify_anchors(text, "rv32")))) if rv32
    buckets[:unpriv_rv64] << add_insn_alias(increment_heading_levels(convert_ext_xrefs(qualify_anchors(text, "rv64")))) if rv64
  end
end

# ── Write output files ────────────────────────────────────────────────────────

TITLES = {
  unpriv_rv32: "Unprivileged RV32 Instructions",
  unpriv_rv64: "Unprivileged RV64 Instructions",
  priv_rv32:   "Privileged RV32 Instructions",
  priv_rv64:   "Privileged RV64 Instructions"
}.freeze

buckets.each do |key, blocks|
  path = File.join(outdir, "#{key}.adoc")
  File.open(path, "w", encoding: "UTF-8") do |f|
    f.write(titled_header(header, TITLES[key]))
    blocks.each { |b| f.write(b) }
  end
  puts "  #{path}  (#{blocks.size} instructions)"
end

total = buckets.values.sum(&:size)
warn "Done. #{total} instruction-file entries written (instructions in both bases counted twice)."
