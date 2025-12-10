export interface PEAnalysis {
  imphash?: string;
  compilation_timestamp?: string;
  entry_point?: string;
  sections?: string;
  imports?: string;
  exports?: string;
  machine?: string;
  number_of_sections?: number;
  characteristics?: string;
  magic?: string;
  image_base?: string;
  subsystem?: string;
  dll_characteristics?: string;
  checksum?: string;
  size_of_image?: number;
  size_of_headers?: number;
  base_of_code?: string;
  linker_version?: string;
  os_version?: string;
  image_version?: string;
  subsystem_version?: string;
  import_dll_count?: number;
  imported_functions_count?: number;
  export_count?: number;
  resources?: string;
  resource_count?: number;
  version_info?: string;
  debug_info?: string;
  tls_info?: string;
  rich_header?: string;
  is_signed?: boolean;
  signature_info?: string;
  analysis_date: string;
}

export interface ELFAnalysis {
  machine?: string;
  entry_point?: string;
  file_class?: string;
  data_encoding?: string;
  os_abi?: string;
  abi_version?: number;
  elf_type?: string;
  version?: string;
  flags?: string;
  header_size?: number;
  program_header_offset?: string;
  section_header_offset?: string;
  program_header_entry_size?: number;
  program_header_count?: number;
  section_header_entry_size?: number;
  section_header_count?: number;
  sections?: string;
  section_count?: number;
  segments?: string;
  segment_count?: number;
  interpreter?: string;
  dynamic_tags?: string;
  shared_libraries?: string;
  shared_library_count?: number;
  symbols?: string;
  symbol_count?: number;
  relocations?: string;
  relocation_count?: number;
  analysis_date: string;
}

export interface MagikaAnalysis {
  label?: string;
  score?: string;
  mime_type?: string;
  group?: string;
  description?: string;
  is_text?: boolean;
  analysis_date: string;
}

export interface CAPAAnalysis {
  capabilities?: string;
  attack?: string;
  mbc?: string;
  result_document?: string;
  total_capabilities?: number;
  analysis_date: string;
}

export interface VirusTotalAnalysis {
  positives?: number;
  total?: number;
  scan_date?: string;
  permalink?: string;
  scans?: string;
  detection_ratio?: string;
  scan_id?: string;
  verbose_msg?: string;
  analysis_date: string;
}

export interface StringsAnalysis {
  ascii_strings?: string;
  unicode_strings?: string;
  ascii_count?: number;
  unicode_count?: number;
  total_count?: number;
  min_length?: number;
  longest_string_length?: number;
  average_string_length?: string;
  urls?: string;
  ip_addresses?: string;
  file_paths?: string;
  registry_keys?: string;
  email_addresses?: string;
  url_count?: number;
  ip_count?: number;
  file_path_count?: number;
  registry_key_count?: number;
  email_count?: number;
  analysis_date: string;
}
