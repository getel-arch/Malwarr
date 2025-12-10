export interface MalwareSample {
  sha512: string;
  sha256: string;
  sha1: string;
  md5: string;
  filename: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
  // Archive fields
  is_archive?: string;
  parent_archive_sha512?: string;
  extracted_file_count?: number;
  // Source information
  source_url?: string;
  // PE basic metadata
  pe_imphash?: string;
  pe_compilation_timestamp?: string;
  pe_entry_point?: string;
  pe_sections?: string;
  pe_imports?: string;
  pe_exports?: string;
  // PE Header information
  pe_machine?: string;
  pe_number_of_sections?: number;
  pe_characteristics?: string;
  pe_magic?: string;
  pe_image_base?: string;
  pe_subsystem?: string;
  pe_dll_characteristics?: string;
  pe_checksum?: string;
  pe_size_of_image?: number;
  pe_size_of_headers?: number;
  pe_base_of_code?: string;
  // PE Version information
  pe_linker_version?: string;
  pe_os_version?: string;
  pe_image_version?: string;
  pe_subsystem_version?: string;
  // PE Import/Export counts
  pe_import_dll_count?: number;
  pe_imported_functions_count?: number;
  pe_export_count?: number;
  // PE Resources
  pe_resources?: string;
  pe_resource_count?: number;
  // PE Version info
  pe_version_info?: string;
  // PE Debug info
  pe_debug_info?: string;
  // PE TLS
  pe_tls_info?: string;
  // PE Rich header
  pe_rich_header?: string;
  // PE Digital signature
  pe_is_signed?: boolean;
  pe_signature_info?: string;
  // ELF metadata
  elf_machine?: string;
  elf_entry_point?: string;
  elf_file_class?: string;
  elf_data_encoding?: string;
  elf_os_abi?: string;
  elf_abi_version?: number;
  elf_type?: string;
  elf_version?: string;
  elf_flags?: string;
  elf_header_size?: number;
  elf_program_header_offset?: string;
  elf_section_header_offset?: string;
  elf_program_header_entry_size?: number;
  elf_program_header_count?: number;
  elf_section_header_entry_size?: number;
  elf_section_header_count?: number;
  elf_sections?: string;
  elf_section_count?: number;
  elf_segments?: string;
  elf_segment_count?: number;
  elf_interpreter?: string;
  elf_dynamic_tags?: string;
  elf_shared_libraries?: string;
  elf_shared_library_count?: number;
  elf_symbols?: string;
  elf_symbol_count?: number;
  elf_relocations?: string;
  elf_relocation_count?: number;
  // Magika AI file type detection
  magika_label?: string;
  magika_score?: string;
  magika_mime_type?: string;
  magika_group?: string;
  magika_description?: string;
  magika_is_text?: boolean;
  magic_description?: string;
  strings_count?: number;
  entropy?: string;
  tags?: string[];
  family?: string;
  classification?: string;
  virustotal_link?: string;
  malwarebazaar_link?: string;
  notes?: string;
  // CAPA analysis fields
  capa_capabilities?: string;
  capa_attack?: string;
  capa_mbc?: string;
  capa_analysis_date?: string;
  capa_total_capabilities?: number;
  analysis_status?: string;
  analysis_task_id?: string;
  // VirusTotal fields
  vt_positives?: number;
  vt_total?: number;
  vt_scan_date?: string;
  vt_permalink?: string;
  vt_scans?: string;
  vt_detection_ratio?: string;
  vt_scan_id?: string;
  vt_verbose_msg?: string;
  vt_analysis_date?: string;
  first_seen: string;
  last_updated: string;
  upload_date: string;
  storage_path: string;
}

export interface UploadResponse {
  sample: MalwareSample;
  extracted_samples: MalwareSample[];
  is_archive: boolean;
  extraction_count: number;
}

export interface SampleMetadata {
  tags?: string;
  family?: string;
  classification?: string;
  notes?: string;
  archive_password?: string;
}

export interface SampleUpdateData {
  tags?: string[];
  family?: string;
  classification?: string;
  notes?: string;
  virustotal_link?: string;
  malwarebazaar_link?: string;
}

export interface UrlUploadData {
  url: string;
  filename?: string;
  tags?: string[];
  family?: string;
  classification?: string;
  notes?: string;
  archive_password?: string;
}
