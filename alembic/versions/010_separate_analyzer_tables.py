"""Separate analyzer tables

Revision ID: 010
Revises: 009
Create Date: 2025-12-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade():
    # Create PE Analysis table
    op.create_table(
        'pe_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('imphash', sa.String(length=32), nullable=True),
        sa.Column('compilation_timestamp', sa.DateTime(), nullable=True),
        sa.Column('entry_point', sa.String(length=20), nullable=True),
        sa.Column('sections', sa.Text(), nullable=True),
        sa.Column('imports', sa.Text(), nullable=True),
        sa.Column('exports', sa.Text(), nullable=True),
        sa.Column('machine', sa.String(length=100), nullable=True),
        sa.Column('number_of_sections', sa.Integer(), nullable=True),
        sa.Column('characteristics', sa.String(length=20), nullable=True),
        sa.Column('magic', sa.String(length=10), nullable=True),
        sa.Column('image_base', sa.String(length=20), nullable=True),
        sa.Column('subsystem', sa.String(length=100), nullable=True),
        sa.Column('dll_characteristics', sa.String(length=20), nullable=True),
        sa.Column('checksum', sa.String(length=20), nullable=True),
        sa.Column('size_of_image', sa.Integer(), nullable=True),
        sa.Column('size_of_headers', sa.Integer(), nullable=True),
        sa.Column('base_of_code', sa.String(length=20), nullable=True),
        sa.Column('linker_version', sa.String(length=20), nullable=True),
        sa.Column('os_version', sa.String(length=20), nullable=True),
        sa.Column('image_version', sa.String(length=20), nullable=True),
        sa.Column('subsystem_version', sa.String(length=20), nullable=True),
        sa.Column('import_dll_count', sa.Integer(), nullable=True),
        sa.Column('imported_functions_count', sa.Integer(), nullable=True),
        sa.Column('export_count', sa.Integer(), nullable=True),
        sa.Column('resources', sa.Text(), nullable=True),
        sa.Column('resource_count', sa.Integer(), nullable=True),
        sa.Column('version_info', sa.Text(), nullable=True),
        sa.Column('debug_info', sa.Text(), nullable=True),
        sa.Column('tls_info', sa.Text(), nullable=True),
        sa.Column('rich_header', sa.Text(), nullable=True),
        sa.Column('is_signed', sa.Boolean(), nullable=True),
        sa.Column('signature_info', sa.Text(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    op.create_index(op.f('ix_pe_analysis_sha512'), 'pe_analysis', ['sha512'], unique=True)
    op.create_index(op.f('ix_pe_analysis_imphash'), 'pe_analysis', ['imphash'], unique=False)

    # Create ELF Analysis table
    op.create_table(
        'elf_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('machine', sa.String(length=50), nullable=True),
        sa.Column('entry_point', sa.String(length=20), nullable=True),
        sa.Column('file_class', sa.String(length=20), nullable=True),
        sa.Column('data_encoding', sa.String(length=20), nullable=True),
        sa.Column('os_abi', sa.String(length=50), nullable=True),
        sa.Column('abi_version', sa.Integer(), nullable=True),
        sa.Column('elf_type', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('flags', sa.String(length=20), nullable=True),
        sa.Column('header_size', sa.Integer(), nullable=True),
        sa.Column('program_header_offset', sa.String(length=20), nullable=True),
        sa.Column('section_header_offset', sa.String(length=20), nullable=True),
        sa.Column('program_header_entry_size', sa.Integer(), nullable=True),
        sa.Column('program_header_count', sa.Integer(), nullable=True),
        sa.Column('section_header_entry_size', sa.Integer(), nullable=True),
        sa.Column('section_header_count', sa.Integer(), nullable=True),
        sa.Column('sections', sa.Text(), nullable=True),
        sa.Column('section_count', sa.Integer(), nullable=True),
        sa.Column('segments', sa.Text(), nullable=True),
        sa.Column('segment_count', sa.Integer(), nullable=True),
        sa.Column('interpreter', sa.String(length=255), nullable=True),
        sa.Column('dynamic_tags', sa.Text(), nullable=True),
        sa.Column('shared_libraries', sa.Text(), nullable=True),
        sa.Column('shared_library_count', sa.Integer(), nullable=True),
        sa.Column('symbols', sa.Text(), nullable=True),
        sa.Column('symbol_count', sa.Integer(), nullable=True),
        sa.Column('relocations', sa.Text(), nullable=True),
        sa.Column('relocation_count', sa.Integer(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    op.create_index(op.f('ix_elf_analysis_sha512'), 'elf_analysis', ['sha512'], unique=True)

    # Create Magika Analysis table
    op.create_table(
        'magika_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('label', sa.String(length=100), nullable=True),
        sa.Column('score', sa.String(length=10), nullable=True),
        sa.Column('mime_type', sa.String(length=100), nullable=True),
        sa.Column('group', sa.String(length=100), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_text', sa.Boolean(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    op.create_index(op.f('ix_magika_analysis_sha512'), 'magika_analysis', ['sha512'], unique=True)

    # Create CAPA Analysis table
    op.create_table(
        'capa_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('capabilities', sa.Text(), nullable=True),
        sa.Column('attack', sa.Text(), nullable=True),
        sa.Column('mbc', sa.Text(), nullable=True),
        sa.Column('result_document', sa.Text(), nullable=True),
        sa.Column('total_capabilities', sa.Integer(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    op.create_index(op.f('ix_capa_analysis_sha512'), 'capa_analysis', ['sha512'], unique=True)

    # Create VirusTotal Analysis table
    op.create_table(
        'virustotal_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('positives', sa.Integer(), nullable=True),
        sa.Column('total', sa.Integer(), nullable=True),
        sa.Column('scan_date', sa.DateTime(), nullable=True),
        sa.Column('permalink', sa.String(length=512), nullable=True),
        sa.Column('scans', sa.Text(), nullable=True),
        sa.Column('detection_ratio', sa.String(length=20), nullable=True),
        sa.Column('scan_id', sa.String(length=255), nullable=True),
        sa.Column('verbose_msg', sa.Text(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    op.create_index(op.f('ix_virustotal_analysis_sha512'), 'virustotal_analysis', ['sha512'], unique=True)

    # Migrate existing data from malware_samples to new tables
    # PE Analysis migration
    op.execute("""
        INSERT INTO pe_analysis (
            sha512, imphash, compilation_timestamp, entry_point, sections, imports, exports,
            machine, number_of_sections, characteristics, magic, image_base, subsystem,
            dll_characteristics, checksum, size_of_image, size_of_headers, base_of_code,
            linker_version, os_version, image_version, subsystem_version, import_dll_count,
            imported_functions_count, export_count, resources, resource_count, version_info,
            debug_info, tls_info, rich_header, is_signed, signature_info, analysis_date
        )
        SELECT 
            sha512, pe_imphash, pe_compilation_timestamp, pe_entry_point, pe_sections, pe_imports, pe_exports,
            pe_machine, pe_number_of_sections, pe_characteristics, pe_magic, pe_image_base, pe_subsystem,
            pe_dll_characteristics, pe_checksum, pe_size_of_image, pe_size_of_headers, pe_base_of_code,
            pe_linker_version, pe_os_version, pe_image_version, pe_subsystem_version, pe_import_dll_count,
            pe_imported_functions_count, pe_export_count, pe_resources, pe_resource_count, pe_version_info,
            pe_debug_info, pe_tls_info, pe_rich_header, pe_is_signed, pe_signature_info,
            COALESCE(last_updated, upload_date, first_seen)
        FROM malware_samples
        WHERE pe_imphash IS NOT NULL OR pe_machine IS NOT NULL
    """)

    # ELF Analysis migration
    op.execute("""
        INSERT INTO elf_analysis (
            sha512, machine, entry_point, file_class, data_encoding, os_abi, abi_version,
            elf_type, version, flags, header_size, program_header_offset, section_header_offset,
            program_header_entry_size, program_header_count, section_header_entry_size,
            section_header_count, sections, section_count, segments, segment_count, interpreter,
            dynamic_tags, shared_libraries, shared_library_count, symbols, symbol_count,
            relocations, relocation_count, analysis_date
        )
        SELECT 
            sha512, elf_machine, elf_entry_point, elf_file_class, elf_data_encoding, elf_os_abi, elf_abi_version,
            elf_type, elf_version, elf_flags, elf_header_size, elf_program_header_offset, elf_section_header_offset,
            elf_program_header_entry_size, elf_program_header_count, elf_section_header_entry_size,
            elf_section_header_count, elf_sections, elf_section_count, elf_segments, elf_segment_count, elf_interpreter,
            elf_dynamic_tags, elf_shared_libraries, elf_shared_library_count, elf_symbols, elf_symbol_count,
            elf_relocations, elf_relocation_count,
            COALESCE(last_updated, upload_date, first_seen)
        FROM malware_samples
        WHERE elf_machine IS NOT NULL OR elf_type IS NOT NULL
    """)

    # Magika Analysis migration
    op.execute("""
        INSERT INTO magika_analysis (
            sha512, label, score, mime_type, "group", description, is_text, analysis_date
        )
        SELECT 
            sha512, magika_label, magika_score, magika_mime_type, magika_group,
            magika_description, magika_is_text,
            COALESCE(last_updated, upload_date, first_seen)
        FROM malware_samples
        WHERE magika_label IS NOT NULL
    """)

    # CAPA Analysis migration
    op.execute("""
        INSERT INTO capa_analysis (
            sha512, capabilities, attack, mbc, result_document, total_capabilities, analysis_date
        )
        SELECT 
            sha512, capa_capabilities, capa_attack, capa_mbc, capa_result_document,
            capa_total_capabilities, COALESCE(capa_analysis_date, last_updated, upload_date, first_seen)
        FROM malware_samples
        WHERE capa_capabilities IS NOT NULL OR capa_result_document IS NOT NULL
    """)

    # VirusTotal Analysis migration
    op.execute("""
        INSERT INTO virustotal_analysis (
            sha512, positives, total, scan_date, permalink, scans, detection_ratio,
            scan_id, verbose_msg, analysis_date
        )
        SELECT 
            sha512, vt_positives, vt_total, vt_scan_date, vt_permalink, vt_scans,
            vt_detection_ratio, vt_scan_id, vt_verbose_msg,
            COALESCE(vt_analysis_date, last_updated, upload_date, first_seen)
        FROM malware_samples
        WHERE vt_positives IS NOT NULL OR vt_scan_id IS NOT NULL
    """)

    # Drop old columns from malware_samples table
    # PE columns
    op.drop_column('malware_samples', 'pe_imphash')
    op.drop_column('malware_samples', 'pe_compilation_timestamp')
    op.drop_column('malware_samples', 'pe_entry_point')
    op.drop_column('malware_samples', 'pe_sections')
    op.drop_column('malware_samples', 'pe_imports')
    op.drop_column('malware_samples', 'pe_exports')
    op.drop_column('malware_samples', 'pe_machine')
    op.drop_column('malware_samples', 'pe_number_of_sections')
    op.drop_column('malware_samples', 'pe_characteristics')
    op.drop_column('malware_samples', 'pe_magic')
    op.drop_column('malware_samples', 'pe_image_base')
    op.drop_column('malware_samples', 'pe_subsystem')
    op.drop_column('malware_samples', 'pe_dll_characteristics')
    op.drop_column('malware_samples', 'pe_checksum')
    op.drop_column('malware_samples', 'pe_size_of_image')
    op.drop_column('malware_samples', 'pe_size_of_headers')
    op.drop_column('malware_samples', 'pe_base_of_code')
    op.drop_column('malware_samples', 'pe_linker_version')
    op.drop_column('malware_samples', 'pe_os_version')
    op.drop_column('malware_samples', 'pe_image_version')
    op.drop_column('malware_samples', 'pe_subsystem_version')
    op.drop_column('malware_samples', 'pe_import_dll_count')
    op.drop_column('malware_samples', 'pe_imported_functions_count')
    op.drop_column('malware_samples', 'pe_export_count')
    op.drop_column('malware_samples', 'pe_resources')
    op.drop_column('malware_samples', 'pe_resource_count')
    op.drop_column('malware_samples', 'pe_version_info')
    op.drop_column('malware_samples', 'pe_debug_info')
    op.drop_column('malware_samples', 'pe_tls_info')
    op.drop_column('malware_samples', 'pe_rich_header')
    op.drop_column('malware_samples', 'pe_is_signed')
    op.drop_column('malware_samples', 'pe_signature_info')

    # ELF columns
    op.drop_column('malware_samples', 'elf_machine')
    op.drop_column('malware_samples', 'elf_entry_point')
    op.drop_column('malware_samples', 'elf_file_class')
    op.drop_column('malware_samples', 'elf_data_encoding')
    op.drop_column('malware_samples', 'elf_os_abi')
    op.drop_column('malware_samples', 'elf_abi_version')
    op.drop_column('malware_samples', 'elf_type')
    op.drop_column('malware_samples', 'elf_version')
    op.drop_column('malware_samples', 'elf_flags')
    op.drop_column('malware_samples', 'elf_header_size')
    op.drop_column('malware_samples', 'elf_program_header_offset')
    op.drop_column('malware_samples', 'elf_section_header_offset')
    op.drop_column('malware_samples', 'elf_program_header_entry_size')
    op.drop_column('malware_samples', 'elf_program_header_count')
    op.drop_column('malware_samples', 'elf_section_header_entry_size')
    op.drop_column('malware_samples', 'elf_section_header_count')
    op.drop_column('malware_samples', 'elf_sections')
    op.drop_column('malware_samples', 'elf_section_count')
    op.drop_column('malware_samples', 'elf_segments')
    op.drop_column('malware_samples', 'elf_segment_count')
    op.drop_column('malware_samples', 'elf_interpreter')
    op.drop_column('malware_samples', 'elf_dynamic_tags')
    op.drop_column('malware_samples', 'elf_shared_libraries')
    op.drop_column('malware_samples', 'elf_shared_library_count')
    op.drop_column('malware_samples', 'elf_symbols')
    op.drop_column('malware_samples', 'elf_symbol_count')
    op.drop_column('malware_samples', 'elf_relocations')
    op.drop_column('malware_samples', 'elf_relocation_count')

    # Magika columns
    op.drop_column('malware_samples', 'magika_label')
    op.drop_column('malware_samples', 'magika_score')
    op.drop_column('malware_samples', 'magika_mime_type')
    op.drop_column('malware_samples', 'magika_group')
    op.drop_column('malware_samples', 'magika_description')
    op.drop_column('malware_samples', 'magika_is_text')

    # CAPA columns
    op.drop_column('malware_samples', 'capa_capabilities')
    op.drop_column('malware_samples', 'capa_attack')
    op.drop_column('malware_samples', 'capa_mbc')
    op.drop_column('malware_samples', 'capa_result_document')
    op.drop_column('malware_samples', 'capa_analysis_date')
    op.drop_column('malware_samples', 'capa_total_capabilities')

    # VirusTotal columns
    op.drop_column('malware_samples', 'vt_positives')
    op.drop_column('malware_samples', 'vt_total')
    op.drop_column('malware_samples', 'vt_scan_date')
    op.drop_column('malware_samples', 'vt_permalink')
    op.drop_column('malware_samples', 'vt_scans')
    op.drop_column('malware_samples', 'vt_detection_ratio')
    op.drop_column('malware_samples', 'vt_scan_id')
    op.drop_column('malware_samples', 'vt_verbose_msg')
    op.drop_column('malware_samples', 'vt_analysis_date')


def downgrade():
    # Re-add columns to malware_samples table
    # PE columns
    op.add_column('malware_samples', sa.Column('pe_imphash', sa.String(length=32), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_compilation_timestamp', sa.DateTime(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_entry_point', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_sections', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_imports', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_exports', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_machine', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_number_of_sections', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_characteristics', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_magic', sa.String(length=10), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_image_base', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_subsystem', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_dll_characteristics', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_checksum', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_size_of_image', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_size_of_headers', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_base_of_code', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_linker_version', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_os_version', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_image_version', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_subsystem_version', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_import_dll_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_imported_functions_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_export_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_resources', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_resource_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_version_info', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_debug_info', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_tls_info', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_rich_header', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_is_signed', sa.Boolean(), nullable=True))
    op.add_column('malware_samples', sa.Column('pe_signature_info', sa.Text(), nullable=True))

    # ELF columns
    op.add_column('malware_samples', sa.Column('elf_machine', sa.String(length=50), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_entry_point', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_file_class', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_data_encoding', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_os_abi', sa.String(length=50), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_abi_version', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_type', sa.String(length=50), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_version', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_flags', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_header_size', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_program_header_offset', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_section_header_offset', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_program_header_entry_size', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_program_header_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_section_header_entry_size', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_section_header_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_sections', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_section_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_segments', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_segment_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_interpreter', sa.String(length=255), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_dynamic_tags', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_shared_libraries', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_shared_library_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_symbols', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_symbol_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_relocations', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_relocation_count', sa.Integer(), nullable=True))

    # Magika columns
    op.add_column('malware_samples', sa.Column('magika_label', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_score', sa.String(length=10), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_mime_type', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_group', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_description', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_is_text', sa.Boolean(), nullable=True))

    # CAPA columns
    op.add_column('malware_samples', sa.Column('capa_capabilities', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('capa_attack', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('capa_mbc', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('capa_result_document', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('capa_analysis_date', sa.DateTime(), nullable=True))
    op.add_column('malware_samples', sa.Column('capa_total_capabilities', sa.Integer(), nullable=True))

    # VirusTotal columns
    op.add_column('malware_samples', sa.Column('vt_positives', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_total', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scan_date', sa.DateTime(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_permalink', sa.String(length=512), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scans', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_detection_ratio', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scan_id', sa.String(length=255), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_verbose_msg', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_analysis_date', sa.DateTime(), nullable=True))

    # Migrate data back from analyzer tables to malware_samples
    op.execute("""
        UPDATE malware_samples ms
        SET 
            pe_imphash = pe.imphash,
            pe_compilation_timestamp = pe.compilation_timestamp,
            pe_entry_point = pe.entry_point,
            pe_sections = pe.sections,
            pe_imports = pe.imports,
            pe_exports = pe.exports,
            pe_machine = pe.machine,
            pe_number_of_sections = pe.number_of_sections,
            pe_characteristics = pe.characteristics,
            pe_magic = pe.magic,
            pe_image_base = pe.image_base,
            pe_subsystem = pe.subsystem,
            pe_dll_characteristics = pe.dll_characteristics,
            pe_checksum = pe.checksum,
            pe_size_of_image = pe.size_of_image,
            pe_size_of_headers = pe.size_of_headers,
            pe_base_of_code = pe.base_of_code,
            pe_linker_version = pe.linker_version,
            pe_os_version = pe.os_version,
            pe_image_version = pe.image_version,
            pe_subsystem_version = pe.subsystem_version,
            pe_import_dll_count = pe.import_dll_count,
            pe_imported_functions_count = pe.imported_functions_count,
            pe_export_count = pe.export_count,
            pe_resources = pe.resources,
            pe_resource_count = pe.resource_count,
            pe_version_info = pe.version_info,
            pe_debug_info = pe.debug_info,
            pe_tls_info = pe.tls_info,
            pe_rich_header = pe.rich_header,
            pe_is_signed = pe.is_signed,
            pe_signature_info = pe.signature_info
        FROM pe_analysis pe
        WHERE ms.sha512 = pe.sha512
    """)

    op.execute("""
        UPDATE malware_samples ms
        SET 
            elf_machine = elf.machine,
            elf_entry_point = elf.entry_point,
            elf_file_class = elf.file_class,
            elf_data_encoding = elf.data_encoding,
            elf_os_abi = elf.os_abi,
            elf_abi_version = elf.abi_version,
            elf_type = elf.elf_type,
            elf_version = elf.version,
            elf_flags = elf.flags,
            elf_header_size = elf.header_size,
            elf_program_header_offset = elf.program_header_offset,
            elf_section_header_offset = elf.section_header_offset,
            elf_program_header_entry_size = elf.program_header_entry_size,
            elf_program_header_count = elf.program_header_count,
            elf_section_header_entry_size = elf.section_header_entry_size,
            elf_section_header_count = elf.section_header_count,
            elf_sections = elf.sections,
            elf_section_count = elf.section_count,
            elf_segments = elf.segments,
            elf_segment_count = elf.segment_count,
            elf_interpreter = elf.interpreter,
            elf_dynamic_tags = elf.dynamic_tags,
            elf_shared_libraries = elf.shared_libraries,
            elf_shared_library_count = elf.shared_library_count,
            elf_symbols = elf.symbols,
            elf_symbol_count = elf.symbol_count,
            elf_relocations = elf.relocations,
            elf_relocation_count = elf.relocation_count
        FROM elf_analysis elf
        WHERE ms.sha512 = elf.sha512
    """)

    op.execute("""
        UPDATE malware_samples ms
        SET 
            magika_label = mag.label,
            magika_score = mag.score,
            magika_mime_type = mag.mime_type,
            magika_group = mag."group",
            magika_description = mag.description,
            magika_is_text = mag.is_text
        FROM magika_analysis mag
        WHERE ms.sha512 = mag.sha512
    """)

    op.execute("""
        UPDATE malware_samples ms
        SET 
            capa_capabilities = capa.capabilities,
            capa_attack = capa.attack,
            capa_mbc = capa.mbc,
            capa_result_document = capa.result_document,
            capa_total_capabilities = capa.total_capabilities,
            capa_analysis_date = capa.analysis_date
        FROM capa_analysis capa
        WHERE ms.sha512 = capa.sha512
    """)

    op.execute("""
        UPDATE malware_samples ms
        SET 
            vt_positives = vt.positives,
            vt_total = vt.total,
            vt_scan_date = vt.scan_date,
            vt_permalink = vt.permalink,
            vt_scans = vt.scans,
            vt_detection_ratio = vt.detection_ratio,
            vt_scan_id = vt.scan_id,
            vt_verbose_msg = vt.verbose_msg,
            vt_analysis_date = vt.analysis_date
        FROM virustotal_analysis vt
        WHERE ms.sha512 = vt.sha512
    """)

    # Drop analyzer tables
    op.drop_index(op.f('ix_virustotal_analysis_sha512'), table_name='virustotal_analysis')
    op.drop_table('virustotal_analysis')
    
    op.drop_index(op.f('ix_capa_analysis_sha512'), table_name='capa_analysis')
    op.drop_table('capa_analysis')
    
    op.drop_index(op.f('ix_magika_analysis_sha512'), table_name='magika_analysis')
    op.drop_table('magika_analysis')
    
    op.drop_index(op.f('ix_elf_analysis_sha512'), table_name='elf_analysis')
    op.drop_table('elf_analysis')
    
    op.drop_index(op.f('ix_pe_analysis_imphash'), table_name='pe_analysis')
    op.drop_index(op.f('ix_pe_analysis_sha512'), table_name='pe_analysis')
    op.drop_table('pe_analysis')
