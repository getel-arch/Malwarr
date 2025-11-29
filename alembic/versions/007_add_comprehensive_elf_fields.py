"""add comprehensive elf fields

Revision ID: 007
Revises: 006
Create Date: 2025-11-29

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new ELF header fields
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
    op.add_column('malware_samples', sa.Column('elf_section_count', sa.Integer(), nullable=True))
    
    # Add ELF segments
    op.add_column('malware_samples', sa.Column('elf_segments', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_segment_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_interpreter', sa.String(length=255), nullable=True))
    
    # Add ELF dynamic section
    op.add_column('malware_samples', sa.Column('elf_dynamic_tags', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_shared_libraries', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_shared_library_count', sa.Integer(), nullable=True))
    
    # Add ELF symbols
    op.add_column('malware_samples', sa.Column('elf_symbols', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_symbol_count', sa.Integer(), nullable=True))
    
    # Add ELF relocations
    op.add_column('malware_samples', sa.Column('elf_relocations', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('elf_relocation_count', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Remove ELF relocations
    op.drop_column('malware_samples', 'elf_relocation_count')
    op.drop_column('malware_samples', 'elf_relocations')
    
    # Remove ELF symbols
    op.drop_column('malware_samples', 'elf_symbol_count')
    op.drop_column('malware_samples', 'elf_symbols')
    
    # Remove ELF dynamic section
    op.drop_column('malware_samples', 'elf_shared_library_count')
    op.drop_column('malware_samples', 'elf_shared_libraries')
    op.drop_column('malware_samples', 'elf_dynamic_tags')
    
    # Remove ELF segments
    op.drop_column('malware_samples', 'elf_interpreter')
    op.drop_column('malware_samples', 'elf_segment_count')
    op.drop_column('malware_samples', 'elf_segments')
    
    # Remove ELF header fields
    op.drop_column('malware_samples', 'elf_section_count')
    op.drop_column('malware_samples', 'elf_section_header_count')
    op.drop_column('malware_samples', 'elf_section_header_entry_size')
    op.drop_column('malware_samples', 'elf_program_header_count')
    op.drop_column('malware_samples', 'elf_program_header_entry_size')
    op.drop_column('malware_samples', 'elf_section_header_offset')
    op.drop_column('malware_samples', 'elf_program_header_offset')
    op.drop_column('malware_samples', 'elf_header_size')
    op.drop_column('malware_samples', 'elf_flags')
    op.drop_column('malware_samples', 'elf_version')
    op.drop_column('malware_samples', 'elf_type')
    op.drop_column('malware_samples', 'elf_abi_version')
    op.drop_column('malware_samples', 'elf_os_abi')
    op.drop_column('malware_samples', 'elf_data_encoding')
    op.drop_column('malware_samples', 'elf_file_class')
