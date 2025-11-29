"""Add comprehensive PE analysis fields

Revision ID: 006
Revises: 005
Create Date: 2025-11-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text, String, Integer, Boolean


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    # Add new PE header fields
    op.add_column('malware_samples', sa.Column('pe_machine', String(100)))
    op.add_column('malware_samples', sa.Column('pe_number_of_sections', Integer))
    op.add_column('malware_samples', sa.Column('pe_characteristics', String(20)))
    op.add_column('malware_samples', sa.Column('pe_magic', String(10)))
    op.add_column('malware_samples', sa.Column('pe_image_base', String(20)))
    op.add_column('malware_samples', sa.Column('pe_subsystem', String(100)))
    op.add_column('malware_samples', sa.Column('pe_dll_characteristics', String(20)))
    op.add_column('malware_samples', sa.Column('pe_checksum', String(20)))
    op.add_column('malware_samples', sa.Column('pe_size_of_image', Integer))
    op.add_column('malware_samples', sa.Column('pe_size_of_headers', Integer))
    op.add_column('malware_samples', sa.Column('pe_base_of_code', String(20)))
    
    # Version information
    op.add_column('malware_samples', sa.Column('pe_linker_version', String(20)))
    op.add_column('malware_samples', sa.Column('pe_os_version', String(20)))
    op.add_column('malware_samples', sa.Column('pe_image_version', String(20)))
    op.add_column('malware_samples', sa.Column('pe_subsystem_version', String(20)))
    
    # Import/Export counts
    op.add_column('malware_samples', sa.Column('pe_import_dll_count', Integer))
    op.add_column('malware_samples', sa.Column('pe_imported_functions_count', Integer))
    op.add_column('malware_samples', sa.Column('pe_export_count', Integer))
    
    # Resources
    op.add_column('malware_samples', sa.Column('pe_resources', Text))
    op.add_column('malware_samples', sa.Column('pe_resource_count', Integer))
    
    # Version info
    op.add_column('malware_samples', sa.Column('pe_version_info', Text))
    
    # Debug info
    op.add_column('malware_samples', sa.Column('pe_debug_info', Text))
    
    # TLS
    op.add_column('malware_samples', sa.Column('pe_tls_info', Text))
    
    # Rich header
    op.add_column('malware_samples', sa.Column('pe_rich_header', Text))
    
    # Digital signature
    op.add_column('malware_samples', sa.Column('pe_is_signed', Boolean, default=False))
    op.add_column('malware_samples', sa.Column('pe_signature_info', Text))


def downgrade():
    # Remove all added columns
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
