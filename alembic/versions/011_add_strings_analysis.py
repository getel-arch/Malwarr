"""Add strings analysis table

Revision ID: 011
Revises: 010
Create Date: 2025-12-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade():
    # Create Strings Analysis table
    op.create_table(
        'strings_analysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sha512', sa.String(length=128), nullable=False),
        sa.Column('ascii_strings', sa.Text(), nullable=True),
        sa.Column('unicode_strings', sa.Text(), nullable=True),
        sa.Column('ascii_count', sa.Integer(), nullable=True),
        sa.Column('unicode_count', sa.Integer(), nullable=True),
        sa.Column('total_count', sa.Integer(), nullable=True),
        sa.Column('min_length', sa.Integer(), nullable=True),
        sa.Column('longest_string_length', sa.Integer(), nullable=True),
        sa.Column('average_string_length', sa.String(length=10), nullable=True),
        sa.Column('urls', sa.Text(), nullable=True),
        sa.Column('ip_addresses', sa.Text(), nullable=True),
        sa.Column('file_paths', sa.Text(), nullable=True),
        sa.Column('registry_keys', sa.Text(), nullable=True),
        sa.Column('email_addresses', sa.Text(), nullable=True),
        sa.Column('url_count', sa.Integer(), nullable=True),
        sa.Column('ip_count', sa.Integer(), nullable=True),
        sa.Column('file_path_count', sa.Integer(), nullable=True),
        sa.Column('registry_key_count', sa.Integer(), nullable=True),
        sa.Column('email_count', sa.Integer(), nullable=True),
        sa.Column('analysis_date', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sha512'], ['malware_samples.sha512'], ondelete='CASCADE'),
    )
    
    # Create indexes
    op.create_index('ix_strings_analysis_sha512', 'strings_analysis', ['sha512'], unique=True)


def downgrade():
    # Drop indexes
    op.drop_index('ix_strings_analysis_sha512', table_name='strings_analysis')
    
    # Drop table
    op.drop_table('strings_analysis')
