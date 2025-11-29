"""add archive fields

Revision ID: 004
Revises: 003
Create Date: 2025-11-28 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add archive relationship fields
    op.add_column('malware_samples', sa.Column('is_archive', sa.String(10), server_default='false', nullable=True))
    op.add_column('malware_samples', sa.Column('parent_archive_sha512', sa.String(128), nullable=True))
    op.add_column('malware_samples', sa.Column('extracted_file_count', sa.Integer(), server_default='0', nullable=True))
    
    # Add index for parent_archive_sha512 for efficient queries
    op.create_index(op.f('ix_malware_samples_parent_archive_sha512'), 'malware_samples', ['parent_archive_sha512'], unique=False)


def downgrade() -> None:
    # Remove index
    op.drop_index(op.f('ix_malware_samples_parent_archive_sha512'), table_name='malware_samples')
    
    # Remove columns
    op.drop_column('malware_samples', 'extracted_file_count')
    op.drop_column('malware_samples', 'parent_archive_sha512')
    op.drop_column('malware_samples', 'is_archive')
