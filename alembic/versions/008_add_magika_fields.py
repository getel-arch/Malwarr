"""add magika fields

Revision ID: 008
Revises: 007
Create Date: 2025-12-09

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add Magika deep learning-based file type detection fields
    op.add_column('malware_samples', sa.Column('magika_label', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_score', sa.String(length=10), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_mime_type', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_group', sa.String(length=100), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_description', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('magika_is_text', sa.Boolean(), nullable=True))


def downgrade() -> None:
    # Remove Magika fields
    op.drop_column('malware_samples', 'magika_is_text')
    op.drop_column('malware_samples', 'magika_description')
    op.drop_column('malware_samples', 'magika_group')
    op.drop_column('malware_samples', 'magika_mime_type')
    op.drop_column('malware_samples', 'magika_score')
    op.drop_column('malware_samples', 'magika_label')
