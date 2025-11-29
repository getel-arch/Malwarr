"""Add source_url field

Revision ID: 005
Revises: 004
Create Date: 2025-11-29

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add source_url column to malware_samples table"""
    op.add_column('malware_samples', sa.Column('source_url', sa.String(length=2048), nullable=True))


def downgrade() -> None:
    """Remove source_url column from malware_samples table"""
    op.drop_column('malware_samples', 'source_url')
