"""remove redundant sample fields

Revision ID: 014
Revises: 013
Create Date: 2025-12-13

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '014'
down_revision = '013'
branch_labels = None
depends_on = None


def upgrade():
    """Remove redundant fields from malware_samples table that are already captured in analyzer tables"""
    
    # Remove fields that are redundant with analyzer tables
    op.drop_column('malware_samples', 'mime_type')
    op.drop_column('malware_samples', 'magic_description')
    op.drop_column('malware_samples', 'strings_count')
    op.drop_column('malware_samples', 'entropy')
    op.drop_column('malware_samples', 'internal_name')


def downgrade():
    """Restore the removed fields"""
    
    op.add_column('malware_samples', sa.Column('internal_name', sa.String(length=255), nullable=True))
    op.add_column('malware_samples', sa.Column('entropy', sa.String(length=10), nullable=True))
    op.add_column('malware_samples', sa.Column('strings_count', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('magic_description', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('mime_type', sa.String(length=100), nullable=True))
