"""add internal_name field

Revision ID: 012
Revises: 011
Create Date: 2025-12-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade():
    # Add internal_name column to malware_samples table
    op.add_column('malware_samples', sa.Column('internal_name', sa.String(255), nullable=True))


def downgrade():
    # Remove internal_name column from malware_samples table
    op.drop_column('malware_samples', 'internal_name')
