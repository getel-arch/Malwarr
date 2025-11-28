"""add capa_result_document column

Revision ID: 002
Revises: 001
Create Date: 2025-11-28

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade():
    # Add capa_result_document column to malware_samples table
    op.add_column('malware_samples', sa.Column('capa_result_document', sa.Text(), nullable=True))


def downgrade():
    # Remove capa_result_document column from malware_samples table
    op.drop_column('malware_samples', 'capa_result_document')
