"""Add CAPA analysis fields

Revision ID: 001
Revises: 
Create Date: 2025-11-28

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add CAPA analysis fields to malware_samples table
    op.add_column('malware_samples', 
                  sa.Column('capa_capabilities', sa.Text(), nullable=True))
    op.add_column('malware_samples', 
                  sa.Column('capa_attack', sa.Text(), nullable=True))
    op.add_column('malware_samples', 
                  sa.Column('capa_mbc', sa.Text(), nullable=True))
    op.add_column('malware_samples', 
                  sa.Column('capa_analysis_date', sa.DateTime(), nullable=True))
    op.add_column('malware_samples', 
                  sa.Column('capa_total_capabilities', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Remove CAPA analysis fields
    op.drop_column('malware_samples', 'capa_total_capabilities')
    op.drop_column('malware_samples', 'capa_analysis_date')
    op.drop_column('malware_samples', 'capa_mbc')
    op.drop_column('malware_samples', 'capa_attack')
    op.drop_column('malware_samples', 'capa_capabilities')
