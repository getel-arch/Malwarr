"""add virustotal fields

Revision ID: 009
Revises: 008
Create Date: 2025-12-09

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add VirusTotal fields
    op.add_column('malware_samples', sa.Column('vt_positives', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_total', sa.Integer(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scan_date', sa.DateTime(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_permalink', sa.String(length=512), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scans', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_detection_ratio', sa.String(length=20), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_scan_id', sa.String(length=255), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_verbose_msg', sa.Text(), nullable=True))
    op.add_column('malware_samples', sa.Column('vt_analysis_date', sa.DateTime(), nullable=True))


def downgrade() -> None:
    # Remove VirusTotal fields
    op.drop_column('malware_samples', 'vt_analysis_date')
    op.drop_column('malware_samples', 'vt_verbose_msg')
    op.drop_column('malware_samples', 'vt_scan_id')
    op.drop_column('malware_samples', 'vt_detection_ratio')
    op.drop_column('malware_samples', 'vt_scans')
    op.drop_column('malware_samples', 'vt_permalink')
    op.drop_column('malware_samples', 'vt_scan_date')
    op.drop_column('malware_samples', 'vt_total')
    op.drop_column('malware_samples', 'vt_positives')
