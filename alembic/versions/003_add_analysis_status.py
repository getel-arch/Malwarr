"""Add analysis status and task tracking fields

Revision ID: 003
Revises: 002
Create Date: 2025-11-28

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum type for analysis status (only if it doesn't exist)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE analysisstatus AS ENUM ('PENDING', 'ANALYZING', 'COMPLETED', 'FAILED', 'SKIPPED');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    # Add analysis status column with default value (only if it doesn't exist)
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE malware_samples 
            ADD COLUMN analysis_status analysisstatus;
        EXCEPTION
            WHEN duplicate_column THEN null;
        END $$;
    """)
    
    # Add analysis task ID column (only if it doesn't exist)
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE malware_samples 
            ADD COLUMN analysis_task_id VARCHAR(255);
        EXCEPTION
            WHEN duplicate_column THEN null;
        END $$;
    """)
    
    # Set default status for existing records
    # Set to COMPLETED if capa_analysis_date exists, otherwise PENDING
    op.execute("""
        UPDATE malware_samples 
        SET analysis_status = CASE 
            WHEN capa_analysis_date IS NOT NULL THEN 'COMPLETED'::analysisstatus
            WHEN file_type = 'PE' OR file_type = 'ELF' THEN 'PENDING'::analysisstatus
            ELSE 'SKIPPED'::analysisstatus
        END
        WHERE analysis_status IS NULL
    """)


def downgrade() -> None:
    # Drop columns (only if they exist)
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE malware_samples DROP COLUMN IF EXISTS analysis_task_id;
            ALTER TABLE malware_samples DROP COLUMN IF EXISTS analysis_status;
        END $$;
    """)
    
    # Drop enum type (only if it exists)
    op.execute("DROP TYPE IF EXISTS analysisstatus")
