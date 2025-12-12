"""fix magika analysis_date onupdate

Revision ID: 013
Revises: 012
Create Date: 2025-12-12

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None


def upgrade():
    # Note: The onupdate parameter in SQLAlchemy is handled at the ORM level,
    # not at the database level. The change to the model is sufficient.
    # This migration serves as a marker for the schema change in the codebase.
    # No database changes are needed - the updated model will handle timestamp updates.
    pass


def downgrade():
    # No database changes to reverse
    pass
