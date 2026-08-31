"""feat: add priority to correlation rules

Revision ID: b3f8a7d92c1e
Revises: 67ff7efffed4
Create Date: 2026-08-31 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b3f8a7d92c1e"
down_revision = "67ff7efffed4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("rule", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "priority",
                sa.Integer(),
                nullable=False,
                server_default="100",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("rule", schema=None) as batch_op:
        batch_op.drop_column("priority")