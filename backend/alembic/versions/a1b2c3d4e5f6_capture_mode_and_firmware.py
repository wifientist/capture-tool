"""capture mode + host_ip on assignments, firmware on targets

Revision ID: a1b2c3d4e5f6
Revises: 8c3c2f7f21a7
Create Date: 2026-07-08 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '8c3c2f7f21a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('assignments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('capture_mode', sa.String(length=20),
                                      nullable=False, server_default='file'))
        batch_op.add_column(sa.Column('host_ip', sa.String(length=64), nullable=True))
    with op.batch_alter_table('targets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('firmware', sa.String(length=40), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('targets', schema=None) as batch_op:
        batch_op.drop_column('firmware')
    with op.batch_alter_table('assignments', schema=None) as batch_op:
        batch_op.drop_column('host_ip')
        batch_op.drop_column('capture_mode')
