"""empty message

Revision ID: 566140a64782
Revises: d7195d961d8d
Create Date: 2021-06-04 14:16:25.128837

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '566140a64782'
down_revision = 'd7195d961d8d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('URL', schema=None) as batch_op:
        batch_op.add_column(sa.Column('clicks', sa.Integer(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('URL', schema=None) as batch_op:
        batch_op.drop_column('clicks')

    # ### end Alembic commands ###
