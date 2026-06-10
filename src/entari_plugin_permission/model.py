from arclet.cithun.model import (
    AclEntry,
    Permission,
    Role,
    SubjectType,
    Track,
    TrackLevel,
    User,
)
from entari_plugin_database import Base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import Integer, String


class UserModel(Base):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)

    def dump(self):
        return User(id=self.id, name=self.name)


class RoleModel(Base):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)

    def dump(self):
        return Role(id=self.id, name=self.name)


class UserRolesModel(Base):
    user_id: Mapped[str] = mapped_column(ForeignKey(UserModel.id, ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[str] = mapped_column(ForeignKey(RoleModel.id, ondelete="CASCADE"), primary_key=True)


class RoleInheritsModel(Base):
    role_id: Mapped[str] = mapped_column(ForeignKey(RoleModel.id, ondelete="CASCADE"), primary_key=True)
    parent_role_id: Mapped[str] = mapped_column(ForeignKey(RoleModel.id, ondelete="CASCADE"), primary_key=True)


class AclEntryModel(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_type: Mapped[SubjectType] = mapped_column(String(16), nullable=False)  # 'USER' or 'ROLE'
    subject_id: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String, nullable=False)
    allow_mask: Mapped[int] = mapped_column(Integer, nullable=False)
    deny_mask: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def dump(self):
        return AclEntry(
            subject_type=SubjectType(self.subject_type),
            subject_id=self.subject_id,
            resource_id=self.resource_id,
            allow_mask=Permission(self.allow_mask),
            deny_mask=Permission(self.deny_mask),
        )


class TrackModel(Base):
    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)

    levels: Mapped[list["TrackLevelModel"]] = relationship(
        "TrackLevelModel", back_populates="track", cascade="all, delete-orphan"
    )

    def dump(self):
        levels = sorted(self.levels, key=lambda level: level.index)
        return Track(
            id=self.id,
            name=self.name,
            levels=[level.dump() for level in levels],
        )


class TrackLevelModel(Base):
    index: Mapped[int] = mapped_column(Integer, nullable=False)
    track_id: Mapped[str] = mapped_column(ForeignKey(TrackModel.id, ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[str] = mapped_column(ForeignKey(RoleModel.id, ondelete="CASCADE"), primary_key=True)
    level_name: Mapped[str] = mapped_column(String(256), nullable=False)

    track: Mapped[TrackModel] = relationship(TrackModel, back_populates="levels")

    def dump(self):
        return TrackLevel(
            role_id=self.role_id,
            level_name=self.level_name,
        )
