import asyncio
from collections.abc import Awaitable, Callable
import fnmatch
import re
from typing import TypeAlias, TypeVar, overload

from arclet.cithun import InheritMode
from arclet.cithun.model import Permission, ResourceNode, Role, User, Track, TrackLevel
from arclet.cithun.async_ import AsyncPermissionEngine, AsyncPermissionExecutor, AsyncPermissionService
from arclet.letoderea.scope import Scope, scope_ctx
from arclet.letoderea.utils import DisposableList
from entari_plugin_database import get_session
from entari_plugin_user.models import UserSession
from launart import Service, Launart
from launart.status import Phase
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import select

from .model import (
    AclEntryModel,
    RoleInheritsModel,
    RoleModel,
    TrackLevelModel,
    TrackModel,
    UserModel,
    UserRolesModel,
)

from .store import ORMStore

Attach: TypeAlias = Callable[
    [User, UserSession | None, Permission, Callable[[User | Role, UserSession | None], Awaitable[Permission]]],
    Awaitable[Permission | tuple[Permission, str]],
]
TAttach = TypeVar("TAttach", bound=Attach)
Attach1: TypeAlias = Callable[
    [User, str, UserSession | None, Permission, Callable[[User | Role, UserSession | None], Awaitable[Permission]]],
    Awaitable[Permission | tuple[Permission, str]],
]
TAttach1 = TypeVar("TAttach1", bound=Attach1)


class PermissionService(Service, ORMStore, AsyncPermissionService[UserSession], AsyncPermissionExecutor[UserSession]):
    @property
    def required(self) -> set[str]:
        return {"database/sqlalchemy"}

    @property
    def stages(self) -> set[Phase]:
        return {"preparing", "blocking"}

    async def launch(self, manager: Launart):
        async with self.stage("preparing"):
            await self.load()
        async with self.stage("blocking"):
            for hook in self._hooks:
                await hook()
            await manager.status.wait_for_sigexit()

    def __init__(self):
        Service.__init__(self)
        ORMStore.__init__(self)
        AsyncPermissionService.__init__(self, engine=AsyncPermissionEngine[UserSession](), storage=self)
        AsyncPermissionExecutor.__init__(self, self, self)

        self._predefine_resources = []
        self._predefine_users = []
        self._predefine_roles = [("group:default", "Default")]
        self._predefine_tracks = []
        self._predefine_track_levels = []
        self._predefine_assigns = []

        self._hooks = []
        self.attaches: DisposableList[tuple[Callable[[str], bool], Attach1]] = DisposableList([])
        self.engine.register_strategy(self._run_attachs)

    async def _run_attachs(
        self,
        user: User,
        resource: ResourceNode,
        context: UserSession | None,
        current_mask: Permission,
        permission_lookup: Callable[[User | Role, UserSession | None], Awaitable[Permission]],
    ) -> Permission:
        result = current_mask
        tasks = []
        for pattern, func in self.attaches:
            if pattern(resource.id):
                tasks.append(func(user, resource.id, context, current_mask, permission_lookup))
        if not tasks:
            return current_mask
        for task in asyncio.as_completed(tasks):
            ret = await task
            if isinstance(ret, tuple):
                mask, mode = ret
                if mode == "+":
                    result |= mask
                elif mode == "-":
                    result &= ~mask
                elif mode == "=":
                    result = mask
            else:
                result |= ret
        return result

    @overload
    def attach(self, pattern: str) -> Callable[[TAttach], TAttach]:
        ...

    @overload
    def attach(self, pattern: Callable[[str], bool]) -> Callable[[TAttach1], TAttach1]:
        ...

    def attach(self, pattern):  # type: ignore
        """注册资源级权限回调。

        当 pattern 为字符串时，支持 glob 通配 (``*`` / ``?`` / ``[]``)。
        回调在对应资源节点被访问时触发。

        Args:
            pattern: 资源匹配模式。字符串精确匹配或 glob 通配，或自定义谓词函数。

        Returns:
            装饰器，将函数注册为 attach 回调。

        - 裸 ``Permission``: 与当前掩码叠加 (等价 ``"+"``)
        - ``(Permission, "+")``: 叠加
        - ``(Permission, "-")``: 从当前掩码中移除
        - ``(Permission, "=")``: 覆盖当前掩码
        """
        scope = scope_ctx.get(default=Scope.root())

        if isinstance(pattern, str):

            def decorator(func: Attach, /):
                if re.search(r"[*?\[\]]", pattern):
                    predicate = lambda p: fnmatch.fnmatch(p, pattern)
                else:
                    predicate = lambda p: p == pattern
                scope.effect(
                    lambda: self.attaches.append((predicate, lambda u, _, c, m, pl: func(u, c, m, pl))),
                    f"system.attach({pattern})"
                )
                return func

            return decorator

        def wrapper(func: Attach1, /):
            scope.effect(
                lambda: self.attaches.append((pattern, func)),
                f"system.attach()"
            )
            return func

        return wrapper

    async def load(self):
        async with get_session() as session:
            users = (await session.scalars(select(UserModel))).all()
            for user_model in users:
                user = user_model.dump()
                self.users[user.id] = user
                role_ids = (
                    await session.scalars(select(UserRolesModel.role_id).where(UserRolesModel.user_id == user.id))
                ).all()
                user.role_ids.extend(role_ids)
            roles = (await session.scalars(select(RoleModel))).all()
            for role_model in roles:
                role = role_model.dump()
                self.roles[role.id] = role
                parent_role_ids = (
                    await session.scalars(
                        select(RoleInheritsModel.parent_role_id).where(RoleInheritsModel.role_id == role.id)
                    )
                ).all()
                role.parent_role_ids.extend(parent_role_ids)
            acls = (await session.scalars(select(AclEntryModel))).all()
            for acl_model in acls:
                acl = acl_model.dump()
                self.acls[acl_model.id] = acl
            tracks = (await session.scalars(select(TrackModel).options(selectinload(TrackModel.levels)))).all()
            for track_model in tracks:
                track = track_model.dump()
                self.tracks[track.id] = track
        self.loaded.set()
        for path, inherit_mode, type_ in self._predefine_resources:
            if path not in self.resources:
                await self.define(path, inherit_mode=inherit_mode, type_=type_)
        for rid, name in self._predefine_roles:
            role = self.roles[rid]
            async with get_session() as session:
                model = RoleModel(id=rid, name=name)
                await session.merge(model)
                for parent_rid in role.parent_role_ids:
                    parent_model = RoleInheritsModel(role_id=rid, parent_role_id=parent_rid)
                    await session.merge(parent_model)
                await session.commit()
        for uid, name in self._predefine_users:
            user = self.users[uid]
            async with get_session() as session:
                model = UserModel(id=uid, name=name)
                await session.merge(model)
                for rid in user.role_ids:
                    user_role_model = UserRolesModel(user_id=uid, role_id=rid)
                    await session.merge(user_role_model)
                await session.commit()
        for tid, name in self._predefine_tracks:
            track = self.tracks[tid]
            async with get_session() as session:
                track_model = TrackModel(id=tid, name=name or tid)
                await session.merge(track_model)
                for index, level in enumerate(track.levels):
                    level_model = TrackLevelModel(
                        index=index,
                        track_id=tid,
                        role_id=level.role_id,
                        level_name=level.level_name,
                    )
                    await session.merge(level_model)
                await session.commit()
        for subject, resource_path, allow_mask, deny_mask in self._predefine_assigns:
            await self.assign(subject, resource_path, allow_mask, deny_mask)

    def pre_define(
        self,
        path: str,
        inherit_mode: InheritMode | None = None,
        type_: str = "GENERIC",
    ):
        self._predefine_resources.append((path, inherit_mode, type_))

    def pre_user(self, uid: str, name: str) -> User:
        user = User(uid, name)
        user.role_ids.append(self.default_role.id)
        self.users[uid] = user
        self._predefine_users.append((uid, name))
        return user

    def pre_role(self, rid: str, name: str) -> Role:
        role = Role(rid, name)
        self._predefine_roles.append((rid, name))
        self.roles[rid] = role
        return role

    def pre_track(self, tid: str, name: str | None = None) -> Track:
        track = Track(tid, name or tid)
        self.tracks[tid] = track
        self._predefine_tracks.append((tid, name))
        return track

    def pre_track_level(self, track: Track, role: Role, name: str | None = None) -> None:
        level = TrackLevel(role.id, name or role.name)
        track.levels.append(level)

    def on_loaded(self, func):
        self._hooks.append(func)
        return func

    def pre_assign(
        self,
        subject: User | Role,
        resource_path: str | Callable[[str], bool] | re.Pattern[str],
        allow_mask: Permission,
        deny_mask: Permission = Permission.NONE,
    ):
        self._predefine_assigns.append((subject, resource_path, allow_mask, deny_mask))

    id = "permission"


system = PermissionService()


AUTH_1 = system.pre_role("group:authority.1", "Authority 1")
AUTH_2 = system.pre_role("group:authority.2", "Authority 2")
AUTH_3 = system.pre_role("group:authority.3", "Authority 3")
AUTH_4 = system.pre_role("group:authority.4", "Authority 4")
AUTH_5 = system.pre_role("group:authority.5", "Authority 5")
AUTHORITY = system.pre_track("authority", "Authority Track")
