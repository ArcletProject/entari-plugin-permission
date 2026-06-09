import asyncio
from collections.abc import Awaitable, Callable
import fnmatch
import re
from typing import TypeAlias, TypeVar, overload

from arclet.letoderea.scope import Scope, scope_ctx
from arclet.letoderea.utils import DisposableList
from arclet.cithun import Permission, ResourceNode, Role, User
from arclet.cithun.async_ import AsyncPermissionEngine, AsyncPermissionExecutor, AsyncPermissionService
from entari_plugin_user.models import UserSession

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


class System(ORMStore, AsyncPermissionService[UserSession], AsyncPermissionExecutor[UserSession]):
    def __init__(self):
        ORMStore.__init__(self)
        AsyncPermissionService.__init__(self, engine=AsyncPermissionEngine[UserSession](), storage=self)
        AsyncPermissionExecutor.__init__(self, self, self)
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
    def attach(self, pattern: str) -> Callable[[TAttach], TAttach]: ...

    @overload
    def attach(self, pattern: Callable[[str], bool]) -> Callable[[TAttach1], TAttach1]: ...

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


system = System()


AUTH_1 = system.pre_role("group:authority.1", "Authority 1")
AUTH_2 = system.pre_role("group:authority.2", "Authority 2")
AUTH_3 = system.pre_role("group:authority.3", "Authority 3")
AUTH_4 = system.pre_role("group:authority.4", "Authority 4")
AUTH_5 = system.pre_role("group:authority.5", "Authority 5")
AUTHORITY = system.pre_track("authority", "Authority Track")

system.pre_assign(AUTH_1, "authority.1", Permission("v-a"))
system.pre_assign(AUTH_2, "authority.2", Permission("v-a"))
system.pre_assign(AUTH_3, "authority.3", Permission("v-a"))
system.pre_assign(AUTH_4, "authority.4", Permission("v-a"))
system.pre_assign(AUTH_5, "authority.5", Permission("v-a"))
