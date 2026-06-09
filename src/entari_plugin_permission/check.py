from arclet.cithun import Permission
from arclet.letoderea import Propagator, STOP
from entari_plugin_user import UserSession

from .main import system


def check_permission(permission: str, default_available: bool = True, prompt: bool = False):
    """
    检查权限是否满足的函数, 可用于 enter_if, Depends 等

    Args:
        permission (str): 权限名称
        default_available (bool): 是否默认可用，默认为True
        prompt (bool): 是否提示
    """

    system.pre_define(permission)
    system.pre_assign(system.default_role, permission, Permission("v-a") if default_available else Permission("v--"))

    async def _check_permission(sess: UserSession):
        try:
            user = await system.get_or_create_user(f"user:{sess.user.id}", sess.user.name)
        except ValueError:
            return False
        if await system.has_permission(user, permission, Permission.AVAILABLE, context=sess):
            return True
        if prompt:
            await sess.send(f"Permission denied: {permission}")
        return False

    return _check_permission


class require_permission(Propagator):
    """
    依赖权限的函数，可用于 propagate 等

    Args:
        permission (str): 权限名称
        default_available (bool): 是否默认可用，默认为True
        prompt (bool): 是否提示
    """
    def __init__(self, permission: str, default_available: bool = True, prompt: bool = False, priority: int = 100):
        self.checker = check_permission(permission, default_available, prompt)
        self.priority = priority

    async def __call__(self, sess: UserSession):
        if not await self.checker(sess):
            raise STOP
        return

    def compose(self):
        yield self.__call__, True, self.priority
