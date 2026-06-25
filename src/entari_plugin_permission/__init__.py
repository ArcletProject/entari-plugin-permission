from arclet.cithun import DependencyCycleError as DependencyCycleError  # noqa: F401
from arclet.cithun import InheritMode as InheritMode  # noqa: F401
from arclet.cithun import Permission as Permission  # noqa: F401
from arclet.cithun import PermissionDeniedError as PermissionDeniedError  # noqa: F401
from arclet.cithun import PermissionExecutor as PermissionExecutor  # noqa: F401
from arclet.cithun import ResourceNode as ResourceNode  # noqa: F401
from arclet.cithun import ResourceNotFoundError as ResourceNotFoundError  # noqa: F401
from arclet.cithun import Role as CithunRole  # noqa: F401
from arclet.cithun import User as CithunUser  # noqa: F401

from arclet.entari import declare_static, metadata, plugin
from arclet.entari.plugin.model import PluginRole
from entari_plugin_user.models import UserSession
from entari_plugin_user.utils import set_user_authority

from .service import AUTH_1, AUTH_2, AUTH_3, AUTH_4, AUTH_5, AUTHORITY
from .check import check_permission as check_permission
from .check import require_permission as require_permission
from .service import system as system
from .event import UserSetTrackLevel as UserSetTrackLevel
from .params import UserOwner as UserOwner
from .config import Config
from . import handler  # noqa: F401


metadata(
    name="权限",
    role=PluginRole.COMPLEX,
    author=[{"name": "RF-Tar-Railt", "email": "rf_tar_railt@qq.com"}],
    version="0.1.0",
    description="基于 Cithun 的权限系统",
    depend_services=["database/sqlalchemy"],
    config=Config,
    readme="README.md",
)

declare_static()
plugin.add_service(system)


@system.on_loaded
async def init_roles():
    await system.inherit(AUTH_2, AUTH_1)
    await system.inherit(AUTH_3, AUTH_2)
    await system.inherit(AUTH_4, AUTH_3)
    await system.inherit(AUTH_5, AUTH_4)
    await system.extend_track(
        AUTHORITY,
        [AUTH_1, AUTH_2, AUTH_3, AUTH_4, AUTH_5],
        ["member", "advanced-member", "admin", "senior-admin", "superuser"]
    )

_auth_map = {"member": 1, "advanced-member": 2, "admin": 3, "senior-admin": 4, "superuser": 5}


# @plugin.listen(UserSetTrackLevel)
async def sync_authority(event: UserSetTrackLevel):
    if event.track.id == AUTHORITY.id and event.user.name.startswith("user:"):
        user_id = int(event.user.name[5:])
        await set_user_authority(
            user_id, _auth_map.get(event.level.level_name, 1)
        )


@system.engine.register_strategy
async def authority_attach(user, resource, context: UserSession | None, current_mask, permission_lookup):
    if context:
        current_user = await system.get_or_create_user(f"user:{context.user.id}", context.user.name)
        if not (lvl := system.get_user_track_level(current_user, AUTHORITY)):
            await system.set_user_track_level(
                current_user, AUTHORITY, context.user.authority - 1,
            )
        elif _auth_map.get(lvl.level_name, 1) != context.user.authority:
            await system.set_user_track_level(
                current_user, AUTHORITY, context.user.authority - 1,
            )
    if (level := system.get_user_track_level(user, AUTHORITY)) and level.level_name == "superuser":
        return Permission(7)
    return current_mask
