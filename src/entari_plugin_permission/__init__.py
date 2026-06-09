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
from arclet.entari.event.lifespan import Startup
from entari_plugin_user.models import UserSession
from entari_plugin_user.utils import set_user_authority

from .check import check_permission as check_permission
from .check import require_permission as require_permission
from .main import system as system
from .event import UserSetTrackLevel as UserSetTrackLevel
from .params import UserOwner as UserOwner

metadata(
    name="Permission",
    author=[{"name": "RF-Tar-Railt", "email": "rf_tar_railt@qq.com"}],
    version="0.1.0",
    description="基于 Cithun 的权限系统",
    depend_services=["database/sqlalchemy"]
)
declare_static()

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


@plugin.listen(Startup)
async def init_roles():
    await system.load()
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
        user = await system.get_or_create_user(f"user:{context.user.id}", context.user.name)
        # if not system.get_user_track_level(user, AUTHORITY):
        await system.set_user_track_level(
            user, AUTHORITY, context.user.authority - 1,
        )
    return current_mask
