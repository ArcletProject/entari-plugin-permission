from typing import Literal

from arclet.alconna import Alconna, Args, CommandMeta, Option, Subcommand, store_true
from arclet.cithun import Permission
from arclet.cithun.exceptions import PermissionDeniedError, ResourceNotFoundError
from arclet.entari.plugin import PluginRole
from nepattern import BasePattern, MatchFailed, MatchMode

from arclet.entari import MessageChain, plugin_config, command, metadata
from arclet.letoderea import propagate
from entari_plugin_user import UserSession, get_user
from satori import At

from .service import AUTH_3, AUTH_1, system
from .config import Config
from .params import UserOwner
from .check import require_permission


metadata(
    name="权限指令",
    role=PluginRole.NORMAL,
    author=[{"name": "RF-Tar-Railt", "email": "rf_tar_railt@qq.com"}],
    version="0.1.0",
    description="权限插件的指令模块，提供权限管理的指令",
)

cfg = plugin_config(Config)


class PermissionPattern(BasePattern[tuple[Permission, str, bool], str, Literal[MatchMode.TYPE_CONVERT]]):
    def match(self, input_):
        if not isinstance(input_, str):
            raise MatchFailed(f"Expected str, got {type(input_)}")
        if input_.lower() in ["true", "false"]:
            return Permission("v-a" if input_.lower() == "true" else "v--"), "=", False
        try:
            return Permission.parse(input_)
        except ValueError:
            raise MatchFailed(f"Invalid permission format: {input_}")


state_pattern = PermissionPattern(
    mode=MatchMode.TYPE_CONVERT, origin=tuple[Permission, str, bool], accepts=str, alias="bool | [ad][+-=][0-7|vma]"
)

cmd = Alconna(
    f"{cfg.command}",
    Subcommand(
        "user",
        Args["user?", At],
        Subcommand("list", help_text="列出所有权限"),
        Subcommand("set", Args["permission", str]["state", state_pattern], help_text="设置权限，支持 chmod 风格的表达式"),
        Subcommand("get", Args["permission", str], help_text="获取权限状态"),
        Subcommand("inherit", Args["name", str], Option("cancel", action=store_true, default=False, help_text="是否取消继承"), help_text="继承角色权限"),
        Subcommand("promote", Args["track", str], help_text="提升权限路径的等级"),
        Subcommand("demote", Args["track", str], help_text="降低权限路径的等级"),
    ),
    Subcommand(
        "track",
        Args["track", str],
        Subcommand("info", help_text="查看权限路径信息"),
        Subcommand("append", Args["role", str], help_text="为权限路径添加角色"),
        Subcommand("insert", Args["role", str]["index", int], help_text="为权限路径插入角色"),
        Subcommand("remove", Args["role", str], help_text="从权限路径移除角色"),
        Subcommand("clear", help_text="清空权限路径"),
        Subcommand("rename", Args["name", str], help_text="重命名权限路径"),
    ),
    Subcommand("listtrack", help_text="列出所有权限路径"),
    Subcommand("createtrack", Args["track", str]["name?", str], help_text="创建权限路径"),
    Subcommand("deletetrack", Args["track", str], help_text="删除权限路径"),
    meta=CommandMeta("权限指令"),
)

cmd.shortcut(
    r"chmod (?P<expr>(?:[ad])?(?:[=+-])?(?:[*0-7]|[vmarwx]+)) (?P<permission>.+)",
    prefix=True,
    command=f"{cfg.command} user set {{permission}} {{expr}}",
    humanized="chmod <expr> <permission>",
)

perm = command.mount(cmd).as_execute()


@perm.assign("user.list")
@propagate(require_permission("command.permission.list", prompt=True))
async def list_permissions(user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        _target = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
    else:
        _target = current
    try:
        return MessageChain(await system.permission_on(_target, expand_inherited=True, context=session))
    except PermissionDeniedError as e:
        return MessageChain(str(e))


@perm.assign("user.set")
@propagate(require_permission("command.permission.set", default_available=False, prompt=True))
async def set_permission(
    permission: str,
    state: command.Match[tuple[Permission, str, bool]],
    user: command.Match[At],
    current: UserOwner,
    session: UserSession,
):
    mask, mode, deny = state.result
    available = mask & Permission.AVAILABLE == Permission.AVAILABLE
    if mode == "-":
        available = not available
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        _target = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
        try:
            await system.set(
                current, _target, permission, mask, mode, deny, context=session
            )
            return MessageChain(
                f"Permission {permission} {'enabled' if available else 'disabled'} for {target_user.name}(user:{target_user.id})"
            )
        except ResourceNotFoundError:
            return MessageChain(f"Permission {permission} not found")
        except PermissionDeniedError as e:
            return MessageChain(str(e))
    else:
        try:
            await system.suset(current, permission, mask, mode, deny)
            return MessageChain(f"Permission {permission} {'enabled' if available else 'disabled'} for {current.name}({current.id})")
        except ResourceNotFoundError:
            return MessageChain(f"Permission {permission} not found")


@perm.assign("user.get")
@propagate(require_permission("command.permission.get", prompt=True))
async def get_permission(permission: str, user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        _target = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
        try:
            state = await system.get(_target, permission, context=session)
            return MessageChain(f"Permission {permission} for {target_user.name}(user:{target_user.id}) is {Permission(state)!r}")
        except ResourceNotFoundError:
            return MessageChain(f"Permission {permission} not found")
        except PermissionDeniedError as e:
            return MessageChain(str(e))
    else:
        try:
            state = await system.get(current, permission, context=session)
            return MessageChain(f"Permission {permission} for {current.name}({current.id}) is {Permission(state)!r}")
        except ResourceNotFoundError:
            return MessageChain(f"Permission {permission} not found")


@perm.assign("user.inherit.cancel.value", False)
@propagate(require_permission("command.permission.inherit", default_available=False, prompt=True))
async def add_inherit(name: str, user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        current = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
    try:
        await system.inherit(current, await system.get_role(name))
    except KeyError:
        return MessageChain(f"Role {name} not found")
    return MessageChain(f"{current.name}({current.id}) inherit {name} success")


@perm.assign("user.inherit.cancel.value", True)
@propagate(require_permission("command.permission.inherit", default_available=False, prompt=True))
async def cancel_inherit(name: str, user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        current = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
    try:
        await system.cancel_inherit(current, await system.get_role(name))
    except KeyError:
        return MessageChain(f"Role {name} not found")
    return MessageChain(f"{current.name}({current.id}) cancel inherit {name} success")


@perm.assign("user.promote")
@propagate(require_permission("command.permission.promote", default_available=False, prompt=True))
async def promote(track: str, user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        current = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
    try:
        await system.promote_track(current, system.get_track(track))
    except KeyError:
        return MessageChain(f"Track {track} not found")
    return MessageChain(f"{current.name}({current.id}) promoted on {track} success")


@perm.assign("user.demote")
@propagate(require_permission("command.permission.demote", default_available=False, prompt=True))
async def demote(track: str, user: command.Match[At], current: UserOwner, session: UserSession):
    if user.available and user.result.id:
        userinfo = await session.internal.account.user_get(user.result.id)
        target_user = await get_user(session.platform, userinfo)
        current = await system.get_or_create_user(f"user:{target_user.id}", target_user.name)
    try:
        await system.demote_track(current, system.get_track(track))
    except KeyError:
        return MessageChain(f"Track {track} not found")
    return MessageChain(f"{current.name}({current.id}) demoted on {track} success")


@perm.assign("listtrack")
@propagate(require_permission("command.permission.listtrack", prompt=True))
async def list_tracks():
    return MessageChain("\n".join(f"{track.name}({track.id}): {', '.join(lvl.level_name for lvl in track.levels)}" for track in system.tracks.values()))


@perm.assign("createtrack")
@propagate(require_permission("command.permission.createtrack", default_available=False, prompt=True))
async def create_track(track: str, name: command.Match[str]):
    if track in system.tracks:
        return MessageChain(f"Track {track} already exists")
    tck = await system.create_track(track, name.result if name.available else track)
    return MessageChain(f"Track {tck.name}({track}) created successfully")


@perm.assign("deletetrack")
@propagate(require_permission("command.permission.deletetrack", default_available=False, prompt=True))
async def delete_track(track: str):
    try:
        tck = await system.delete_track(track)
        return MessageChain(f"Track {tck.name}({track}) deleted successfully")
    except KeyError:
        return MessageChain(f"Track {track} not found")


@perm.assign("track.info")
@propagate(require_permission("command.permission.track.info", prompt=True))
async def track_info(track: str):
    try:
        tck = system.get_track(track)
        return MessageChain(
f"""\
Id: {tck.id}
Name: {tck.name}
Levels:
""" + "\n".join(f"  {lvl.level_name}: {lvl.role_id}" for lvl in tck.levels)
        )
    except KeyError:
        return MessageChain(f"Track {track} not found")


@perm.assign("track.append")
@propagate(require_permission("command.permission.track.append", default_available=False, prompt=True))
async def track_append(track: str, role: str):
    try:
        tck = system.get_track(track)
        rl = await system.get_role(role)
        await system.add_track_level(tck, rl)
        return MessageChain(f"Role {rl.name}({rl.id}) appended to track {tck.name}({tck.id}) successfully")
    except KeyError:
        return MessageChain(f"Track {track} not found")
    except ValueError:
        return MessageChain(f"Role {role} not found")


@perm.assign("track.insert")
@propagate(require_permission("command.permission.track.insert", default_available=False, prompt=True))
async def track_insert(track: str, role: str, index: int):
    try:
        tck = system.get_track(track)
    except KeyError:
        return MessageChain(f"Track {track} not found")
    try:
        rl = await system.get_role(role)
        await system.insert_track_level(tck, index, rl)
        return MessageChain(f"Role {rl.name}({rl.id}) inserted to track {tck.name}({tck.id}) at index {index} successfully")
    except ValueError:
        return MessageChain(f"Role {role} not found")
    except IndexError:
        return MessageChain(f"Index {index} out of range for track {tck.name}({tck.id})")


@perm.assign("track.remove")
@propagate(require_permission("command.permission.track.remove", default_available=False, prompt=True))
async def track_remove(track: str, role: str):
    try:
        tck = system.get_track(track)
    except KeyError:
        return MessageChain(f"Track {track} not found")
    try:
        rl = await system.get_role(role)
        await system.remove_track_level(tck, rl)
        return MessageChain(f"Role {rl.name}({rl.id}) removed from track {tck.name}({tck.id}) successfully")
    except ValueError:
        return MessageChain(f"Role {role} not found")
    except IndexError:
        return MessageChain(f"Role {role} not in track {tck.name}({tck.id})")


@perm.assign("track.clear")
@propagate(require_permission("command.permission.track.clear", default_available=False, prompt=True))
async def track_clear(track: str):
    try:
        tck = system.get_track(track)
        await system.clear_track_levels(tck)
        return MessageChain(f"Track {tck.name}({tck.id}) cleared successfully")
    except KeyError:
        return MessageChain(f"Track {track} not found")


@perm.assign("track.rename")
@propagate(require_permission("command.permission.track.rename", default_available=False, prompt=True))
async def track_rename(track: str, name: str):
    try:
        tck = system.get_track(track)
        await system.update_track_name(tck, name)
        return MessageChain(f"Track {tck.name}({tck.id}) renamed to {name} successfully")
    except KeyError:
        return MessageChain(f"Track {track} not found")


system.pre_assign(AUTH_1, "command.permission.*", Permission.VISIT)
system.pre_assign(AUTH_3, "command.permission.*", Permission.VISIT | Permission.AVAILABLE)
system.pre_assign(system.default_role, "command.permission", Permission("vma"))
