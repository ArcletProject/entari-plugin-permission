from arclet.alconna import Args, Alconna, store_true, Option
from arclet.cithun import Permission
from arclet.entari import Image, Session, command


from entari_plugin_permission import AUTH_3, require_permission, system, AUTH_1


mask_cmd = command.mount(
    Alconna(
        "设置词云形状",
        Args["img?", Image],
        Option("--default", action=store_true, default=False),
    ),
)
mask_cmd.propagators.append(require_permission("command.mask", default_available=False, prompt=True, priority=100))


@mask_cmd.handle()
async def mask(
    sess: Session,
    img: command.Match[Image],
    default: command.Query[bool] = command.Query("default.value", default=False),
):
    if not img.available:
        resp = await sess.prompt("请输入图片")
        if not resp:
            return
        img_result = resp.get(Image)
        if not img_result:
            return
        img_result = img_result[0]
    else:
        img_result = img.result
    if default.result:
        await sess.send([img_result])
    else:
        await sess.send("ok")


MASK = system.pre_role("group:mask", "Mask")
mask_track = system.pre_track("mask_track", "Mask Track")
system.pre_track_level(mask_track, system.default_role, "default")
system.pre_track_level(mask_track, MASK, "mask")

system.pre_assign(MASK, "command.mask", Permission(7))
system.pre_assign(AUTH_1, "command.mask", Permission.VISIT)
system.pre_assign(AUTH_3, "command.mask", Permission.VISIT | Permission.AVAILABLE)
