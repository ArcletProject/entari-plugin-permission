# entari-plugin-permission

基于 [`arclet-cithun`](https://github.com/ArcletProject/Arclet) 的 Entari 权限插件。

它提供了一套可持久化的权限、角色、继承链与 Track（权限路径）管理能力，并为 Entari 指令系统提供了现成的权限校验与管理命令。

## 功能特性

- 用户 / 角色权限管理，数据持久化到数据库
- 角色继承与用户继承角色
- Track（权限路径）管理：创建、删除、查看、增删等级、重命名、清空
- 支持 `chmod` 风格的权限设置快捷写法
- 支持按资源 ID 注册自定义权限附加策略（`attach`）
- 提供可直接复用的权限校验工具：`check_permission` / `require_permission`
- 内置 Entari 管理指令
- 自动同步用户 `authority` 到内置 `authority` Track

## 依赖环境

- Python `>= 3.10`
- `arclet-entari >= 0.18.0rc2`
- `arclet-cithun >= 1.4.0, < 1.5.0`
- `entari-plugin-user >= 0.1.6`
- `entari-plugin-database >= 0.3.1`
- 需要启用数据库服务：`database/sqlalchemy`

## 安装

```shell
pdm add entari-plugin-permission
```

## 配置

### 指令前缀

插件默认指令名为 `permission`，可通过配置修改：

```yaml
# entari.yml
plugins:
  permission:
    command: permission
```

也就是说，默认管理指令前缀为：

```text
/permission
```

如果你把 `command` 改成别的值，那么所有子指令前缀也会随之改变。

## 内置权限模型

插件启动后会创建并使用以下默认角色 / Track：

### 默认角色

- `group:default`：默认角色, 所有用户默认继承

### 内置权限角色

- `group:authority.1` — `Authority 1`
- `group:authority.2` — `Authority 2`
- `group:authority.3` — `Authority 3`
- `group:authority.4` — `Authority 4`
- `group:authority.5` — `Authority 5`

### 内置 Track

- `authority` — `Authority Track`

其等级名称依次为：

1. `member`
2. `advanced-member`
3. `admin`
4. `senior-admin`
5. `superuser`

插件会在启动时建立如下继承关系：

```text
AUTH_2 -> AUTH_1
AUTH_3 -> AUTH_2
AUTH_4 -> AUTH_3
AUTH_5 -> AUTH_4
```

并将 `authority` Track 与这些权限角色关联起来。

## 内置指令

以下指令默认都挂在 `/permission` 下（实际前缀取决于 `Config.command`）。

### 用户权限

- `/permission user [@用户] list`
  - 查看用户权限

- `/permission user [@用户] set <permission> <state>`
  - 设置权限状态
  - `state` 支持：
    - `true` / `false`
    - `Permission.parse(...)` 支持的权限表达式
    - `chmod` 风格快捷写法

- `/permission user [@用户] get <permission>`
  - 查询单个权限状态

- `/permission user [@用户] inherit <role> [--cancel]`
  - 继承 / 取消继承某个角色

- `/permission user [@用户] promote <track>`
  - 提升指定 Track 的等级

- `/permission user [@用户] demote <track>`
  - 降低指定 Track 的等级

### Track 管理

- `/permission track <track> info`
  - 查看 Track 信息

- `/permission track <track> append <role>`
  - 向 Track 末尾添加等级

- `/permission track <track> insert <role> <index>`
  - 在指定位置插入等级

- `/permission track <track> remove <role>`
  - 从 Track 移除等级

- `/permission track <track> clear`
  - 清空 Track 等级

- `/permission track <track> rename <name>`
  - 重命名 Track

- `/permission listtrack`
  - 列出所有 Track

- `/permission createtrack <track> [name]`
  - 创建 Track

- `/permission deletetrack <track>`
  - 删除 Track

### `chmod` 快捷写法

插件内置了一个快捷指令：

```text
/chmod <expr> <permission>
```

它会被自动转换为：

```text
/permission user set <permission> <expr>
```

## 权限点

插件自身的管理指令也有权限控制，主要权限点如下：

- `command.permission.list`
- `command.permission.set`
- `command.permission.get`
- `command.permission.inherit`
- `command.permission.promote`
- `command.permission.demote`
- `command.permission.listtrack`
- `command.permission.createtrack`
- `command.permission.deletetrack`
- `command.permission.track.info`
- `command.permission.track.append`
- `command.permission.track.insert`
- `command.permission.track.remove`
- `command.permission.track.clear`
- `command.permission.track.rename`

默认预设权限：

- `group:default` 对 `command.permission` 拥有 `vma`
- `AUTH_1` 对 `command.permission.*` 拥有 `VISIT`
- `AUTH_3` 对 `command.permission.*` 拥有 `VISIT | AVAILABLE`

## 开发者接口

如果你想在自己的插件中复用这套权限系统，可以直接导入下列对象：

```python
from entari_plugin_permission import (
    system,
    Permission,
    UserOwner,
    check_permission,
    require_permission,
    AUTH_1,
    AUTH_2,
    AUTH_3,
    AUTH_4,
    AUTH_5,
    AUTHORITY,
)
```

### `system`

`system` 是权限系统的核心实例，已经集成：

- `AsyncPermissionService`
- `AsyncPermissionExecutor`
- ORM 持久化存储

常用能力包括：

- `system.pre_role(...)`
- `system.pre_track(...)`
- `system.pre_assign(...)`
- `system.attach(...)`
- `system.get_or_create_user(...)`
- `system.get_role(...)`
- `system.get_track(...)`

### `check_permission(...)`

返回一个异步检查函数，可用于 `enter_if`、`Depends` 等场景。

```python
from entari_plugin_permission import check_permission


checker = check_permission("command.foo", prompt=True)
```

### `require_permission(...)`

这是 `Propagator` 封装，适合直接挂到 `propagate(...)` 上：

```python
from arclet.letoderea import propagate
from entari_plugin_permission import require_permission


@propagate(require_permission("command.foo", prompt=True))
async def handler() -> None:
    ...
```

### `UserOwner`

`UserOwner` 是一个可直接注入的类型别名，会自动从当前会话取出对应的 Cithun `User` 对象。

## 自定义资源权限附加

你可以通过 `system.attach(...)` 为某类资源动态追加权限：

- `pattern` 可以是字符串
  - 精确匹配
  - glob 通配：`*`、`?`、`[]`
- 也可以是自定义谓词函数 `Callable[[str], bool]`

回调返回值支持：

- 直接返回 `Permission`：表示追加允许权限
- 返回 `(Permission, "+")`：追加
- 返回 `(Permission, "-")`：移除
- 返回 `(Permission, "=")`：覆盖

## 事件

插件定义了一个事件：

- `UserSetTrackLevel`

当用户 Track 等级变化时会发布该事件，适合做外部同步或审计。

## 示例

仓库里的 `example_plugin.py` 展示了一个完整用法：

- 定义了一个自定义权限 `command.mask`
- 创建了 `mask_track`
- 通过 `system.pre_assign(...)` 给不同权限角色分配该权限
- 在指令执行前使用 `require_permission(...)` 做校验

如果你需要在自己的插件里增加权限控制，通常可以按下面的模式写：

```python
from arclet.cithun import Permission
from entari_plugin_permission import AUTH_1, AUTH_3, require_permission, system


system.pre_assign(system.default_role, "command.xxx", Permission("v-a"))
system.pre_assign(AUTH_1, "command.xxx", Permission.VISIT)
system.pre_assign(AUTH_3, "command.xxx", Permission.VISIT | Permission.AVAILABLE)
```

## 许可证

MIT
