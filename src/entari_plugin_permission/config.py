from arclet.entari.config import BasicConfModel


class Config(BasicConfModel):
    command: str = "permission"
    """权限操作指令的名称，默认为 "permission" """
