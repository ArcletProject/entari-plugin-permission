from typing import Annotated

from arclet.cithun import User
from arclet.letoderea import Depends
from arclet.entari import Session
from entari_plugin_user import get_user

from .main import system


async def get_user_model(sess: Session) -> User:
    user_model = await get_user(sess.account.platform, sess.user)
    user = await system.get_or_create_user(f"user:{user_model.id}", user_model.name)
    return user


UserOwner = Annotated[User, Depends(get_user_model)]