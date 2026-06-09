from dataclasses import dataclass

from arclet.cithun.model import Track, TrackLevel, User
from arclet.letoderea import define


@dataclass
class UserSetTrackLevel:
    user: User
    track: Track
    level: TrackLevel


define(UserSetTrackLevel, name="permission/user_set_track_level")
