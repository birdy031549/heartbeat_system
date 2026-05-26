"""
Permissions module for PluralLog Relay Server.
Maps sharing permissions to accessible volumes.
"""
from plurallog_relay import config


def permissions_to_volumes(permissions):
    """
    Convert a permissions dict to a set of allowed volume names.
    Always includes 'meta'.
    """
    volumes = {"meta"}  # Always include meta
    
    if permissions.get("share_front_status"):
        volumes.add("fronts")
    
    if permissions.get("share_members"):
        volumes.add("members")
    
    if permissions.get("share_front_history"):
        volumes.add("fronts")  # History is part of fronts
    
    if permissions.get("share_journal"):
        volumes.add("journal")
    
    if permissions.get("share_mood_trends"):
        volumes.add("analytics")
    
    if permissions.get("share_polls"):
        volumes.add("polls")
    
    if permissions.get("share_chat"):
        volumes.add("chat")
    
    return volumes
