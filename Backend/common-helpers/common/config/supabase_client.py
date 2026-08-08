from functools import lru_cache
from supabase import create_client, Client
from common.config.settings import get_settings

@lru_cache()
def get_supabase_client():
    settings = get_settings()
    return create_client(settings.supabase_url, settings.supabase_service_role_key)
