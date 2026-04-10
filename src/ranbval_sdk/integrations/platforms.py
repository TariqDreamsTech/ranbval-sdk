from ranbval_sdk.integrations.universal import build_secure_client

try:
    import anthropic
    SecureAnthropic = build_secure_client(
        anthropic.Anthropic,
        env_var_name="ANTHROPIC_API_KEY",
        key_kwarg="api_key",
        method_path_to_patch="messages.create"
    )
except ImportError:
    SecureAnthropic = None

try:
    import mistralai.client
    SecureMistral = build_secure_client(
        mistralai.client.MistralClient,
        env_var_name="MISTRAL_API_KEY",
        key_kwarg="api_key",
        method_path_to_patch="chat"
    )
except ImportError:
    SecureMistral = None

# Support for Supabase Database
try:
    import supabase
    # Supabase uses supabase.create_client(supabase_url, supabase_key)
    # The universal builder expects a class, so we can wrap the actual Client class
    from supabase.client import Client as SupabaseClient
    SecureSupabase = build_secure_client(
        SupabaseClient,
        env_var_name="SUPABASE_KEY",
        key_kwarg="supabase_key",
        method_path_to_patch="table" # E.g., patch DB fetches
    )
except ImportError:
    SecureSupabase = None
