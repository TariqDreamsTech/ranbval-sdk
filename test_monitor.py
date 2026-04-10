import os
import time

# pip install openai   # vendor is YOUR dependency, not ranbval-sdk's

# Local password-manager (telemetry)
os.environ["RANBVAL_HOST"] = "http://localhost:8006"

os.environ["OPENAI_API_KEY"] = (
    "ranbval.o7lrianaua0024b..wVh7NBq896i7DcYR33rzQviwCo6XUyPBZoPGW3AxpwiHjjFpMRdrB8GG5kOoUHoMTHnmrcAprmUabWhMYLzA2FslovC74GRQQFKyAmXVfAxVfo3ISHEre0VTlQ4CjrclLkThPm5S6TkTml5UUpA6ZKT/TEpHARkUDd+MalqKKDtqjDSuYuLMEEXsNZX0H3jPpJMbFY3WUcUFXYzGcrjxhOy60MWfyUnPzI8diSyeeZjCLdtYyrPKIaONUb7GeqVV.ahsan"
)

os.environ["RANBVAL_VAULT_SECRET"] = "hello"

import openai
from ranbval_sdk import secure_client


def run_test():
    print("Initialising OpenAI via secure_client...")
    client = secure_client(
        openai.OpenAI,
        env_var="OPENAI_API_KEY",
        key_kwarg="api_key",
        method_path_to_patch="chat.completions.create",
    )

    print("Calling OpenAI...")
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Tell me a very short programmer joke."},
            ],
        )

        print("\n=== Response Received ===")
        print(response.choices[0].message.content)
        print("=== Token Usage ===")
        print(
            f"Prompt: {response.usage.prompt_tokens}, Completion: {response.usage.completion_tokens}"
        )
        print("=========================\n")

        print("Waiting for background telemetry...")
        time.sleep(2.5)
        print("Done. Check Live Monitor if backend + token match your project.")

    except Exception as e:
        print(f"Error during OpenAI Call: {e}")


if __name__ == "__main__":
    run_test()
