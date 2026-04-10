import os
import time

# Ensure your local ranbval-password-manager backend is running on 8006
# We set this so the background thread knows where to stream the live logs
os.environ["RANBVAL_HOST"] = "http://localhost:8006"

# TODO: Paste your LIVE Token (copied from the React "Copy Encoded" button) Here!
os.environ["OPENAI_API_KEY"] = (
    "ranbval.o7lrianaua0024b..wVh7NBq896i7DcYR33rzQviwCo6XUyPBZoPGW3AxpwiHjjFpMRdrB8GG5kOoUHoMTHnmrcAprmUabWhMYLzA2FslovC74GRQQFKyAmXVfAxVfo3ISHEre0VTlQ4CjrclLkThPm5S6TkTml5UUpA6ZKT/TEpHARkUDd+MalqKKDtqjDSuYuLMEEXsNZX0H3jPpJMbFY3WUcUFXYzGcrjxhOy60MWfyUnPzI8diSyeeZjCLdtYyrPKIaONUb7GeqVV.ahsan"
)

# TODO: Put your actual master Vault password here
os.environ["RANBVAL_VAULT_SECRET"] = "hello"

# Only import after setting env variables (or you can use a .env file loaded with python-dotenv)
from ranbval_sdk import SecureOpenAI


def run_test():
    print("Initialising SecureOpenAI...")
    # NOTE: SecureOpenAI will mathematically extract the Project Salt from your api_key,
    # meaning the backend knows exactly which Live Viewer UI to route this request to!
    client = SecureOpenAI()

    print("Calling OpenAI to generate a message. (Go watch your React UI now!)...")
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

        # Wait a moment for our SDK's background threading implementation to push telemetry
        print(
            "Waiting gracefully for background Fire-And-Forget telemetry thread to finish..."
        )
        time.sleep(2.5)
        print(
            "Done! If you were viewing the specific project's 'Live Monitor' in React, you should see this entry!"
        )

    except Exception as e:
        print(f"Error during OpenAI Call: {e}")


if __name__ == "__main__":
    run_test()
