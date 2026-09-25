import json
import sys
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:1.5b"

def generate_remediation_stream(attack_chain: list, choke_point: str):
    """
    Sends the attack path to local Ollama and streams the remediation patch safely.
    """
    prompt = f"""You are a senior DevSecOps engineer.
Analyze this attack path:
{json.dumps(attack_chain, indent=2)}

Choke Point to sever:
{choke_point}

Task:
1. Write a 2-sentence explanation of the risk.
2. Provide a minimal least-privilege Terraform patch to sever the choke point.
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "num_predict": 300  # Hard cap: stops generation after 300 tokens max to prevent hangs
        }
    }

    try:
        # 10s connection timeout, 60s read timeout
        response = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=(10, 60))
        response.raise_for_status()

        print("\n--- [Local AI: Analyzing Path & Generating Fix] ---\n")

        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("response", "")
                
                # Print token immediately to terminal
                sys.stdout.write(token)
                sys.stdout.flush()

                # Explicit break condition when model signals completion
                if chunk.get("done", False):
                    print("\n\n--- [Stream Complete] ---\n")
                    break

    except requests.exceptions.Timeout:
        print("\n[ERROR] Request timed out. Ollama took too long to respond.")
    except requests.exceptions.ConnectionError:
        print("\n[ERROR] Could not connect to Ollama. Make sure Ollama is running.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Dummy test data (Simulating Member 1's graph output)
    dummy_attack_chain = [
        "Internet (0.0.0.0/0) -> Web_EC2 (Port 80 Open)",
        "Web_EC2 -> DevAppRole (Instance Profile)",
        "DevAppRole -> Prod_S3_Bucket (iam:PassRole Admin)"
    ]
    dummy_choke_point = "Web_EC2 holding over-permissive role 'DevAppRole'"

    generate_remediation_stream(dummy_attack_chain, dummy_choke_point)
