import pandas as pd
import matplotlib.pyplot as plt
import re

# Parse audits.log (credentials only)
credentials_data = []
with open("audits.log", "r") as f:
    for line in f:
        match = re.match(r".*Client ([\d\.]+) attempted connection with username: (.*?), password: (.*?)\s*$", line.strip())
        if match:
            ip, username, password = match.groups()
            credentials_data.append((ip, username, password))

creds_df = pd.DataFrame(credentials_data, columns=["IP", "Username", "Password"])
creds_df.to_csv("csv/credentials_attempts.csv", index=False)

# Parse cmd_audits.log (commands only)
commands_data = []
with open("cmd_audits.log", "r") as f:
    for line in f:
        match = re.match(r".*Command (b?'?.*?'?)exceuted by ([\d\.]+)", line.strip())
        if match:
            command = match.group(1).replace("b'", "").replace("'", "")
            ip = match.group(2)
            commands_data.append((ip, command))

cmds_df = pd.DataFrame(commands_data, columns=["IP", "Command"])
cmds_df.to_csv("csv/command_executions.csv", index=False)

# Plot Top Commands
top_cmds = cmds_df["Command"].value_counts().head(10)
plt.figure(figsize=(10, 6))
top_cmds.plot(kind="barh", color="skyblue")
plt.title("Top 10 Commands Executed")
plt.xlabel("Frequency")
plt.tight_layout()
plt.savefig("data/top_commands.png")
plt.close()

# Plot Top Attacker IPs
top_ips = cmds_df["IP"].value_counts().head(10)
plt.figure(figsize=(10, 6))
top_ips.plot(kind="bar", color="salmon")
plt.title("Top Attacker IPs")
plt.xlabel("IP Address")
plt.ylabel("Command Count")
plt.tight_layout()
plt.savefig("data/top_attackerips.png")
plt.close()

# Top Usernames
top_usernames = creds_df["Username"].value_counts().head(10)
plt.figure(figsize=(10, 6))
top_usernames.plot(kind="bar", color="mediumseagreen")
plt.title("Top Attempted Usernames")
plt.xlabel("Username")
plt.ylabel("Attempt Count")
plt.tight_layout()
plt.savefig("data/top_usernames.png")
plt.close()

# Top Passwords
top_passwords = creds_df["Password"].value_counts().head(10)
plt.figure(figsize=(10, 6))
top_passwords.plot(kind="bar", color="plum")
plt.title("Top Attempted Passwords")
plt.xlabel("Password")
plt.ylabel("Attempt Count")
plt.tight_layout()
plt.savefig("data/top_passwords.png")
plt.close()

print("Analysis complete. Charts and CSVs are saved")
