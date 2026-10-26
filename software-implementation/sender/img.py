import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# CSV file path
filename =Path(__file__).resolve().parent/"performance_receiver.csv"

# Read CSV
df = pd.read_csv(filename)

# Convert columns into numeric values
columns = [
    'Image size',
    'Decryption time',
    'Throughput',
    'Overall delay'
]

for col in columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')

print(df)

# Graph 1: Image Size vs Decryption Time
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Decryption time'],
         marker='o', color='blue')

plt.xlabel("Image Size (MB)")
plt.ylabel("Decryption Time (ms)")
plt.title("Image Size vs Decryption Time")
plt.grid(True)
plt.tight_layout()
plt.show()

# Graph 2: Image Size vs Throughput
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Throughput'],
         marker='o', color='green')

plt.xlabel("Image Size (MB)")
plt.ylabel("Throughput (MB/s)")
plt.title("Image Size vs Decryption Throughput")
plt.grid(True)
plt.tight_layout()
plt.show()

# Graph 3: Image Size vs Overall Delay
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Overall delay'],
         marker='o', color='red')

plt.xlabel("Image Size (MB)")
plt.ylabel("Overall Delay (ms)")
plt.title("Image Size vs Overall Delay")
plt.grid(True)
plt.tight_layout()
plt.show()
filename =Path(__file__).resolve().parent/"performance_sender.csv"

# Read CSV
df = pd.read_csv(filename)

# Convert columns into numeric values
columns = [
    'Image size','HQC encaps time','Encryption time','Throughput','Overall delay'
]

for col in columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')

print(df)

# Graph 1: Image Size vs Decryption Time
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Encryption time'],
         marker='o', color='blue')

plt.xlabel("Image Size (MB)")
plt.ylabel("Encryption Time (ms)")
plt.title("Image Size vs Encryption Time")
plt.grid(True)
plt.tight_layout()
plt.show()

# Graph 2: Image Size vs Throughput
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Throughput'],
         marker='o', color='green')

plt.xlabel("Image Size (MB)")
plt.ylabel("Throughput (MB/s)")
plt.title("Image Size vs DEncryption Throughput")
plt.grid(True)
plt.tight_layout()
plt.show()

# Graph 3: Image Size vs Overall Delay
plt.figure(figsize=(8, 5))
plt.plot(df['Image size'], df['Overall delay'],
         marker='o', color='red')

plt.xlabel("Image Size (MB)")
plt.ylabel("Overall Delay (ms)")
plt.title("Image Size vs Overall Delay")
plt.grid(True)
plt.tight_layout()
plt.show()