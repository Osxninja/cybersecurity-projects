---
tags: [basic-project, cybersecurity, beginner-friendly]
category: "Basic Cybersecurity Projects"
difficulty: "Basic"
real_world_problem: "Securely concealing secret text notes inside standard PNG images for covert communication."
tools: [Python]
---

# 007 - Simple LSB Image Steganography Encoder & Decoder

> **Category**: Basic Cybersecurity Projects | **Difficulty**: ⭐ Basic | **Duration**: 1-2 weeks

---

## Problem Statement and Real World Impact

Real-world applications me yeh problem kafi common hai. Securely concealing secret text notes inside standard PNG images for covert communication.

Jab hum beginner-level cybersecurity practicals ki baat karte hain, toh foundational concepts ko code ke zariye samajhna sabse effective tareeka hota hai. Yeh project ek simple Python script ke zariye is real-world problem ko directly solve karta hai.

---

## Textbook & Paper References

- **Book Reference**: Disappearing Cryptography: Information Hiding by Peter Wayner (Chapter on LSB Image Steganography)
- **Research Paper**: Steganography in Digital Media: Principles, Algorithms, and Applications (Cambridge University Press, 2010)

---

## System Architecture

Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project Basic-007: 007 - Simple LSB Image Steganography Encoder & Decoder|Excalidraw Architecture Diagram]]

```mermaid
graph TD
    A[Input Data / Target] --> B[Processing Module]
    B --> C{Security Logic Check}
    C -- Matched / Anomaly --> D[Alert & Action]
    C -- Normal --> E[Pass / Complete]
```

---

## Technical Implementation Code

Python script using Pillow library to embed and extract secret text message bits into the Least Significant Bits of image pixels.

```python
from PIL import Image

def encode_message(image_path, secret_text, output_path):
    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size
    
    binary_secret = ''.join(format(ord(c), '08b') for c in secret_text) + '1111111111111110'
    data_index = 0
    
    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))
            for n in range(3): # R, G, B
                if data_index < len(binary_secret):
                    pixel[n] = (pixel[n] & ~1) | int(binary_secret[data_index])
                    data_index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if data_index >= len(binary_secret):
                break
        if data_index >= len(binary_secret):
            break
            
    encoded.save(output_path)
    print(f"[+] Message hidden successfully inside {output_path}")

def decode_message(image_path):
    img = Image.open(image_path)
    width, height = img.size
    binary_data = ""
    
    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            for n in range(3):
                binary_data += str(pixel[n] & 1)
                
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ""
    for byte in all_bytes:
        if byte == '11111111': # Delimiter check
            break
        decoded_text += chr(int(byte, 2))
    return decoded_text

if __name__ == "__main__":
    print("[*] Simple LSB Steganography Tool Ready.")

```

---

## Expected Results & Outcomes

1. Clear understanding of underlying networking, hashing, or system security mechanics.
2. Functional, lightweight Python script ready to execute in a local lab.
3. Verification of security controls against common real-world misconfigurations.

---

## Legal and Ethical Notice

> [!WARNING] Educational Use Only
> Always run these basic projects in your own local testing environment or authorized laboratory network.

---

## Related Index
- [[00 - Basic Cybersecurity Projects Index]]
